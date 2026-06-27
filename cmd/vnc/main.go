//go:build windows

package main

import (
	"encoding/hex"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"tailvnc/pkg/authtoken"
	"tailvnc/pkg/deobfuscator"
	"tailvnc/pkg/secrets"
	"tailvnc/pkg/utils"
	"tailvnc/pkg/vnc"

	winio "github.com/tailscale/go-winio"
	"tailscale.com/tsnet"
)

func setupFileLog(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("WARNING: cannot open log file %s: %v", path, err)
		return
	}
	log.SetOutput(io.MultiWriter(f, os.Stderr))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("=== log opened: %s ===", path)
}

// Build-time injected directory to store and retrieve persistent config data used by tsnet
var buildWithConfigDir string

// Build-time injected obfuscated key (hex string)
var buildWithObfuscatedAuthKey string

// Build-time injected control server URL
var buildWithControlURL string

// Build-time injected listening port
var buildWithListenPort string

// Build-time injected vnc auth password
var buildWithAuthPass string

// Build-time injected listen address for direct (non-tsnet) mode.
// Only used when no Tailscale auth key is provided. Defaults to 0.0.0.0.
var buildWithListenAddr string

// Build-time injected TLS certificate and key paths for VeNCrypt.
// When both are set, the VNC server offers VeNCrypt TLS encryption.
var (
	buildWithTLSCert string
	buildWithTLSKey  string
)

// version / buildTime are injected via LDFLAGS -X main.version / -X main.buildTime
// (see Makefile). Printed at startup so the log line unambiguously identifies
// which build is running — needed to stop debugging against a stale .exe.
var (
	version   = "dev"
	buildTime = "unknown"
)

// logBanner prints the build identity at startup. zlibFix tracks whether this
// build includes the persistent deflate-stream fix (RFC 6143 §7.7.5); the
// version string itself carries the build suffix so there is no ambiguity.
func logBanner() {
	log.Printf("=== TailVNC %s (built %s) — zlib-fix: persistent RFB deflate stream ===", version, buildTime)
}

// flagValue returns the value following a "--name" flag in os.Args, or the
// empty string when the flag is absent.  Lightweight command-line parsing
// without depending on the flag package.
func flagValue(name string) string {
	args := os.Args[1:]
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// agentPort returns the port number from "--agent <port>" in os.Args,
// or an empty string if this is not an agent invocation.
func agentPort() string {
	return flagValue("--agent")
}

// runAgent runs a local VNC server on a Windows Named Pipe.
// Called when the process is spawned as a user-session agent by the service.
// Screen capture and input injection work correctly here because the process
// is running inside the interactive user session (not Session 0 / SYSTEM).
func runAgent(_ string) {
	// setupFileLog(`C:\Windows\Temp\tailvnc-agent.log`)
	log.Printf("[agent] starting on named pipe %s", vnc.AgentPipeName)

	// Create a security descriptor that allows only SYSTEM and
	// Administrators to connect to the pipe.
	pipeConfig := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
		MessageMode:        false,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}

	ln, err := winio.ListenPipe(vnc.AgentPipeName, pipeConfig)
	if err != nil {
		log.Fatalf("[agent] ListenPipe: %v", err)
	}
	defer ln.Close()

	// SEC-2: if spawned by the service, require the one-time IPC token on this
	// pipe listener so a non-authorized local process cannot seize the
	// desktop without the VNC password.
	if tokHex := os.Getenv("TAILVNC_AGENT_TOKEN"); tokHex != "" {
		tok, err := hex.DecodeString(tokHex)
		if err != nil || len(tok) == 0 {
			log.Fatalf("[agent] invalid TAILVNC_AGENT_TOKEN: %v", err)
		}
		ln = authtoken.NewListener(ln, tok)
		log.Printf("[agent] IPC token auth enabled")
	}

	srv := &vnc.Server{}
	srv.RunLocal(ln)
}

type TailVNC struct {
	server *tsnet.Server
}

// startServer listens on the embedded Tailscale (tsnet) interface and serves
// VNC over the WireGuard-encrypted mesh. Used when a Tailscale auth key is
// configured at build time.
func (t *TailVNC) startServer(listenPort string, authPass string, tlsCfg *tls.Config) error {
	listener, err := t.server.Listen("tcp", ":"+listenPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("VNC server started (tsnet): %s:%s", t.server.Hostname, listenPort)
	return serve(listener, authPass, tlsCfg)
}

// startDirectServer listens on a plain TCP address (no Tailscale/WireGuard).
// Used by default when no auth key is embedded, so the binary works as a plain
// VNC server without any Tailscale dependency.
func startDirectServer(listenAddr, listenPort, authPass string, tlsCfg *tls.Config) error {
	listener, err := net.Listen("tcp", listenAddr+":"+listenPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("VNC server started (direct TCP): %s:%s", listenAddr, listenPort)
	return serve(listener, authPass, tlsCfg)
}

// serve is the shared entry point once a listener exists: it picks service vs
// local mode based on the Windows session the process runs in.
func serve(listener net.Listener, authPass string, tlsCfg *tls.Config) error {
	srv := &vnc.Server{Password: authPass, TLSConfig: tlsCfg}

	if vnc.GetCurrentSessionID() == 0 {
		// Running as SYSTEM in Session 0 (e.g. as a service or via psexec -s).
		// Spawn an agent in the interactive user session and proxy connections.
		log.Println("detected Session 0 – starting in service mode")
		srv.RunAsService(listener)
	} else {
		// Already in an interactive session; capture and inject directly.
		srv.RunLocal(listener)
	}

	return nil
}

func main() {
	logBanner()

	// Agent mode: spawned by the service inside the user's session.
	// Must be checked before anything else (before auth-key guard, before tsnet).
	if port := agentPort(); port != "" {
		runAgent(port)
		return
	}

	// setupFileLog(`C:\Windows\Temp\tailvnc-service.log`)

	hostName := utils.GetSystemHostname()
	authKey := ""
	controlURL := ""
	listenPort := "5900"
	authPass := ""
	configDir := "C:\\Windows\\Temp\\.config"

	if buildWithConfigDir != "" {
		configDir = buildWithConfigDir
	}

	// Auth key: runtime --auth-key takes priority over the build-time value.
	if rt := flagValue("--auth-key"); rt != "" {
		authKey = rt
	} else if buildWithObfuscatedAuthKey != "" {
		authKey = deobfuscator.DeobfuscateAuthKey(buildWithObfuscatedAuthKey)
	}
	// authKey stays empty when neither is provided -> direct TCP mode below.

	if buildWithControlURL != "" {
		controlURL = buildWithControlURL
	}

	if buildWithListenPort != "" {
		listenPort = buildWithListenPort
	}

	// VNC password: runtime --auth-pass takes priority over the build-time
	// value.  A password is mandatory — refuse to start without one so the
	// desktop is never exposed unauthenticated.
	if rt := flagValue("--auth-pass"); rt != "" {
		authPass = rt
	} else if buildWithAuthPass != "" {
		authPass = buildWithAuthPass
	} else if v := secrets.FromEnvOrFile("TAILVNC_AUTH_PASS", ""); v != "" {
		authPass = v
	} else {
		log.Fatal("no VNC password: pass --auth-pass <pwd>, set TAILVNC_AUTH_PASS env, or set AUTH_PASS at build time")
	}

	// Listen address for direct (non-tsnet) mode. SEC-1: default to loopback —
	// exposing VNC to other interfaces now requires an explicit LISTEN_ADDR.
	listenAddr := "127.0.0.1"
	if buildWithListenAddr != "" {
		listenAddr = buildWithListenAddr
	}

	// TLS configuration for VeNCrypt. Load certificate if provided.
	var tlsCfg *tls.Config
	tlsCert := flagValue("--tls-cert")
	tlsKey := flagValue("--tls-key")
	if tlsCert == "" {
		tlsCert = buildWithTLSCert
	}
	if tlsKey == "" {
		tlsKey = buildWithTLSKey
	}
	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatalf("Failed to load TLS key pair: %v", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Printf("VeNCrypt TLS enabled (cert: %s)", tlsCert)
	}

	// No Tailscale auth key: serve VNC over plain TCP without WireGuard.
	if authKey == "" {
		log.Printf("Starting direct VNC server on %s as %s", listenAddr+":"+listenPort, hostName)
		if err := startDirectServer(listenAddr, listenPort, authPass, tlsCfg); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
		return
	}

	// Tailscale auth key present: embed a WireGuard peer via tsnet.
	log.Printf("Starting tsnet VNC proxy as %s", hostName)

	s := &tsnet.Server{
		Hostname:   hostName,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Logf:       func(format string, args ...interface{}) {},
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatal(err)
	}
	s.Dir = configDir

	tailVNC := &TailVNC{server: s}

	if err := tailVNC.startServer(listenPort, authPass, tlsCfg); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
