//go:build windows

package main

import (
	"io"
	"log"
	"net"
	"os"
	"tailvnc/pkg/deobfuscator"
	"tailvnc/pkg/utils"
	"tailvnc/pkg/vnc"

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

// runAgent runs a local VNC server on 127.0.0.1:<port>.
// Called when the process is spawned as a user-session agent by the service.
// Screen capture and input injection work correctly here because the process
// is running inside the interactive user session (not Session 0 / SYSTEM).
func runAgent(port string) {
	// setupFileLog(`C:\Windows\Temp\tailvnc-agent.log`)
	log.Printf("[agent] starting on 127.0.0.1:%s", port)

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatalf("[agent] listen: %v", err)
	}
	defer ln.Close()

	srv := &vnc.Server{}
	srv.RunLocal(ln)
}

type TailVNC struct {
	server *tsnet.Server
}

// startServer listens on the embedded Tailscale (tsnet) interface and serves
// VNC over the WireGuard-encrypted mesh. Used when a Tailscale auth key is
// configured at build time.
func (t *TailVNC) startServer(listenPort string, authPass string) error {
	listener, err := t.server.Listen("tcp", ":"+listenPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("VNC server started (tsnet): %s:%s", t.server.Hostname, listenPort)
	return serve(listener, authPass)
}

// startDirectServer listens on a plain TCP address (no Tailscale/WireGuard).
// Used by default when no auth key is embedded, so the binary works as a plain
// VNC server without any Tailscale dependency.
func startDirectServer(listenAddr, listenPort, authPass string) error {
	listener, err := net.Listen("tcp", listenAddr+":"+listenPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("VNC server started (direct TCP): %s:%s", listenAddr, listenPort)
	return serve(listener, authPass)
}

// serve is the shared entry point once a listener exists: it picks service vs
// local mode based on the Windows session the process runs in.
func serve(listener net.Listener, authPass string) error {
	srv := &vnc.Server{Password: authPass}

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
	} else {
		log.Fatal("no VNC password: pass --auth-pass <pwd> at runtime or set AUTH_PASS at build time")
	}

	// Listen address for direct (non-tsnet) mode. Defaults to all interfaces.
	listenAddr := "0.0.0.0"
	if buildWithListenAddr != "" {
		listenAddr = buildWithListenAddr
	}

	// No Tailscale auth key: serve VNC over plain TCP without WireGuard.
	if authKey == "" {
		log.Printf("Starting direct VNC server on %s as %s", listenAddr+":"+listenPort, hostName)
		if err := startDirectServer(listenAddr, listenPort, authPass); err != nil {
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

	if err := tailVNC.startServer(listenPort, authPass); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
