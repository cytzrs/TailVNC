//go:build windows

package vnc

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailvnc/pkg/authtoken"
	"tailvnc/pkg/secureroot"
)

const (
	agentLocalPort = "15900"

	// stillActive is the Windows STILL_ACTIVE exit code (259 / 0x103).
	stillActive = 259

	// tokenPrimary / securityImpersonation for DuplicateTokenEx.
	tokenPrimary          = 1
	securityImpersonation = 2

	// tokenSessionId is TOKEN_INFORMATION_CLASS value for session ID.
	tokenSessionId = 12

	// createUnicodeEnvironment / createNoWindow process creation flags.
	createUnicodeEnvironment = 0x00000400
	createNoWindow           = 0x08000000
)

var (
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	userenv  = windows.NewLazySystemDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procCreateEnvironmentBlock       = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = userenv.NewProc("DestroyEnvironmentBlock")
	procSetTokenInformation          = advapi32.NewProc("SetTokenInformation")
)

// getConsoleSessionID returns the active console (interactive) session ID.
// Returns 0xFFFFFFFF if no console session exists.
func getConsoleSessionID() uint32 {
	r, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r)
}

// getSystemTokenForSession duplicates the current SYSTEM token and reassigns
// its session ID so that the spawned process lives in the target session.
//
// Using a SYSTEM token (rather than the user token from WTSQueryUserToken) is
// intentional: a SYSTEM process in the target session can call
// OpenInputDesktop / SetThreadDesktop for both the normal desktop and the
// secure desktop (Winlogon / UAC), and SendInput as SYSTEM bypasses UIPI so
// input events are never blocked.  A user-token process fails with
// ERROR_ACCESS_DENIED whenever the secure desktop is active.
func getSystemTokenForSession(sessionID uint32) (windows.Token, error) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.MAXIMUM_ALLOWED, &cur); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer cur.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(cur, windows.MAXIMUM_ALLOWED, nil,
		securityImpersonation, tokenPrimary, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	// Redirect the token to the target session so the spawned process appears
	// in that session's window station (WinSta0).
	sid := sessionID
	r, _, err := procSetTokenInformation.Call(
		uintptr(dup),
		uintptr(tokenSessionId),
		uintptr(unsafe.Pointer(&sid)),
		unsafe.Sizeof(sid),
	)
	if r == 0 {
		dup.Close()
		return 0, fmt.Errorf("SetTokenInformation(TokenSessionId=%d): %w", sessionID, err)
	}
	return dup, nil
}

// spawnAgentInSession launches the current executable with "--agent <port>" in
// the given Windows session using a SYSTEM token placed in that session. It
// also generates a fresh one-time IPC token (SEC-2) and passes it to the agent
// via its environment block; the agent's loopback listener then refuses any
// connection that does not present it.
func spawnAgentInSession(sessionID uint32, port string) (windows.Handle, []byte, error) {
	token, err := getSystemTokenForSession(sessionID)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot get SYSTEM token for session %d: %w", sessionID, err)
	}
	defer token.Close()

	ipcToken, err := authtoken.Generate(32)
	if err != nil {
		return 0, nil, fmt.Errorf("authtoken.Generate: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return 0, nil, fmt.Errorf("Executable: %w", err)
	}
	if err := secureExePath(exePath); err != nil {
		return 0, nil, fmt.Errorf("SEC-4: %w", err)
	}

	cmdLine := `"` + exePath + `" --agent ` + port
	cmdLineW, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, nil, err
	}

	desktop, _ := windows.UTF16PtrFromString(`WinSta0\Default`)
	si := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: 0, // SW_HIDE
	}
	var pi windows.ProcessInformation

	// Minimal UTF-16 env block carrying only the IPC token. The agent (screen
	// capture / input / clipboard) does not need the parent service's env.
	envPtr := buildAgentEnv(ipcToken)

	err = windows.CreateProcessAsUser(
		token, nil, cmdLineW,
		nil, nil, false,
		createUnicodeEnvironment|createNoWindow,
		envPtr, nil, &si, &pi,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	log.Printf("[agent] spawned PID=%d in session %d on port %s (token=SYSTEM, ipc-auth=on)", pi.ProcessId, sessionID, port)
	return pi.Process, ipcToken, nil
}

// secureExePath enforces SEC-4: the agent (re-executed as SYSTEM) may only run
// from an admin-writable directory. SystemRoot is narrowed to System32 so
// C:\Windows\Temp (user-writable) does not slip through. The full DACL check
// is deferred to M3.
func secureExePath(exePath string) error {
	roots := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("SystemRoot") + `\System32`,
	}
	if !secureroot.IsInSecureDir(exePath, roots) {
		return fmt.Errorf("executable must live under %%ProgramFiles%% or %%SystemRoot%%\\System32; got %s", exePath)
	}
	return nil
}

// buildAgentEnv returns a Windows double-null-terminated UTF-16 environment
// block containing TAILVNC_AGENT_TOKEN=<hex(token)>. The agent reads it via
// os.Getenv. Built manually (not CreateEnvironmentBlock) so the token is the
// only record and nothing else is inherited.
func buildAgentEnv(token []byte) *uint16 {
	rec := "TAILVNC_AGENT_TOKEN=" + hex.EncodeToString(token)
	var buf []uint16
	for _, r := range rec {
		buf = append(buf, uint16(r)) // ASCII-only record (hex chars + '=')
	}
	buf = append(buf, 0) // record terminator
	buf = append(buf, 0) // block terminator
	return &buf[0]
}

// sessionManager monitors the active console session and keeps an agent process
// running in it.  On session change (logoff / new logon), it kills the old
// agent and spawns a fresh one.
type sessionManager struct {
	port       string
	mu         sync.Mutex
	agentProc  windows.Handle
	agentToken []byte // current one-time IPC token (SEC-2), rotated per spawn
	sessionID  uint32
}

func newSessionManager(port string) *sessionManager {
	return &sessionManager{port: port, sessionID: ^uint32(0)}
}

func (m *sessionManager) run() {
	for {
		sid := getConsoleSessionID()

		m.mu.Lock()
		if sid != m.sessionID {
			log.Printf("[session] console session changed: %d → %d", m.sessionID, sid)
			m.killAgent()
			m.sessionID = sid
		}

		// Respawn if agent exited.
		if m.agentProc != 0 {
			var code uint32
			_ = windows.GetExitCodeProcess(m.agentProc, &code)
			if code != stillActive {
				log.Printf("[session] agent exited (code=%d), respawning", code)
				windows.CloseHandle(m.agentProc)
				m.agentProc = 0
			}
		}

		if m.agentProc == 0 && sid != 0xFFFFFFFF {
			h, tok, err := spawnAgentInSession(sid, m.port)
			if err != nil {
				log.Printf("[session] spawn agent: %v", err)
			} else {
				m.agentProc = h
				m.agentToken = tok
			}
		}
		m.mu.Unlock()

		time.Sleep(2 * time.Second)
	}
}

// currentToken returns the active IPC token (or nil if no agent is running),
// copied under the lock so the caller can hand it to a proxy goroutine.
func (m *sessionManager) currentToken() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.agentToken
}

func (m *sessionManager) killAgent() {
	if m.agentProc != 0 {
		windows.TerminateProcess(m.agentProc, 0)
		windows.CloseHandle(m.agentProc)
		m.agentProc = 0
		log.Println("[session] killed old agent")
	}
}
