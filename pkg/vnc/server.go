//go:build windows

package vnc

import (
	"image"
	"log"
	"net"
	"runtime"
	"time"
	"unsafe"

	"crypto/tls"

	"golang.org/x/sys/windows"
	"tailvnc/pkg/rfbcore"
)

// Server holds top-level configuration for the VNC server.
type Server struct {
	// Password is the VNC authentication password.
	// An empty string disables authentication (accepts any client).
	Password string

	// TLSConfig, when non-nil, enables VeNCrypt TLS encryption.
	// Clients that support VeNCrypt will get a TLS-wrapped RFB session.
	// Clients without VeNCrypt fall back to plain RFB (backward compatible).
	TLSConfig *tls.Config
}

// NewServer returns a default Server.
func NewServer() *Server {
	return &Server{}
}

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	// sasDLL / procSendSAS: the actual SendSAS call must happen from session 0
	// (the service process). The agent (session 1) signals sasTriggerEvent;
	// startSASListener() receives that signal and calls SendSAS(FALSE) here.
	sasDLL      = windows.NewLazySystemDLL("sas.dll")
	procSendSAS = sasDLL.NewProc("SendSAS")
)

// sasTriggerEvent is the Global named Windows event used for agent→service IPC.
// The agent (session 1) signals it; the service (session 0) calls SendSAS(FALSE).
const sasTriggerEvent = `Global\TailVNC_SAS`

// startSASListener creates the named SAS trigger event and starts a goroutine
// that calls SendSAS(FALSE) from session 0 whenever the agent signals it.
// Must be called from the service process (session 0).
func startSASListener() {
	namePtr, err := windows.UTF16PtrFromString(sasTriggerEvent)
	if err != nil {
		log.Printf("[sas] UTF16PtrFromString: %v", err)
		return
	}
	ev, err := windows.CreateEvent(nil, 0, 0, namePtr) // auto-reset, not-signaled
	if err != nil {
		log.Printf("[sas] CreateEvent failed: %v", err)
		return
	}
	log.Printf("[sas] SAS listener ready (session 0)")
	go func() {
		defer windows.CloseHandle(ev)
		for {
			ret, _ := windows.WaitForSingleObject(ev, windows.INFINITE)
			if ret == windows.WAIT_OBJECT_0 {
				procSendSAS.Call(0) // FALSE = service/non-interactive context
				log.Printf("[sas] SendSAS(FALSE) called from session 0")
			}
		}
	}()
}

// ScreenCapturer is the interface used by the RFB session to grab frames.
type ScreenCapturer interface {
	Width() int
	Height() int
	Capture() (*image.RGBA, error)
	// CaptureDirty returns the current frame, the CopyRect moves and dirty
	// rectangles since the last call, and a full flag — when full is true the
	// caller must send the whole frame (too many changes / first frame / resize)
	// instead of the moves/dirty rects (which will be empty).
	CaptureDirty() (*image.RGBA, []rfbcore.CopyRect, []rfbcore.Rect, bool, error)
}

// InputInjector is the interface used by the RFB session to deliver
// keyboard and mouse events.
type InputInjector interface {
	InjectKey(keysym uint32, down bool)
	InjectPointer(buttonMask uint8, x, y, serverW, serverH int)
}

// GetCurrentSessionID returns the Windows session ID of the current process.
// Returns 0 for Session 0 (SYSTEM / service), >0 for interactive sessions.
func GetCurrentSessionID() uint32 {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return 0
	}
	defer token.Close()
	var id uint32
	var ret uint32
	windows.GetTokenInformation(token, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&id)), 4, &ret)
	return id
}

// enablePrivilege enables a named privilege in the current process token.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	namePtr, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// ---------- LocalInput ----------

// LocalInput satisfies InputInjector by calling Win32 SendInput directly.
// It is used both when already in an interactive session (RunLocal) and when
// running as a SYSTEM service after associating with the interactive window
// station via setupInteractiveWindowStation (RunAsService).
type LocalInput struct{ st inputState }

func (l *LocalInput) InjectKey(keysym uint32, down bool) {
	l.st.keyEvent(keysym, down)
}

func (l *LocalInput) InjectPointer(buttonMask uint8, x, y, serverW, serverH int) {
	SimulatePointer(x, y, buttonMask, serverW, serverH)
	l.st.buttonEvent(buttonMask, x, y, serverW, serverH)
}

// ---------- DesktopAwareInput ----------

// inputCmd is an input event queued to the DesktopAwareInput worker.
type inputCmd struct {
	isKey                  bool
	keysym                 uint32
	down                   bool
	buttonMask             uint8
	x, y, serverW, serverH int
}

// DesktopAwareInput is an InputInjector that routes all events through a
// single OS-thread-locked goroutine. Before each SendInput call the goroutine
// calls switchToInputDesktop() so that input is delivered to whichever desktop
// is currently active (WinSta0\Default or WinSta0\Winlogon). Without this,
// SendInput from a thread that is still on the Default desktop is silently
// discarded when the user is on the Winlogon / lock-screen desktop.
type DesktopAwareInput struct {
	ch chan inputCmd
	st inputState
}

// NewDesktopAwareInput creates and starts the input worker goroutine.
func NewDesktopAwareInput() *DesktopAwareInput {
	d := &DesktopAwareInput{ch: make(chan inputCmd, 64)}
	go d.loop()
	return d
}

func (d *DesktopAwareInput) loop() {
	// Lock to a single OS thread for the lifetime of this goroutine.
	// SetThreadDesktop affects only the calling OS thread; without this lock
	// Go's scheduler may migrate the goroutine between calls, causing SendInput
	// to run on a thread with a stale desktop association.
	runtime.LockOSThread()

	var lastInputDesk string

	for cmd := range d.ch {
		// Switch to whichever desktop currently owns user input before
		// injecting.  As a SYSTEM process we can access both the Default and
		// the Winlogon/secure desktop.  If the desktop is mid-transition,
		// OpenInputDesktop may return NULL briefly; retry up to ~500 ms so we
		// don't lose the event and don't inject on a stale desktop.
		const maxRetries = 10
		var ok bool
		var desk string
		for i := 0; i < maxRetries; i++ {
			ok, desk = switchToInputDesktop()
			if ok {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if !ok {
			// Desktop still unavailable after retries — drop this event.
			// This should be rare for a SYSTEM-token process.
			log.Printf("[input] switchToInputDesktop failed after %d retries — dropping event", maxRetries)
			continue
		}

		if desk != lastInputDesk {
			log.Printf("[input] desktop changed: %q → %q", lastInputDesk, desk)
			lastInputDesk = desk
		}

		if cmd.isKey {
			d.st.keyEvent(cmd.keysym, cmd.down)
		} else {
			SimulatePointer(cmd.x, cmd.y, cmd.buttonMask, cmd.serverW, cmd.serverH)
			d.st.buttonEvent(cmd.buttonMask, cmd.x, cmd.y, cmd.serverW, cmd.serverH)
		}
	}
}

func (d *DesktopAwareInput) InjectKey(keysym uint32, down bool) {
	d.ch <- inputCmd{isKey: true, keysym: keysym, down: down}
}

func (d *DesktopAwareInput) InjectPointer(buttonMask uint8, x, y, serverW, serverH int) {
	d.ch <- inputCmd{buttonMask: buttonMask, x: x, y: y, serverW: serverW, serverH: serverH}
}

// ---------- top-level run functions ----------

// RunLocal starts the VNC server using direct screen capture and input
// injection. Used when already running in an interactive session.
//
// Uses SessionAwareCapturer so that desktop switches (lock screen, Winlogon)
// are handled gracefully: BitBlt failures keep the last good frame instead of
// disconnecting the VNC client.
func (s *Server) RunLocal(ln net.Listener) {
	capturer := NewSessionAwareCapturer()
	// Wait for the capture loop to produce the first frame and report screen dims.
	for capturer.Width() == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("screen: %dx%d", capturer.Width(), capturer.Height())
	s.serveVNC(ln, capturer, NewDesktopAwareInput(), newLocalClipboard())
}

// RunAsService starts the VNC server from Session 0 (SYSTEM) using the
// Chrome Remote Desktop pattern:
//
//  1. A sessionManager goroutine monitors the active console session and
//     spawns the same binary with "--agent <port>" inside the user's session.
//     The agent runs a full local VNC server on 127.0.0.1:<port>.
//
//  2. For each incoming VNC connection on the tsnet listener, this function
//     acts as a transparent TCP proxy to the agent, forwarding bytes in both
//     directions.
//
// This sidesteps the Vista+ Session Isolation limitation: GDI BitBlt from
// Session 0 always returns a black bitmap because the display content is
// owned by the user's Session 1 DWM.  By running the screen capture inside
// the user session the agent sees the real pixels.
func (s *Server) RunAsService(ln net.Listener) {
	// SeTcbPrivilege is required for WTSQueryUserToken.
	// SeAssignPrimaryTokenPrivilege is required for CreateProcessAsUser.
	for _, priv := range []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege"} {
		if err := enablePrivilege(priv); err != nil {
			log.Printf("[service] enable %s: %v", priv, err)
		}
	}

	startSASListener()

	sm := newSessionManager(agentLocalPort)
	go sm.run()

	log.Printf("[service] proxying VNC connections to agent on 127.0.0.1:%s", agentLocalPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go proxyToAgent(conn, agentLocalPort, sm.currentToken())
	}
}

// serveVNC accepts incoming VNC connections on ln and spawns a session
// goroutine for each one.
func (s *Server) serveVNC(ln net.Listener, capturer ScreenCapturer, input InputInjector, clipboard ClipboardBridge) {
	log.Printf("VNC server listening on %s", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		// Signal the capturer that a client connected (wakes idle capture loop).
		if sc, ok := capturer.(interface{ AddClient() }); ok {
			sc.AddClient()
		}
		sess := &session{
			conn:      conn,
			capturer:  capturer,
			injector:  input,
			clipBoard: clipboard,
			serverW:   capturer.Width(),
			serverH:   capturer.Height(),
			password:  s.Password,
			tlsConfig: s.TLSConfig,
		}
		go func() {
			sess.Serve()
			if sc, ok := capturer.(interface{ RemoveClient() }); ok {
				sc.RemoveClient()
			}
		}()
	}
}
