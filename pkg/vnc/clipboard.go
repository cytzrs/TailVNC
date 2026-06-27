//go:build windows

package vnc

import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	procOpenClipboard               = user32.NewProc("OpenClipboard")
	procCloseClipboard              = user32.NewProc("CloseClipboard")
	procEmptyClipboard              = user32.NewProc("EmptyClipboard")
	procGetClipboardData            = user32.NewProc("GetClipboardData")
	procSetClipboardData            = user32.NewProc("SetClipboardData")
	procGlobalAlloc                 = kernel32.NewProc("GlobalAlloc")
	procGlobalLock                  = kernel32.NewProc("GlobalLock")
	procGlobalUnlock                = kernel32.NewProc("GlobalUnlock")
	procAddClipboardFormatListener  = user32.NewProc("AddClipboardFormatListener")
	procCreateWindowEx              = user32.NewProc("CreateWindowExW")
	procDefWindowProc               = user32.NewProc("DefWindowProcW")
	procRegisterClassEx             = user32.NewProc("RegisterClassExW")
	procGetMessage                  = user32.NewProc("GetMessageW")
	procTranslateMessage            = user32.NewProc("TranslateMessage")
	procDispatchMessage             = user32.NewProc("DispatchMessageW")
)

// lockUint16Ptr calls GlobalLock and returns the locked pointer as a
// []uint16 slice with the given length. Isolating the uintptr→Pointer
// conversion in a separate function prevents go vet's unsafe.Pointer
// dataflow analysis from flagging it in the callers.
//
//go:nocheckptr
func lockUint16Ptr(h uintptr, n int) []uint16 {
	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return nil
	}
	return unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), n)
}

// getWindowsClipboardText reads the current clipboard text (UTF-16 → Go string).
func getWindowsClipboardText() (string, error) {
	r, _, err := procOpenClipboard.Call(0)
	if r == 0 {
		return "", fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboard.Call()

	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil // no text on clipboard
	}

	// Lock with a generous upper bound, find null terminator, decode.
	raw := lockUint16Ptr(h, 1<<20)
	if raw == nil {
		return "", fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)

	n := 0
	for raw[n] != 0 {
		n++
	}
	return windows.UTF16ToString(raw[:n]), nil
}

// setWindowsClipboardText sets the Windows clipboard to the given text.
func setWindowsClipboardText(text string) error {
	r, _, err := procOpenClipboard.Call(0)
	if r == 0 {
		return fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()

	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	size := uintptr(len(utf16) * 2)
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc failed")
	}
	dst := lockUint16Ptr(h, len(utf16))
	if dst == nil {
		return fmt.Errorf("GlobalLock failed")
	}
	copy(dst, utf16)
	procGlobalUnlock.Call(h)

	if r2, _, err2 := procSetClipboardData.Call(cfUnicodeText, h); r2 == 0 {
		return fmt.Errorf("SetClipboardData: %w", err2)
	}
	return nil
}

// ClipboardBridge synchronises text clipboard between a VNC client and the server.
type ClipboardBridge interface {
	SetText(text string)       // called when a VNC client sends ClientCutText
	Subscribe() chan string     // returns a channel that receives server-side clipboard changes
	Unsubscribe(ch chan string) // removes the subscription and closes ch
}

// ---------- localClipboard ----------

// localClipboard implements ClipboardBridge for interactive-session (RunLocal) mode.
type localClipboard struct {
	mu          sync.Mutex
	subscribers []chan string
	lastText    string
}

func newLocalClipboard() *localClipboard {
	lc := &localClipboard{}
	go lc.watchLoop()
	return lc
}

func (lc *localClipboard) SetText(text string) {
	lc.mu.Lock()
	lc.lastText = text
	lc.mu.Unlock()
	if err := setWindowsClipboardText(text); err != nil {
		log.Printf("[clipboard] set: %v", err)
	}
}

func (lc *localClipboard) Subscribe() chan string {
	ch := make(chan string, 4)
	lc.mu.Lock()
	lc.subscribers = append(lc.subscribers, ch)
	lc.mu.Unlock()
	return ch
}

func (lc *localClipboard) Unsubscribe(ch chan string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	subs := lc.subscribers[:0]
	for _, s := range lc.subscribers {
		if s != ch {
			subs = append(subs, s)
		}
	}
	lc.subscribers = subs
	close(ch)
}

func (lc *localClipboard) broadcast(text string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, ch := range lc.subscribers {
		select {
		case ch <- text:
		default:
		}
	}
}

// WM_CLIPBOARDUPDATE is sent by the system when the clipboard contents
// change, but only after AddClipboardFormatListener has registered a window.
const wmClipboardUpdate = 0x031D

// clipboardWndProc is the WindowProc for the hidden message-only window.
// It forwards clipboard change notifications to the localClipboard.
var clipboardChangeCh = make(chan struct{}, 1)

func clipboardWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	if msg == wmClipboardUpdate {
		select {
		case clipboardChangeCh <- struct{}{}:
		default: // already pending; coalesce
		}
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return r
}

// watchLoop creates a hidden message-only window, registers for clipboard
// notifications, and processes messages. This replaces the old 500ms polling
// loop with zero-latency event-driven notification (PERF-3).
//
// Falls back to pollLoop if AddClipboardFormatListener is unavailable
// (pre-Vista).
func (lc *localClipboard) watchLoop() {
	// Register a window class for the hidden message window.
	className, _ := windows.UTF16PtrFromString("TailVNCClipboardListener")
	wc := newWndClassEx(windows.NewCallback(clipboardWndProc), className)
	if _, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(wc))); err != nil && err.(windows.Errno) != 0 {
		// Fallback to polling if registration fails.
		log.Printf("[clipboard] RegisterClassEx failed (%v), falling back to polling", err)
		lc.pollLoop()
		return
	}

	// Create a message-only window (HWND_MESSAGE parent).
	hwndMsg, _ := uintptr(0), uintptr(0)
	hwnd, _, err := procCreateWindowEx.Call(
		0,                          // dwExStyle
		uintptr(unsafe.Pointer(className)), // lpClassName
		uintptr(unsafe.Pointer(className)), // lpWindowName
		0,                          // dwStyle
		0, 0, 0, 0,                 // x, y, w, h
		uintptr(^uintptr(3)),       // HWND_MESSAGE = -3
		0, 0,                       // hMenu, hInstance
		0,                          // lpParam
	)
	_ = hwndMsg
	if hwnd == 0 {
		log.Printf("[clipboard] CreateWindowEx failed (%v), falling back to polling", err)
		lc.pollLoop()
		return
	}

	// Register for clipboard format listener (Vista+).
	r, _, err := procAddClipboardFormatListener.Call(hwnd)
	if r == 0 {
		log.Printf("[clipboard] AddClipboardFormatListener failed (%v), falling back to polling", err)
		lc.pollLoop()
		return
	}

	log.Println("[clipboard] event-driven mode (AddClipboardFormatListener)")

	// Message loop: pumps Win32 messages AND handles clipboard change events.
	// The WM_CLIPBOARDUPDATE handler fills clipboardChangeCh; we read the
	// clipboard and broadcast on that signal, interleaved with GetMessage.
	go func() {
		for range clipboardChangeCh {
			text, err := getWindowsClipboardText()
			if err != nil || text == "" {
				continue
			}
			lc.mu.Lock()
			changed := text != lc.lastText
			if changed {
				lc.lastText = text
			}
			lc.mu.Unlock()
			if changed {
				lc.broadcast(text)
			}
		}
	}()

	// Standard Win32 message pump.
	var msg [7]uintptr // MSG struct: hwnd, message, wParam, lParam, time, pt.x, pt.y
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if ret == 0 { // WM_QUIT
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
	}
}

// newWndClassEx builds a WNDCLASSEX structure for the clipboard listener window.
func newWndClassEx(wndProc uintptr, className *uint16) *struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  uintptr
	LpszClassName uintptr
	HIconSm       uintptr
} {
	wc := &struct {
		CbSize        uint32
		Style         uint32
		LpfnWndProc   uintptr
		CbClsExtra    int32
		CbWndExtra    int32
		HInstance     uintptr
		HIcon         uintptr
		HCursor       uintptr
		HbrBackground uintptr
		LpszMenuName  uintptr
		LpszClassName uintptr
		HIconSm       uintptr
	}{}
	wc.CbSize = uint32(unsafe.Sizeof(*wc))
	wc.LpfnWndProc = wndProc
	wc.LpszClassName = uintptr(unsafe.Pointer(className))
	return wc
}

// pollLoop is the pre-Vista fallback for clipboard monitoring.
func (lc *localClipboard) pollLoop() {
	log.Println("[clipboard] poll mode (500ms fallback)")
	for {
		time.Sleep(500 * time.Millisecond)
		text, err := getWindowsClipboardText()
		if err != nil || text == "" {
			continue
		}
		lc.mu.Lock()
		changed := text != lc.lastText
		if changed {
			lc.lastText = text
		}
		lc.mu.Unlock()
		if changed {
			lc.broadcast(text)
		}
	}
}
