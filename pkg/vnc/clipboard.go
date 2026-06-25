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
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
)

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

	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return "", fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr))), nil
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
	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock failed")
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16)), utf16)
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
	go lc.pollLoop()
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

func (lc *localClipboard) pollLoop() {
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

// ---------- Latin-1 / UTF-8 helpers ----------
// Moved to pkg/rfbcore (Latin1ToUTF8 / UTF8ToLatin1) so they are unit-tested
// alongside the rest of the protocol logic.
