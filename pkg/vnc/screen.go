//go:build windows

package vnc

import (
	"fmt"
	"image"
	"log"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailvnc/pkg/rfbcore"
)

var (
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procDeleteDC         = gdi32.NewProc("DeleteDC")
	procBitBlt           = gdi32.NewProc("BitBlt")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	// Desktop / window-station management
	procOpenInputDesktop         = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop         = user32.NewProc("SetThreadDesktop")
	procCloseDesktop             = user32.NewProc("CloseDesktop")
	procGetUserObjectInformation = user32.NewProc("GetUserObjectInformationW")
	procOpenWindowStation        = user32.NewProc("OpenWindowStationW")
	procSetProcessWindowStation  = user32.NewProc("SetProcessWindowStation")
	procCloseWindowStation       = user32.NewProc("CloseWindowStation")
)

const (
	smCxScreen   = 0
	smCyScreen   = 1
	srccopy      = 0x00CC0020
	dibRgbColors = 0
	uoiName      = 2
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
}

// setupInteractiveWindowStation opens WinSta0 (the interactive window station)
// and associates the current process with it. This is required for a SYSTEM
// service in Session 0 to access the interactive desktop for screen capture
// and input injection.
//
// Per MSDN: "A service can call OpenWindowStation with the 'WinSta0' name to
// open a handle to the interactive window station."
//
// The returned handle must remain open for the lifetime of the process.
func setupInteractiveWindowStation() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("WinSta0")
	if err != nil {
		return 0, err
	}
	hWinSta, _, err := procOpenWindowStation.Call(
		uintptr(unsafe.Pointer(name)),
		0, // bInherit = FALSE
		uintptr(windows.MAXIMUM_ALLOWED),
	)
	if hWinSta == 0 {
		return 0, fmt.Errorf("OpenWindowStation(WinSta0): %w", err)
	}
	r, _, err := procSetProcessWindowStation.Call(hWinSta)
	if r == 0 {
		procCloseWindowStation.Call(hWinSta)
		return 0, fmt.Errorf("SetProcessWindowStation: %w", err)
	}
	log.Println("[screen] process window station set to WinSta0 (interactive)")
	return windows.Handle(hWinSta), nil
}

// getDesktopName returns the name of the given desktop handle.
func getDesktopName(hDesk uintptr) string {
	var buf [256]uint16
	var needed uint32
	procGetUserObjectInformation.Call(hDesk, uoiName,
		uintptr(unsafe.Pointer(&buf[0])), 512,
		uintptr(unsafe.Pointer(&needed)))
	return windows.UTF16ToString(buf[:])
}

// switchToInputDesktop opens the desktop currently receiving user input
// (handles normal desktop, login screen, lock screen, screensaver) and
// sets it as the calling OS thread's desktop.
// Returns (success, desktopName). desktopName is empty on failure.
//
// Must be called from a goroutine locked to its OS thread via
// runtime.LockOSThread().
func switchToInputDesktop() (bool, string) {
	hDesk, _, _ := procOpenInputDesktop.Call(0, 0, uintptr(windows.MAXIMUM_ALLOWED))
	if hDesk == 0 {
		return false, ""
	}
	name := getDesktopName(hDesk)
	ret, _, _ := procSetThreadDesktop.Call(hDesk)
	procCloseDesktop.Call(hDesk)
	return ret != 0, name
}

// Capturer captures the desktop screen using CreateDIBSection for direct pixel
// access. The compatible DC and DIB section are pooled (created on first
// capture, freed by Close) so each frame only does GetDC/ReleaseDC + BitBlt
// instead of a full DC+bitmap create/destroy cycle — a significant GDI/syscall
// churn cut at 30 fps. The capture goroutine is runtime.LockOSThread'd, so these
// thread-affine handles stay on one OS thread for their lifetime.
type Capturer struct {
	mu     sync.Mutex
	width  int
	height int

	memDC uintptr        // pooled compatible DC
	bmp   uintptr        // pooled DIB section
	bits  unsafe.Pointer // pooled DIB pixel pointer (BGRA)
}

func screenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(uintptr(smCxScreen))
	h, _, _ := procGetSystemMetrics.Call(uintptr(smCyScreen))
	return int(w), int(h)
}

func NewCapturer() (*Capturer, error) {
	w, h := screenSize()
	if w == 0 || h == 0 {
		return nil, fmt.Errorf("failed to get screen dimensions")
	}
	return &Capturer{width: w, height: h}, nil
}

func (c *Capturer) Width() int  { return c.width }
func (c *Capturer) Height() int { return c.height }

// ensureBuffer lazily creates the pooled DC + DIB. Dims are fixed for a
// Capturer's lifetime (a desktop change creates a fresh Capturer), so this runs
// at most once per Capturer.
func (c *Capturer) ensureBuffer(screenDC uintptr) error {
	if c.memDC != 0 && c.bmp != 0 && c.bits != nil {
		return nil
	}
	memDC, _, _ := procCreateCompatDC.Call(screenDC)
	if memDC == 0 {
		return fmt.Errorf("CreateCompatibleDC failed")
	}
	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:    int32(c.width),
			Height:   -int32(c.height), // negative = top-down DIB
			Planes:   1,
			BitCount: 32,
		},
	}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(
		memDC,
		uintptr(unsafe.Pointer(&bi)),
		dibRgbColors,
		uintptr(unsafe.Pointer(&bits)),
		0, 0,
	)
	if bmp == 0 || bits == nil {
		procDeleteDC.Call(memDC)
		return fmt.Errorf("CreateDIBSection failed (bmp=%v bits=%v)", bmp, bits)
	}
	procSelectObject.Call(memDC, bmp)
	c.memDC, c.bmp, c.bits = memDC, bmp, bits
	return nil
}

func (c *Capturer) destroyBuffer() {
	if c.bmp != 0 {
		procDeleteObject.Call(c.bmp)
		c.bmp = 0
	}
	if c.memDC != 0 {
		procDeleteDC.Call(c.memDC)
		c.memDC = 0
	}
	c.bits = nil
}

// Close releases the pooled GDI objects. Idempotent; call before discarding a
// Capturer (e.g. on desktop change) so the thread-affine handles don't leak.
func (c *Capturer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyBuffer()
}

// Capture grabs the current desktop into a freshly allocated RGBA image (a new
// buffer per call, so callers can hold it across capture cycles without races).
// The GDI DC/DIB backing the capture are pooled; only the RGBA copy is allocated.
func (c *Capturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// GetDC(0) = NULL: gets the screen DC for the calling thread's current desktop.
	// This is correct after SetThreadDesktop (e.g. switching to the Winlogon
	// desktop on user logoff), whereas GetDC(GetDesktopWindow()) can silently
	// return 0 because GetDesktopWindow may still refer to the old desktop window.
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	if err := c.ensureBuffer(screenDC); err != nil {
		return nil, err
	}

	if ret, _, _ := procBitBlt.Call(c.memDC, 0, 0, uintptr(c.width), uintptr(c.height),
		screenDC, 0, 0, srccopy); ret == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}

	// bits points to the raw BGRA pixel data of the pooled DIB.
	raw := unsafe.Slice((*byte)(c.bits), c.width*c.height*4)
	img := image.NewRGBA(image.Rect(0, 0, c.width, c.height))
	for i := 0; i < c.width*c.height; i++ {
		img.Pix[i*4+0] = raw[i*4+2] // R <- B
		img.Pix[i*4+1] = raw[i*4+1] // G
		img.Pix[i*4+2] = raw[i*4+0] // B <- R
		img.Pix[i*4+3] = 0xff
	}
	return img, nil
}

// SessionAwareCapturer captures the interactive desktop directly from a SYSTEM
// service process (Session 0). It requires that setupInteractiveWindowStation()
// has already been called to associate the process with WinSta0.
//
// A dedicated goroutine is locked to an OS thread so that SetThreadDesktop
// and GetDC(NULL) always operate on the same thread. The goroutine continuously
// calls switchToInputDesktop() to follow session transitions (login, logout,
// lock screen) automatically — no agent process needed.
type SessionAwareCapturer struct {
	mu        sync.Mutex
	frame     *image.RGBA
	prevFrame *image.RGBA        // previous frame for dirty-rect comparison
	dirty     []rfbcore.Rect     // dirty rectangles since the last CaptureDirty
	moves     []rfbcore.CopyRect // CopyRect moves since the last CaptureDirty
	full      bool               // sticky: a full-frame update is pending until consumed
	w, h      int
}

// NewSessionAwareCapturer creates and starts the background capture loop.
func NewSessionAwareCapturer() *SessionAwareCapturer {
	c := &SessionAwareCapturer{}
	go c.loop()
	return c
}

func (c *SessionAwareCapturer) Width() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.w
}

func (c *SessionAwareCapturer) Height() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.h
}

// Capture returns the latest captured frame. Blocks if no frame has been
// captured yet (e.g. during startup or a desktop transition failure).
func (c *SessionAwareCapturer) Capture() (*image.RGBA, error) {
	for {
		c.mu.Lock()
		img := c.frame
		c.mu.Unlock()
		if img != nil {
			return img, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// CaptureDirty returns the latest frame, the CopyRect moves and dirty rectangles
// since the previous call, and a full flag. full=true means "send the whole
// frame" (first frame, desktop/resolution change, or too many changes to tile
// well); moves and dirty will be empty in that case. All three are consumed: a
// subsequent call reports only new changes.
func (c *SessionAwareCapturer) CaptureDirty() (*image.RGBA, []rfbcore.CopyRect, []rfbcore.Rect, bool, error) {
	for {
		c.mu.Lock()
		img := c.frame
		c.mu.Unlock()
		if img != nil {
			c.mu.Lock()
			moves := c.moves
			dirty := c.dirty
			full := c.full
			c.moves = nil // consume; next call reports fresh changes only
			c.dirty = nil
			c.full = false
			c.mu.Unlock()
			return img, moves, dirty, full, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// loop is the capture goroutine — must not be called directly.
// Locks itself to an OS thread so SetThreadDesktop + GetDC(NULL) are coherent.
func (c *SessionAwareCapturer) loop() {
	// Lock this goroutine to its OS thread for the entire capture loop.
	// SetThreadDesktop() affects only the calling OS thread. Without this
	// lock, Go's scheduler may migrate the goroutine to a different thread
	// after time.Sleep, causing GetDC(0) to see a stale desktop.
	runtime.LockOSThread()

	var capturer *Capturer
	var lastDesk string
	var desktopFails int
	var staticFrames int // consecutive frames with no changes (for adaptive fps)

	for {
		// Switch to whichever desktop is currently receiving user input.
		// This handles: user desktop (Default), login screen (Winlogon),
		// lock screen, and screensaver — automatically, without needing to
		// know the current session ID.
		ok, desk := switchToInputDesktop()
		if !ok {
			desktopFails++
			if desktopFails == 1 || desktopFails%30 == 0 {
				log.Printf("[screen] switchToInputDesktop failed (consecutive=%d) — desktop transitioning", desktopFails)
			}
			// During logoff→Winlogon transitions OpenInputDesktop may fail
			// for several seconds. Keep retrying; don't reset capturer yet.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if desktopFails > 0 {
			log.Printf("[screen] switchToInputDesktop recovered after %d failures, desktop=%q", desktopFails, desk)
			desktopFails = 0
		}

		if desk != lastDesk {
			log.Printf("[screen] desktop changed: %q → %q", lastDesk, desk)
			lastDesk = desk
			// Reset capturer because the new desktop may have different dimensions.
			if capturer != nil {
				capturer.Close()
				capturer = nil
			}
		}

		if capturer == nil {
			var err error
			capturer, err = NewCapturer()
			if err != nil {
				log.Printf("[screen] NewCapturer on desktop %q: %v", desk, err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			c.mu.Lock()
			c.w, c.h = capturer.Width(), capturer.Height()
			c.mu.Unlock()
			log.Printf("[screen] capturer ready: %dx%d on desktop %q", capturer.Width(), capturer.Height(), desk)
		}

		img, err := capturer.Capture()
		if err != nil {
			log.Printf("[screen] Capture on desktop %q: %v", desk, err)
			capturer.Close()
			capturer = nil
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// CORR-3: capture the adaptive-FPS decision inside the lock — the old
		// code read c.dirty after Unlock, racing with CaptureDirty consumers.
		changed := false
		c.mu.Lock()
		// Three-state diff: (nil,false)=no change, (rects,false)=dirty,
		// (nil,true)=full update needed. "full" is sticky until a consumer
		// reads it (CaptureDirty), so a one-shot full-screen change is never
		// lost when the very next frame happens to be identical to it.
		dirty, full := rfbcore.DiffFrames(c.prevFrame, img)
		prev := c.prevFrame // detect moves against this frame before overwriting it
		c.frame = img
		c.prevFrame = img
		if full {
			c.full = true
			c.dirty = nil
			c.moves = nil
		} else if !c.full {
			// Detect CopyRect moves on the raw tile-aligned dirty list, then
			// coalesce the genuinely-changed remainder.
			moves, realDirty := rfbcore.DetectMoves(prev, img, dirty)
			c.moves = moves
			c.dirty = rfbcore.CoalesceRects(realDirty)
		}
		changed = full || len(dirty) > 0
		c.mu.Unlock()

		// Adaptive frame rate: stay at full 30 fps while the screen is
		// changing, but back off when it is static to save CPU and let the
		// dirty-rect path report changes cheaply.  The moment anything
		// changes we return to 30 fps immediately.
		staticFrames++
		delay := 33 * time.Millisecond // ~30 fps (active)
		if staticFrames > 3 {
			delay = 100 * time.Millisecond // static → ~10 fps
		}
		if changed {
			staticFrames = 0
		}
		time.Sleep(delay)
	}
}
