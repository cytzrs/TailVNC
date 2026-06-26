//go:build windows

package vnc

import (
	"image"
	"log"
	"unsafe"
)

// Local cursor capture (Cursor pseudo-encoding -239). The cursor's SHAPE is sent
// once when it changes; the VNC client then renders it locally as the user moves
// the mouse, so pointer motion costs no bandwidth.
//
// All Win32 structs below rely on Go's natural field alignment, which matches
// the x64 ABI for these primitive types (no hand-padded [N]byte fields — see the
// QUAL-5 note). Behavioral correctness (does the cursor rasterize and place
// correctly) must be verified on a Windows VM; capture failures are logged and
// skipped so they never crash the session.

var (
	procGetCursorInfo = user32.NewProc("GetCursorInfo")
	procGetIconInfo   = user32.NewProc("GetIconInfo")
	procDrawIconEx    = user32.NewProc("DrawIconEx")
	procGetObjectW    = gdi32.NewProc("GetObjectW")
)

const (
	cursorShowing = 0x00000001 // CURSOR_SHOWING: the cursor is visible
	diNormal      = 0x00000001 // DI_NORMAL: draw image + mask
)

// cursorPos mirrors Win32 POINT (two LONGs).
type cursorPos struct{ X, Y int32 }

// cursorInfo mirrors Win32 CURSORINFO. Field order + Go alignment give the
// correct x64 layout (cbSize, flags, hCursor@8, ptScreenPos@16 = 24 bytes).
type cursorInfo struct {
	CbSize      uint32
	Flags       uint32
	HCursor     uintptr
	PtScreenPos cursorPos
}

// iconInfo mirrors Win32 ICONINFO. x64 layout: fIcon, xHotspot, yHotspot, then
// hbmMask@16 / hbmColor@24 (Go auto-inserts the 4-byte alignment pad) = 32 bytes.
type iconInfo struct {
	FIcon    uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

// bitmapHeader mirrors Win32 BITMAP (bmType..bmBits). x64: 32 bytes, bmBits@24.
type bitmapHeader struct {
	BmType       int32
	BmWidth      int32
	BmHeight     int32
	BmWidthBytes int32
	BmPlanes     uint16
	BmBitsPixel  uint16
	BmBits       uintptr
}

// cursorShot is the result of rasterizing the current cursor.
type cursorShot struct {
	img     *image.RGBA
	hotX    int
	hotY    int
	x, y    int // hotspot screen position
	handle  uintptr
	changed bool
}

// captureCursor rasterizes the current cursor. It returns changed=false when the
// cursor is hidden or its handle is unchanged since prevHandle — so callers only
// re-send on shape changes. Any Win32 failure is logged and reported as
// changed=false; it never returns a partial image.
func captureCursor(prevHandle uintptr) cursorShot {
	var ci cursorInfo
	ci.CbSize = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 {
		return cursorShot{handle: prevHandle}
	}
	if ci.Flags&cursorShowing == 0 {
		return cursorShot{handle: prevHandle} // hidden: nothing to send
	}
	if ci.HCursor == prevHandle {
		// Shape unchanged — still report position in case a future revision
		// wants it, but no re-send.
		return cursorShot{handle: prevHandle, x: int(ci.PtScreenPos.X), y: int(ci.PtScreenPos.Y)}
	}

	var ii iconInfo
	if r, _, _ := procGetIconInfo.Call(ci.HCursor, uintptr(unsafe.Pointer(&ii))); r == 0 {
		log.Printf("[cursor] GetIconInfo failed")
		return cursorShot{handle: prevHandle}
	}
	// GetIconInfo returns GDI bitmaps the caller must free.
	defer func() {
		if ii.HbmMask != 0 {
			procDeleteObject.Call(ii.HbmMask)
		}
		if ii.HbmColor != 0 {
			procDeleteObject.Call(ii.HbmColor)
		}
	}()

	// Cursor dimensions come from the color bitmap (masked cursors use the mask).
	srcBmp := ii.HbmColor
	if srcBmp == 0 {
		srcBmp = ii.HbmMask
	}
	var bh bitmapHeader
	procGetObjectW.Call(srcBmp, unsafe.Sizeof(bitmapHeader{}), uintptr(unsafe.Pointer(&bh)))
	w, h := int(bh.BmWidth), int(bh.BmHeight)
	// Masked (colorless) cursors have a double-height mask bitmap; use its half.
	if ii.HbmColor == 0 && h > 0 {
		h = h / 2
	}
	if w <= 0 || h <= 0 {
		return cursorShot{handle: prevHandle}
	}

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return cursorShot{handle: prevHandle}
	}
	defer procReleaseDC.Call(0, screenDC)
	memDC, _, _ := procCreateCompatDC.Call(screenDC)
	if memDC == 0 {
		return cursorShot{handle: prevHandle}
	}
	defer procDeleteDC.Call(memDC)

	bi := bitmapInfo{Header: bitmapInfoHeader{
		Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:    int32(w),
		Height:   -int32(h), // negative = top-down DIB
		Planes:   1,
		BitCount: 32,
	}}
	var bits unsafe.Pointer
	bm, _, _ := procCreateDIBSection.Call(memDC, uintptr(unsafe.Pointer(&bi)),
		dibRgbColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bm == 0 || bits == nil {
		return cursorShot{handle: prevHandle}
	}
	defer procDeleteObject.Call(bm)
	procSelectObject.Call(memDC, bm)

	// Zero the DIB so transparent areas are well-defined, then draw.
	raw := unsafe.Slice((*byte)(bits), w*h*4)
	clear(raw)
	if r, _, _ := procDrawIconEx.Call(memDC, 0, 0, ci.HCursor,
		uintptr(w), uintptr(h), 0, 0, diNormal); r == 0 {
		log.Printf("[cursor] DrawIconEx failed")
		return cursorShot{handle: prevHandle}
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		img.Pix[i*4+0] = raw[i*4+2] // R <- B
		img.Pix[i*4+1] = raw[i*4+1] // G
		img.Pix[i*4+2] = raw[i*4+0] // B <- R
		img.Pix[i*4+3] = raw[i*4+3] // alpha (premultiplied; EncodeCursorPseudoRect treats !=0 as visible)
	}

	return cursorShot{
		img:     img,
		hotX:    int(ii.XHotspot),
		hotY:    int(ii.YHotspot),
		x:       int(ci.PtScreenPos.X),
		y:       int(ci.PtScreenPos.Y),
		handle:  ci.HCursor,
		changed: true,
	}
}
