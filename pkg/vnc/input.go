package vnc

import (
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSendInput = user32.NewProc("SendInput")

	// procOpenEventW: used to signal the service-side SAS listener.
	procOpenEventW = kernel32.NewProc("OpenEventW")
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove       = 0x0001
	mouseeventfLeftDown   = 0x0002
	mouseeventfLeftUp     = 0x0004
	mouseeventfRightDown  = 0x0008
	mouseeventfRightUp    = 0x0010
	mouseeventfMiddleDown = 0x0020
	mouseeventfMiddleUp   = 0x0040
	mouseeventfWheel      = 0x0800
	mouseeventfHWheel     = 0x1000
	mouseeventfAbsolute   = 0x8000

	wheelDelta = 120 // standard Windows scroll unit

	keyeventfKeyUp    = 0x0002
	keyeventfUnicode  = 0x0004
	keyeventfScanCode = 0x0008

	extendedKeyFlag = 0x0001
)

// mouseInput mirrors the WIN32 MOUSEINPUT structure.
type mouseInput struct {
	Dx          int32
	Dy          int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

// keybdInput mirrors the WIN32 KEYBDINPUT structure.
type keybdInput struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
	_           [8]byte // padding to match INPUT union size on 64-bit
}

// inputUnion is sized for the largest member (mouseInput on 64-bit is 28 bytes,
// keybdInput padded to 32; we use a fixed-size array to match WIN32 INPUT).
type inputUnion [32]byte

type winInput struct {
	Type uint32
	_    [4]byte // padding before union on 64-bit
	Data inputUnion
}

func sendMouseInput(flags uint32, dx, dy int32, mouseData uint32) {
	mi := mouseInput{
		Dx:        dx,
		Dy:        dy,
		MouseData: mouseData,
		DwFlags:   flags,
	}
	inp := winInput{Type: inputMouse}
	copy(inp.Data[:], (*[unsafe.Sizeof(mi)]byte)(unsafe.Pointer(&mi))[:])
	r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&inp)), unsafe.Sizeof(inp))
	if r == 0 {
		log.Printf("[input] SendInput(mouse flags=0x%x) failed: %v", flags, err)
	}
}

func sendKeyInput(vk uint16, scanCode uint16, flags uint32) {
	ki := keybdInput{
		WVk:     vk,
		WScan:   scanCode,
		DwFlags: flags,
	}
	inp := winInput{Type: inputKeyboard}
	copy(inp.Data[:], (*[unsafe.Sizeof(ki)]byte)(unsafe.Pointer(&ki))[:])
	r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&inp)), unsafe.Sizeof(inp))
	if r == 0 {
		log.Printf("[input] SendInput(key vk=0x%x flags=0x%x) failed: %v", vk, flags, err)
	}
}

// SimulatePointer handles a VNC pointer event: x, y are desktop coordinates,
// buttonMask follows the RFB spec (bit0=left, bit1=middle, bit2=right).
func SimulatePointer(x, y int, buttonMask uint8, screenW, screenH int) {
	// Convert to absolute mickeys (0–65535) and inject via SendInput.  This is
	// the canonical absolute move: it goes through the input stream so it is
	// observed by every application (including full-screen/DirectInput games).
	// SetCursorPos was previously called as well, but it bypasses the input
	// stream and was redundant with the absolute SendInput below.
	absX := int32(x * 65535 / screenW)
	absY := int32(y * 65535 / screenH)
	sendMouseInput(mouseeventfMove|mouseeventfAbsolute, absX, absY, 0)
}

var prevButtonMask uint8

// SimulateButtonEvent sends press/release events for changed buttons.
// RFB button mask bits:
//
//	bit0=left  bit1=middle  bit2=right
//	bit3=wheel-up  bit4=wheel-down  bit5=wheel-left  bit6=wheel-right
func SimulateButtonEvent(buttonMask uint8, x, y, screenW, screenH int) {
	changed := buttonMask ^ prevButtonMask
	prevButtonMask = buttonMask

	absX := int32(x * 65535 / screenW)
	absY := int32(y * 65535 / screenH)

	// Regular buttons (press/release on transition).
	type btnMap struct {
		bit  uint8
		down uint32
		up   uint32
	}
	buttons := []btnMap{
		{0x01, mouseeventfLeftDown, mouseeventfLeftUp},
		{0x02, mouseeventfMiddleDown, mouseeventfMiddleUp},
		{0x04, mouseeventfRightDown, mouseeventfRightUp},
	}
	for _, b := range buttons {
		if changed&b.bit != 0 {
			var flags uint32
			if buttonMask&b.bit != 0 {
				flags = b.down
			} else {
				flags = b.up
			}
			sendMouseInput(flags|mouseeventfAbsolute, absX, absY, 0)
		}
	}

	// Scroll wheel: fire on the leading edge (bit goes 0→1).
	// Windows MOUSEINPUT.mouseData for wheel is a signed DWORD passed as uint32;
	// negWheelDelta is the two's-complement uint32 representation of -120.
	const negWheelDelta = ^uint32(wheelDelta - 1) // 0xFFFFFF88 == -120 as int32

	// Vertical scroll: bit3=up (+120), bit4=down (-120).
	if changed&0x08 != 0 && buttonMask&0x08 != 0 {
		sendMouseInput(mouseeventfWheel|mouseeventfAbsolute, absX, absY, wheelDelta)
	}
	if changed&0x10 != 0 && buttonMask&0x10 != 0 {
		sendMouseInput(mouseeventfWheel|mouseeventfAbsolute, absX, absY, negWheelDelta)
	}
	// Horizontal scroll: bit5=left (-120), bit6=right (+120).
	if changed&0x20 != 0 && buttonMask&0x20 != 0 {
		sendMouseInput(mouseeventfHWheel|mouseeventfAbsolute, absX, absY, negWheelDelta)
	}
	if changed&0x40 != 0 && buttonMask&0x40 != 0 {
		sendMouseInput(mouseeventfHWheel|mouseeventfAbsolute, absX, absY, wheelDelta)
	}
}

// keysym2VK maps X11 KeySyms used by RFB to Windows virtual-key codes.
func keysym2VK(keysym uint32) (vk uint16, scan uint16, extended bool) {
	// Latin-1 printable
	if keysym >= 0x20 && keysym <= 0x7e {
		r, _, _ := procVkKeyScanA.Call(uintptr(keysym))
		vk = uint16(r & 0xff)
		return
	}
	// Function keys
	if keysym >= 0xffbe && keysym <= 0xffc9 {
		vk = uint16(0x70 + keysym - 0xffbe)
		return
	}
	switch keysym {
	case 0xff08:
		vk = 0x08 // Backspace
	case 0xff09:
		vk = 0x09 // Tab
	case 0xff0d:
		vk = 0x0d // Return
	case 0xff1b:
		vk = 0x1b // Escape
	case 0xff63:
		vk, extended = 0x2d, true // Insert
	case 0xff9f, 0xffff:
		vk, extended = 0x2e, true // Delete
	case 0xff50:
		vk, extended = 0x24, true // Home
	case 0xff57:
		vk, extended = 0x23, true // End
	case 0xff55:
		vk, extended = 0x21, true // PageUp
	case 0xff56:
		vk, extended = 0x22, true // PageDown
	case 0xff51:
		vk, extended = 0x25, true // Left
	case 0xff52:
		vk, extended = 0x26, true // Up
	case 0xff53:
		vk, extended = 0x27, true // Right
	case 0xff54:
		vk, extended = 0x28, true // Down
	case 0xffe1, 0xffe2:
		vk = 0x10 // Shift
	case 0xffe3, 0xffe4:
		vk = 0x11 // Control
	case 0xffe7, 0xffe8:
		vk = 0x12 // Alt/Meta
	case 0xffe9, 0xffea:
		vk = 0x12 // Alt
	case 0xff20:
		vk = 0x14 // Caps Lock
	case 0xff61:
		vk = 0x2c // PrintScreen
	case 0xff13:
		vk = 0x13 // Pause
	case 0xff14:
		vk = 0x91 // ScrollLock
	}
	return
}

var procVkKeyScanA = user32.NewProc("VkKeyScanA")

// sasCtrlDown / sasAltDown track whether the client currently holds Ctrl/Alt,
// so we can detect the Ctrl+Alt+Del combination and route it to SendSAS.
var (
	sasCtrlDown bool
	sasAltDown  bool
)

// sendSAS signals the service process (session 0) to call SendSAS(FALSE).
// SendSAS only works when called from session 0; the agent runs in session 1,
// so it signals a named Windows event that the service listens for.
func sendSAS() {
	namePtr, err := windows.UTF16PtrFromString(sasTriggerEvent)
	if err != nil {
		log.Printf("[input] sendSAS: UTF16PtrFromString: %v", err)
		return
	}
	h, _, lerr := procOpenEventW.Call(
		uintptr(windows.EVENT_MODIFY_STATE),
		0, // bInheritHandle = FALSE
		uintptr(unsafe.Pointer(namePtr)),
	)
	if h == 0 {
		log.Printf("[input] sendSAS: OpenEvent(%s) failed: %v", sasTriggerEvent, lerr)
		return
	}
	ev := windows.Handle(h)
	defer windows.CloseHandle(ev)
	if err2 := windows.SetEvent(ev); err2 != nil {
		log.Printf("[input] sendSAS: SetEvent failed: %v", err2)
	} else {
		log.Printf("[input] SAS event signaled → service will call SendSAS from session 0")
	}
}

// SimulateKeyEvent handles an RFB key event.
func SimulateKeyEvent(keysym uint32, down bool) {
	// Track Ctrl/Alt modifier state for SAS detection.
	switch keysym {
	case 0xffe3, 0xffe4: // Left/Right Control
		sasCtrlDown = down
	case 0xffe7, 0xffe8, 0xffe9, 0xffea: // Meta/Alt
		sasAltDown = down
	}

	// Intercept Ctrl+Alt+Del → SendSAS instead of SendInput.
	// SendInput cannot inject the Secure Attention Sequence regardless of
	// privilege; the kernel intercepts it before the input stream.
	if (keysym == 0xff9f || keysym == 0xffff) && sasCtrlDown && sasAltDown {
		if down {
			sendSAS()
		}
		// Suppress both key-down and key-up for Delete to avoid orphaned events.
		return
	}

	vk, _, extended := keysym2VK(keysym)
	if vk == 0 {
		return
	}
	var flags uint32
	if !down {
		flags |= keyeventfKeyUp
	}
	if extended {
		flags |= extendedKeyFlag
	}
	sendKeyInput(vk, 0, flags)
}
