//go:build windows

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

// inputState holds per-session input tracking that must not be shared across
// concurrent VNC clients (CORR-2: previously package globals).
type inputState struct {
	prevButton uint8
	ctrlDown   bool
	altDown    bool
}

// buttonEvent sends press/release events for changed buttons.
// RFB button mask bits:
//
//	bit0=left  bit1=middle  bit2=right
//	bit3=wheel-up  bit4=wheel-down  bit5=wheel-left  bit6=wheel-right
func (st *inputState) buttonEvent(buttonMask uint8, x, y, screenW, screenH int) {
	changed := buttonMask ^ st.prevButton
	st.prevButton = buttonMask

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
// Uses a pre-built table (keysymTable) populated at init time with
// layout-aware mappings via VkKeyScanExW + MapVirtualKeyW. Falls back to
// a dynamic VkKeyScanExW call for Latin-1 characters not in the table.
func keysym2VK(keysym uint32) (vk uint16, scan uint16, extended bool) {
	if m, ok := keysymTable[keysym]; ok {
		return m.vk, m.scan, m.extended
	}
	// Dynamic fallback for Latin-1 chars not cached at init.
	if keysym >= 0x20 && keysym <= 0xff {
		hkl, _, _ := procGetKeyboardLayout.Call(0)
		r, _, _ := procVkKeyScanExW.Call(uintptr(keysym), hkl)
		if r != 0xFFFFFFFF && r&0xFF != 0xFF {
			vk = uint16(r & 0xFF)
			sc, _, _ := procMapVirtualKeyW.Call(uintptr(vk), mapvkVkToVsc)
			return vk, uint16(sc), false
		}
	}
	return
}

var (
	procVkKeyScanExW    = user32.NewProc("VkKeyScanExW")
	procMapVirtualKeyW  = user32.NewProc("MapVirtualKeyW")
	procGetKeyboardLayout = user32.NewProc("GetKeyboardLayout")
)

const (
	mapvkVkToVsc = 0 // MAPVK_VK_TO_VSC
	mapvkVkToChar = 2 // MAPVK_VK_TO_CHAR
)

// keyMapping holds the Windows VK code, scan code, and extended flag for an
// X11 keysym.
type keyMapping struct {
	vk       uint16
	scan     uint16
	extended bool
}

// keysymTable maps X11 KeySyms to Windows virtual-key codes. Built once at
// init from the hardcoded X11→VK table (control/edit/function/movement keys)
// plus a dynamic Latin-1 range via VkKeyScanExW for the current keyboard layout.
var keysymTable map[uint32]keyMapping

// staticKeysymMap contains the fixed X11→VK mappings that do not depend on
// keyboard layout. These cover control keys, navigation keys, function keys,
// and modifiers — all of which have well-defined VK codes regardless of layout.
var staticKeysymMap = map[uint32]keyMapping{
	// Edit keys
	0xff08: {0x08, 0, false}, // Backspace
	0xff09: {0x09, 0, false}, // Tab
	0xff0d: {0x0d, 0, false}, // Return
	0xff1b: {0x1b, 0, false}, // Escape
	0xff63: {0x2d, 0, true},  // Insert
	0xff9f: {0x2e, 0, true},  // Delete (KP_Delete)
	0xffff: {0x2e, 0, true},  // Delete

	// Navigation keys (all extended)
	0xff50: {0x24, 0, true}, // Home
	0xff57: {0x23, 0, true}, // End
	0xff55: {0x21, 0, true}, // PageUp
	0xff56: {0x22, 0, true}, // PageDown
	0xff51: {0x25, 0, true}, // Left
	0xff52: {0x26, 0, true}, // Up
	0xff53: {0x27, 0, true}, // Right
	0xff54: {0x28, 0, true}, // Down

	// Modifiers
	0xffe1: {0x10, 0, false}, // Left Shift
	0xffe2: {0x10, 0, false}, // Right Shift
	0xffe3: {0x11, 0, false}, // Left Control
	0xffe4: {0x11, 0, false}, // Right Control
	0xffe7: {0x12, 0, false}, // Left Meta (Alt)
	0xffe8: {0x12, 0, false}, // Right Meta (Alt)
	0xffe9: {0x12, 0, false}, // Left Alt
	0xffea: {0x12, 0, false}, // Right Alt

	// Lock/special keys
	0xff20: {0x14, 0, false}, // Caps Lock
	0xff61: {0x2c, 0, false}, // PrintScreen
	0xff13: {0x13, 0, false}, // Pause
	0xff14: {0x91, 0, false}, // ScrollLock

	// NumLock
	0xff7f: {0x90, 0, false},

	// Space
	0x020: {0x20, 0, false},
}

func init() {
	keysymTable = make(map[uint32]keyMapping, len(staticKeysymMap)+95)

	// Copy static mappings and resolve scan codes via MapVirtualKeyW.
	for ks, m := range staticKeysymMap {
		if m.scan == 0 {
			sc, _, _ := procMapVirtualKeyW.Call(uintptr(m.vk), mapvkVkToVsc)
			m.scan = uint16(sc)
		}
		keysymTable[ks] = m
	}

	// Function keys F1–F12 (0xffbe–0xffc9 → VK_F1–VK_F12 = 0x70–0x7B).
	for i := uint32(0); i < 12; i++ {
		vk := uint16(0x70 + i)
		sc, _, _ := procMapVirtualKeyW.Call(uintptr(vk), mapvkVkToVsc)
		keysymTable[0xffbe+i] = keyMapping{vk: vk, scan: uint16(sc)}
	}

	// Latin-1 printable range (0x21–0x7e): use VkKeyScanExW for layout-aware
	// mapping. Skip 0x20 (space, handled in static table).
	hkl, _, _ := procGetKeyboardLayout.Call(0)
	for ch := uint32(0x21); ch <= 0x7e; ch++ {
		r, _, _ := procVkKeyScanExW.Call(uintptr(ch), hkl)
		if r != 0xFFFFFFFF && r&0xFF != 0xFF {
			vk := uint16(r & 0xFF)
			sc, _, _ := procMapVirtualKeyW.Call(uintptr(vk), mapvkVkToVsc)
			keysymTable[ch] = keyMapping{vk: vk, scan: uint16(sc)}
		}
	}
}

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

// keyEvent handles an RFB key event.
func (st *inputState) keyEvent(keysym uint32, down bool) {
	// Track Ctrl/Alt modifier state for SAS detection.
	switch keysym {
	case 0xffe3, 0xffe4: // Left/Right Control
		st.ctrlDown = down
	case 0xffe7, 0xffe8, 0xffe9, 0xffea: // Meta/Alt
		st.altDown = down
	}

	// Intercept Ctrl+Alt+Del → SendSAS instead of SendInput.
	// SendInput cannot inject the Secure Attention Sequence regardless of
	// privilege; the kernel intercepts it before the input stream.
	if (keysym == 0xff9f || keysym == 0xffff) && st.ctrlDown && st.altDown {
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
