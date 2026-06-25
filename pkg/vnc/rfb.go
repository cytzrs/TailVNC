//go:build windows

package vnc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tailvnc/pkg/rfbcore"
)

const (
	rfbProtocolVersion = "RFB 003.008\n"

	secNone    = 1
	secVNCAuth = 2

	clientSetPixelFormat           = 0
	clientSetEncodings             = 2
	clientFramebufferUpdateRequest = 3
	clientKeyEvent                 = 4
	clientPointerEvent             = 5
	clientCutText                  = 6

	serverFramebufferUpdate = 0
	serverCutText           = 3

	encRaw     = 0
	encCopyRect = 1
	encZlib     = 6
	encTight    = 7
)

// The canonical RFB pixel format: 32 bpp, big-endian, XRGB
// byte[0]=0  byte[1]=R  byte[2]=G  byte[3]=B
// RedShift=16 means: in the big-endian 32-bit word, red occupies bits 16-23
// = byte offset 1 from the most-significant byte.
var serverPixelFormat = [16]byte{
	32,          // bits-per-pixel
	24,          // depth
	1,           // big-endian-flag  (1 = big-endian)
	1,           // true-colour-flag
	0, 255,      // red-max   (big-endian uint16 = 255)
	0, 255,      // green-max
	0, 255,      // blue-max
	16,          // red-shift
	8,           // green-shift
	0,           // blue-shift
	0, 0, 0,     // padding
}

// session handles a single VNC client connection.
type session struct {
	conn      net.Conn
	capturer  ScreenCapturer
	injector  InputInjector
	clipBoard ClipboardBridge
	serverW   int
	serverH   int
	password  string

	// writeMu protects all writes to conn (message loop + clipboard goroutine).
	writeMu sync.Mutex

	// client's current pixel format (updated by SetPixelFormat messages)
	clientBpp       uint8
	clientBigEndian uint8
	clientRMax      uint16
	clientGMax      uint16
	clientBMax      uint16
	clientRShift    uint8
	clientGShift    uint8
	clientBShift    uint8

	// encodings the client declared via SetEncodings.  Empty = only Raw(0).
	clientEncodings []int32
}

func (s *session) addr() string { return s.conn.RemoteAddr().String() }

// syncDims refreshes the cached framebuffer dimensions from the capturer.
// The capturer tracks the current desktop, whose resolution may change on a
// desktop transition (e.g. to the Winlogon secure desktop); a stale snapshot
// would shift injected pointer coordinates and mis-clamp framebuffer updates.
func (s *session) syncDims() {
	if w, h := s.capturer.Width(), s.capturer.Height(); w > 0 && h > 0 {
		s.serverW = w
		s.serverH = h
	}
}

// initClientPixelFormat sets the client pixel format to match the server's
// declared ServerInit format. Called once before the handshake.
func (s *session) initClientPixelFormat() {
	s.clientBpp = serverPixelFormat[0]
	s.clientBigEndian = serverPixelFormat[2]
	s.clientRMax = binary.BigEndian.Uint16(serverPixelFormat[4:6])
	s.clientGMax = binary.BigEndian.Uint16(serverPixelFormat[6:8])
	s.clientBMax = binary.BigEndian.Uint16(serverPixelFormat[8:10])
	s.clientRShift = serverPixelFormat[10]
	s.clientGShift = serverPixelFormat[11]
	s.clientBShift = serverPixelFormat[12]
}

// Serve runs the RFB handshake then the main message loop.
func (s *session) Serve() {
	defer s.conn.Close()

	s.initClientPixelFormat()

	if err := s.handshake(); err != nil {
		log.Printf("[%s] handshake: %v", s.addr(), err)
		return
	}
	log.Printf("[%s] connected", s.addr())

	// Start goroutine to push server-side clipboard changes to the client.
	if s.clipBoard != nil {
		clipCh := s.clipBoard.Subscribe()
		defer s.clipBoard.Unsubscribe(clipCh)
		go s.clipboardSendLoop(clipCh)
	}

	if err := s.messageLoop(); err != nil && err != io.EOF {
		log.Printf("[%s] disconnected: %v", s.addr(), err)
	} else {
		log.Printf("[%s] disconnected", s.addr())
	}
}

// clipboardSendLoop watches for server-side clipboard changes and sends
// ServerCutText messages to the VNC client.
func (s *session) clipboardSendLoop(ch chan string) {
	for text := range ch {
		if err := s.sendServerCutText(text); err != nil {
			return
		}
	}
}

// sendServerCutText sends a ServerCutText message (type 3) to the client.
// Text is encoded as Latin-1 (ISO 8859-1) per the RFB spec.
func (s *session) sendServerCutText(text string) error {
	latin1 := rfbcore.UTF8ToLatin1(text)
	buf := make([]byte, 8+len(latin1))
	buf[0] = serverCutText
	// buf[1..3] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(latin1)))
	copy(buf[8:], latin1)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write(buf)
	return err
}

func (s *session) handshake() error {
	// 1. Server → Client: version
	if _, err := io.WriteString(s.conn, rfbProtocolVersion); err != nil {
		return err
	}

	// 2. Client → Server: version
	var clientVer [12]byte
	if _, err := io.ReadFull(s.conn, clientVer[:]); err != nil {
		return err
	}
	log.Printf("[%s] client version: %q", s.addr(), string(clientVer[:]))

	// 3. Server → Client: security type list
	//    No password → offer None(1) so clients without a password can skip auth.
	//    With password → offer VNCAuth(2) only, client must authenticate.
	if s.password == "" {
		if _, err := s.conn.Write([]byte{1, secNone}); err != nil {
			return err
		}
	} else {
		if _, err := s.conn.Write([]byte{1, secVNCAuth}); err != nil {
			return err
		}
	}

	// 4. Client → Server: chosen security type
	var secType [1]byte
	if _, err := io.ReadFull(s.conn, secType[:]); err != nil {
		return err
	}
	log.Printf("[%s] security type selected: %d", s.addr(), secType[0])

	// 5. Authentication
	switch secType[0] {
	case secVNCAuth:
		if err := s.doVNCAuth(); err != nil {
			return err
		}
	case secNone:
		// SecurityResult OK (required by RFB 3.8 even for None)
		if err := binary.Write(s.conn, binary.BigEndian, uint32(0)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported security type: %d", secType[0])
	}

	// 6. Client → Server: ClientInit (shared flag, 1 byte)
	var clientInit [1]byte
	if _, err := io.ReadFull(s.conn, clientInit[:]); err != nil {
		return err
	}
	log.Printf("[%s] ClientInit: shared=%d", s.addr(), clientInit[0])

	// 7. Server → Client: ServerInit
	return s.sendServerInit()
}

// authFails counts recent VNCAuth failures per remote address (SEC-1) so
// repeated wrong passwords are throttled, slowing online brute force of the
// weak single-DES VNC auth.
var (
	authFailMu sync.Mutex
	authFails  = map[string]int{}
)

// authBackoff sleeps before replying to a failed auth, scaling with the count
// of recent failures from the same remote address (1s, 2s, ... capped 30s).
func authBackoff(remote string) {
	authFailMu.Lock()
	n := authFails[remote] + 1
	authFails[remote] = n
	authFailMu.Unlock()
	d := time.Second << uint(min(n, 5))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	time.Sleep(d)
}

// authReset clears the failure counter on a successful auth.
func authReset(remote string) {
	authFailMu.Lock()
	delete(authFails, remote)
	authFailMu.Unlock()
}

// doVNCAuth performs the RFB VNC Authentication challenge-response (security type 2).
// Key bytes are bit-reversed per the RFB spec. Empty server password accepts any client.
func (s *session) doVNCAuth() error {
	if s.password == "" {
		return fmt.Errorf("vnc auth requested but no server password configured")
	}
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if _, err := s.conn.Write(challenge); err != nil {
		return err
	}

	response := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, response); err != nil {
		return err
	}

	var result uint32
	expected, err := rfbcore.VncAuthEncrypt(challenge, s.password)
	if err != nil {
		return fmt.Errorf("vnc auth: %w", err)
	}
	if !bytes.Equal(expected, response) {
		result = 1
	}

	// SEC-1: throttle repeated failures from the same remote address.
	if result != 0 {
		authBackoff(s.addr())
	} else {
		authReset(s.addr())
	}

	if err := binary.Write(s.conn, binary.BigEndian, result); err != nil {
		return err
	}
	if result != 0 {
		msg := "Authentication failed"
		binary.Write(s.conn, binary.BigEndian, uint32(len(msg)))
		s.conn.Write([]byte(msg))
		return fmt.Errorf("authentication failed")
	}
	return nil
}

func (s *session) sendServerInit() error {
	buf := make([]byte, 0, 4+16+4+5)

	// framebuffer width + height (big-endian uint16 each)
	buf = append(buf, byte(s.serverW>>8), byte(s.serverW))
	buf = append(buf, byte(s.serverH>>8), byte(s.serverH))

	// pixel format (16 bytes, as defined in serverPixelFormat)
	buf = append(buf, serverPixelFormat[:]...)

	// name: "GoVNC"
	name := []byte("GoVNC")
	buf = append(buf,
		byte(len(name)>>24), byte(len(name)>>16),
		byte(len(name)>>8), byte(len(name)),
	)
	buf = append(buf, name...)

	log.Printf("[%s] ServerInit: %dx%d, %d bytes", s.addr(), s.serverW, s.serverH, len(buf))
	_, err := s.conn.Write(buf)
	return err
}

var msgNames = map[uint8]string{
	0: "SetPixelFormat",
	2: "SetEncodings",
	3: "FramebufferUpdateRequest",
	4: "KeyEvent",
	5: "PointerEvent",
	6: "ClientCutText",
}

func (s *session) messageLoop() error {
	for {
		var msgType [1]byte
		if err := s.conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return err
		}
		if _, err := io.ReadFull(s.conn, msgType[:]); err != nil {
			return err
		}
		s.conn.SetDeadline(time.Time{})

		name, known := msgNames[msgType[0]]
		if !known {
			name = fmt.Sprintf("Unknown(%d)", msgType[0])
		}
		log.Printf("[%s] << %s", s.addr(), name)

		switch msgType[0] {
		case clientSetPixelFormat:
			if err := s.handleSetPixelFormat(); err != nil {
				return err
			}
		case clientSetEncodings:
			if err := s.handleSetEncodings(); err != nil {
				return err
			}
		case clientFramebufferUpdateRequest:
			if err := s.handleFBUpdateRequest(); err != nil {
				return err
			}
		case clientKeyEvent:
			if err := s.handleKeyEvent(); err != nil {
				return err
			}
		case clientPointerEvent:
			if err := s.handlePointerEvent(); err != nil {
				return err
			}
		case clientCutText:
			if err := s.handleCutText(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown client message type: %d", msgType[0])
		}
	}
}

func (s *session) handleSetPixelFormat() error {
	// body: 3-byte padding + 16-byte pixel-format = 19 bytes
	var buf [19]byte
	if _, err := io.ReadFull(s.conn, buf[:]); err != nil {
		return err
	}
	pf := buf[3:19]

	s.clientBpp = pf[0]
	s.clientBigEndian = pf[2]
	s.clientRMax = binary.BigEndian.Uint16(pf[4:6])
	s.clientGMax = binary.BigEndian.Uint16(pf[6:8])
	s.clientBMax = binary.BigEndian.Uint16(pf[8:10])
	s.clientRShift = pf[10]
	s.clientGShift = pf[11]
	s.clientBShift = pf[12]

	log.Printf("[%s]   SetPixelFormat: bpp=%d depth=%d bigEndian=%d trueColor=%d rMax=%d gMax=%d bMax=%d rShift=%d gShift=%d bShift=%d",
		s.addr(),
		pf[0], pf[1], pf[2], pf[3],
		s.clientRMax, s.clientGMax, s.clientBMax,
		s.clientRShift, s.clientGShift, s.clientBShift,
	)
	return nil
}

func (s *session) handleSetEncodings() error {
	var header [3]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return err
	}
	numEnc := binary.BigEndian.Uint16(header[1:3])
	buf := make([]byte, int(numEnc)*4)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}
	encs := make([]int32, numEnc)
	for i := uint16(0); i < numEnc; i++ {
		encs[i] = int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
	}
	s.clientEncodings = encs
	log.Printf("[%s]   SetEncodings: %d encodings %v", s.addr(), numEnc, encs)
	return nil
}

func (s *session) handleFBUpdateRequest() error {
	var req [9]byte
	if _, err := io.ReadFull(s.conn, req[:]); err != nil {
		return err
	}
	incremental := req[0]
	x := int(binary.BigEndian.Uint16(req[1:3]))
	y := int(binary.BigEndian.Uint16(req[3:5]))
	w := int(binary.BigEndian.Uint16(req[5:7]))
	h := int(binary.BigEndian.Uint16(req[7:9]))

	s.syncDims()

	// Incremental requests with nothing changed: send an empty update so the
	// client stops asking until the next change.  This is what makes a static
	// desktop consume ~0 bandwidth instead of re-sending the full frame.
	if incremental == 1 {
		img, dirty, err := s.capturer.CaptureDirty()
		if err != nil {
			return err
		}
		if len(dirty) == 0 {
			// No changes since last frame → empty FramebufferUpdate.
			return s.sendEmptyUpdate()
		}
		return s.sendDirtyUpdate(img, dirty)
	}

	// Non-incremental (full) request: send the whole requested rectangle.
	log.Printf("[%s]   FBUpdateReq: full x=%d y=%d w=%d h=%d", s.addr(), x, y, w, h)
	img, err := s.capturer.Capture()
	if err != nil {
		return err
	}
	return s.sendFramebufferUpdate(img, x, y, w, h)
}

// sendEmptyUpdate sends a FramebufferUpdate with zero rectangles, telling the
// client the framebuffer has not changed.  Lets the client stop polling until
// the next real change.
func (s *session) sendEmptyUpdate() error {
	hdr := make([]byte, 4)
	hdr[0] = serverFramebufferUpdate
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:4], 0) // numRects = 0
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write(hdr)
	return err
}

// sendDirtyUpdate sends a FramebufferUpdate containing only the changed
// rectangles.  Each rectangle is encoded separately; when the client supports
// zlib, pixel data is zlib-compressed (encoding 6), otherwise Raw(0).
func (s *session) sendDirtyUpdate(img *image.RGBA, dirty []rfbcore.Rect) error {
	stride := img.Stride
	useZlib := s.clientSupports(encZlib)
	pf := s.pixelFormat()

	// Build the whole message in one buffer: header + per-rect (12-byte hdr +
	// pixel payload). EncodeDirtyRect handles zlib and downgrades to Raw on
	// compression failure (CORR-1: never emit raw bytes under encZlib).
	rectHdrs := make([][]byte, 0, len(dirty))
	pixels := make([][]byte, 0, len(dirty))
	totalLen := 4

	for _, r := range dirty {
		enc, payload := rfbcore.EncodeDirtyRect(img, r, stride, pf, useZlib)
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[0:2], uint16(r.X))
		binary.BigEndian.PutUint16(hdr[2:4], uint16(r.Y))
		binary.BigEndian.PutUint16(hdr[4:6], uint16(r.W))
		binary.BigEndian.PutUint16(hdr[6:8], uint16(r.H))
		binary.BigEndian.PutUint32(hdr[8:12], uint32(enc))
		rectHdrs = append(rectHdrs, hdr)
		pixels = append(pixels, payload)
		totalLen += 12 + len(payload)
	}

	msg := make([]byte, totalLen)
	msg[0] = serverFramebufferUpdate
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(dirty)))
	off := 4
	for i := range dirty {
		copy(msg[off:], rectHdrs[i])
		off += 12
		copy(msg[off:], pixels[i])
		off += len(pixels[i])
	}

	log.Printf("[%s] >> FBU dirty %d rects (%d bytes, zlib=%v)", s.addr(), len(dirty), len(msg), useZlib)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write(msg)
	return err
}

func (s *session) sendFramebufferUpdate(img *image.RGBA, x, y, w, h int) error {
	// clamp to framebuffer bounds
	if x+w > s.serverW {
		w = s.serverW - x
	}
	if y+h > s.serverH {
		h = s.serverH - y
	}
	if w <= 0 || h <= 0 {
		return nil
	}

	pf := s.pixelFormat()
	bytesPerPixel := pf.BytesPerPixel()
	pixelBytes := w * h * bytesPerPixel
	buf := make([]byte, 4+12+pixelBytes)

	// FramebufferUpdate header: type(1) + padding(1) + numRects(2)
	buf[0] = serverFramebufferUpdate
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 1)

	// Rectangle header: x(2)+y(2)+w(2)+h(2)+encoding(4)
	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encRaw))

	// Encode pixels.  The common case — a 32-bpp client using the canonical
	// RGB-255 / R,G,B-shift 16,8,0 format — is handled by the fast path
	// (bulk per-row copy with an optional byte-swap).  Anything else falls
	// back to the generic per-pixel loop for correctness.
	off := 16
	stride := img.Stride

	if rfbcore.CanUseFastPath(pf) {
		rfbcore.EncodePixelsFast(img, x, y, w, h, stride, pf.BigEndian != 0, buf[off:])
	} else {
		rfbcore.EncodePixelsGeneric(img, x, y, w, h, stride, bytesPerPixel, pf, buf[off:])
	}

	log.Printf("[%s] >> FBU raw %dx%d (%d bytes)", s.addr(), w, h, len(buf))
	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	if err != nil {
		log.Printf("[%s]    write error: %v", s.addr(), err)
	}
	return err
}

// pixelFormat snapshots the client-negotiated pixel format from the session
// fields into the rfbcore value the encoders consume.
func (s *session) pixelFormat() rfbcore.PixelFormat {
	return rfbcore.PixelFormat{
		Bpp:       s.clientBpp,
		BigEndian: s.clientBigEndian,
		RMax:      s.clientRMax,
		GMax:      s.clientGMax,
		BMax:      s.clientBMax,
		RShift:    s.clientRShift,
		GShift:    s.clientGShift,
		BShift:    s.clientBShift,
	}
}

// clientSupports reports whether the client advertised the given encoding.
func (s *session) clientSupports(enc int32) bool {
	for _, e := range s.clientEncodings {
		if e == enc {
			return true
		}
	}
	return false
}

func (s *session) handleKeyEvent() error {
	var data [7]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return err
	}
	down := data[0] == 1
	keysym := binary.BigEndian.Uint32(data[3:7])
	s.injector.InjectKey(keysym, down)
	return nil
}

func (s *session) handlePointerEvent() error {
	var data [5]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return err
	}
	buttonMask := data[0]
	x := int(binary.BigEndian.Uint16(data[1:3]))
	y := int(binary.BigEndian.Uint16(data[3:5]))
	s.syncDims()
	s.injector.InjectPointer(buttonMask, x, y, s.serverW, s.serverH)
	return nil
}

func (s *session) handleCutText() error {
	var header [7]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[3:7])
	if length > 1<<20 {
		return fmt.Errorf("cut text too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}
	// RFB ClientCutText is Latin-1 encoded; convert to UTF-8 for Windows clipboard.
	if s.clipBoard != nil && length > 0 {
		s.clipBoard.SetText(rfbcore.Latin1ToUTF8(buf))
	}
	return nil
}
