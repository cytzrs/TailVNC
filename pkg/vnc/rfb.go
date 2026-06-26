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

	encRaw      = 0
	encCopyRect = 1
	encZlib     = 6
	encTight    = 7
	encCursor   = -239 // Cursor pseudo-encoding: server sends shape, client renders locally
)

// The canonical RFB pixel format: 32 bpp, big-endian, XRGB
// byte[0]=0  byte[1]=R  byte[2]=G  byte[3]=B
// RedShift=16 means: in the big-endian 32-bit word, red occupies bits 16-23
// = byte offset 1 from the most-significant byte.
var serverPixelFormat = [16]byte{
	32,     // bits-per-pixel
	24,     // depth
	1,      // big-endian-flag  (1 = big-endian)
	1,      // true-colour-flag
	0, 255, // red-max   (big-endian uint16 = 255)
	0, 255, // green-max
	0, 255, // blue-max
	16,      // red-shift
	8,       // green-shift
	0,       // blue-shift
	0, 0, 0, // padding
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

	// encMu guards clientEncodings (written by the message loop, read by the
	// cursor push goroutine). cursorStop closes to signal the cursor loop exit.
	encMu      sync.Mutex
	cursorStop chan struct{}

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

	// Tight tuning parsed from pseudo-encodings in SetEncodings: zlib level
	// (1-9, default 6) and JPEG quality (0 = no JPEG; else 10-100).
	tightLevel  int
	jpegQuality int

	// zlibStream is the single persistent deflate context for the EncZlib
	// encoding (RFC 6143 §7.7.5): the connection must reuse ONE zlib stream so
	// the client's decompressor stays primed and dictionaries carry across
	// rectangles. Created lazily on the first zlib-encoded rect and closed when
	// the session ends. ZLIB-FIX: the old per-rect zlib.NewWriter+Close
	// finalized a standalone stream each time, so strict clients hit
	// end-of-stream after rect 1 and went silent (vnc connection timeout).
	zlibStream *rfbcore.ZlibStream
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
	defer s.closeZlibStream()

	s.initClientPixelFormat()
	s.tightLevel = 6 // default Tight zlib level until the client hints otherwise

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

	// Start the local-cursor push loop (only sends once the client advertises
	// the Cursor pseudo-encoding -239).
	s.cursorStop = make(chan struct{})
	defer close(s.cursorStop)
	go s.cursorSendLoop()

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

// cursorSendLoop pushes the cursor shape to the client when it changes AND the
// client advertised the Cursor pseudo-encoding (-239). The client then renders
// the cursor locally, so mouse motion costs no bandwidth. Exits when cursorStop
// closes (session end) or the connection breaks.
func (s *session) cursorSendLoop() {
	var prevHandle uintptr
	for {
		select {
		case <-s.cursorStop:
			return
		case <-time.After(100 * time.Millisecond): // ~10Hz shape-change poll
		}
		if !s.clientSupports(encCursor) {
			continue
		}
		shot := captureCursor(prevHandle)
		prevHandle = shot.handle
		if !shot.changed || shot.img == nil {
			continue
		}
		buf := rfbcore.EncodeCursorPseudoRect(shot.x, shot.y,
			shot.img.Bounds().Dx(), shot.img.Bounds().Dy(),
			shot.hotX, shot.hotY, s.pixelFormat(), shot.img)
		s.writeMu.Lock()
		_, err := s.conn.Write(buf)
		s.writeMu.Unlock()
		if err != nil {
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
	if numEnc > 256 { // SEC-5: bound untrusted client input
		return fmt.Errorf("too many encodings: %d (max 256)", numEnc)
	}
	buf := make([]byte, int(numEnc)*4)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}
	encs := make([]int32, numEnc)
	for i := uint16(0); i < numEnc; i++ {
		encs[i] = int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
	}
	// Parse Tight tuning pseudo-encodings: JPEG quality -23 (high) .. -32 (low)
	// and compression level -247 (high) .. -256 (low).
	for _, e := range encs {
		switch {
		case e >= -32 && e <= -23:
			s.jpegQuality = 100 - int(-23-e)*10 // -23 -> 100, -32 -> 10
		case e >= -256 && e <= -247:
			lvl := 9 - int(-247-e) // -247 -> 9, -256 -> 0
			if lvl < 1 {
				lvl = 1
			}
			s.tightLevel = lvl
		}
	}
	s.encMu.Lock()
	s.clientEncodings = encs
	s.encMu.Unlock()
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

	// Incremental request: ask the capturer what changed. Three outcomes —
	// full (deliver the whole frame so full-screen motion is visible, not
	// frozen), empty (nothing changed, tell the client to stop polling), or
	// dirty (send just the changed rects).
	if incremental == 1 {
		img, moves, dirty, full, err := s.capturer.CaptureDirty()
		if err != nil {
			return err
		}
		switch {
		case full:
			return s.sendFramebufferUpdate(img, 0, 0, s.serverW, s.serverH)
		case len(moves) == 0 && len(dirty) == 0:
			return s.sendEmptyUpdate()
		default:
			return s.sendDirtyUpdate(img, moves, dirty)
		}
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

// encodePixelRect selects the best wire encoding for one pixel rectangle given
// the client's advertised encodings and Tight tuning. It is shared by
// sendFramebufferUpdate (the single full-frame rect used for non-incremental
// requests and the CaptureDirty full-degradation path) and sendDirtyUpdate
// (each dirty rect) so both paths honor the negotiated encodings identically.
//
// Tight (Fill/Basic-zlib/JPEG) is preferred when the client supports it and the
// rect fits Tight's 2048px width limit; otherwise zlib (RFC 6143
// length-prefixed) when supported; otherwise Raw. EncodeDirtyRect downgrades to
// Raw on zlib failure (CORR-1), so a failure never corrupts the stream.
// rectPart is one wire rectangle: a 12-byte RFB rect header plus its encoding
// payload. A single logical framebuffer rectangle can expand into several
// rectParts — notably when the client only advertises Tight, whose rectangles
// are capped at 2048px wide, so a 2560px-wide full frame is split into vertical
// strips. Shared by sendFramebufferUpdate and sendDirtyUpdate.
type rectPart struct {
	hdr     [12]byte
	payload []byte
}

// encodePixelRect encodes one logical rectangle and returns the single rect
// part it produces. Kept for callers that can emit only one rect; the full-frame
// and dirty paths use encodePixelRects so a >2048px Tight rect is striped.
func (s *session) encodePixelRect(img *image.RGBA, x, y, w, h int) (enc int32, payload []byte) {
	parts := s.encodePixelRects(img, x, y, w, h)
	if len(parts) == 1 {
		return int32(binary.BigEndian.Uint32(parts[0].hdr[8:12])), parts[0].payload
	}
	// Should not happen for a single in-bounds rect, but stay safe.
	return rfbcore.EncodeDirtyRect(img, rfbcore.Rect{X: x, Y: y, W: w, H: h}, img.Stride, s.pixelFormat(), s.clientSupports(encZlib), s.getZlibStream())
}

// encodePixelRects encodes one logical pixel rectangle into one or more wire
// rects, honouring the client's negotiated encodings. Tight (Fill/Basic-zlib/
// JPEG) is preferred when the client supports it; because Tight caps each rect
// at 2048px wide (rfbproto.rst), a wider rectangle is split into vertical strips
// of <= 2048px, each emitted as its own Tight rect. This is what stops a
// 2560px-wide full frame from falling through to a 12 MB Raw rect (PERF/RFB:
// the previous code gated Tight on w<=2048, so any over-wide rect silently
// became Raw regardless of what the client advertised).
//
// Falls back to zlib (RFC 6143 length-prefixed, persistent stream) then Raw.
func (s *session) encodePixelRects(img *image.RGBA, x, y, w, h int) []rectPart {
	pf := s.pixelFormat()
	stride := img.Stride
	useJPEG := s.jpegQuality > 0 && (pf.Bpp == 32 || pf.Bpp == 16)

	if s.clientSupports(encTight) {
		const tightMaxW = 2048
		parts := make([]rectPart, 0, (w+tightMaxW-1)/tightMaxW)
		for sx := x; sx < x+w; sx += tightMaxW {
			sw := tightMaxW
			if sx+sw > x+w {
				sw = x + w - sx
			}
			rect := rfbcore.Rect{X: sx, Y: y, W: sw, H: h}
			tp, err := rfbcore.EncodeTight(img, rect, stride, pf, s.tightLevel, useJPEG, s.jpegQuality)
			if err != nil {
				// Tight failed for this strip -> abandon Tight entirely and fall
				// through to the zlib/raw single-rect path below.
				break
			}
			var p rectPart
			binary.BigEndian.PutUint16(p.hdr[0:2], uint16(sx))
			binary.BigEndian.PutUint16(p.hdr[2:4], uint16(y))
			binary.BigEndian.PutUint16(p.hdr[4:6], uint16(sw))
			binary.BigEndian.PutUint16(p.hdr[6:8], uint16(h))
			binary.BigEndian.PutUint32(p.hdr[8:12], uint32(encTight))
			p.payload = tp
			parts = append(parts, p)
		}
		if len(parts) > 0 {
			return parts
		}
	}

	enc, payload := rfbcore.EncodeDirtyRect(img, rfbcore.Rect{X: x, Y: y, W: w, H: h}, stride, pf, s.clientSupports(encZlib), s.getZlibStream())
	var p rectPart
	binary.BigEndian.PutUint16(p.hdr[0:2], uint16(x))
	binary.BigEndian.PutUint16(p.hdr[2:4], uint16(y))
	binary.BigEndian.PutUint16(p.hdr[4:6], uint16(w))
	binary.BigEndian.PutUint16(p.hdr[6:8], uint16(h))
	binary.BigEndian.PutUint32(p.hdr[8:12], uint32(enc))
	p.payload = payload
	return []rectPart{p}
}

// writeUpdate assembles a FramebufferUpdate message from the given rect parts and
// writes it atomically under writeMu. Shared by sendFramebufferUpdate and
// sendDirtyUpdate so both paths emit identically-framed updates.
func (s *session) writeUpdate(parts []rectPart) error {
	if len(parts) == 0 {
		return s.sendEmptyUpdate()
	}
	totalLen := 4
	for _, p := range parts {
		totalLen += 12 + len(p.payload)
	}
	msg := make([]byte, totalLen)
	msg[0] = serverFramebufferUpdate
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(parts)))
	off := 4
	for _, p := range parts {
		copy(msg[off:], p.hdr[:])
		off += 12
		copy(msg[off:], p.payload)
		off += len(p.payload)
	}
	log.Printf("[%s] >> FBU %d rects (%d bytes)", s.addr(), len(parts), len(msg))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write(msg)
	if err != nil {
		log.Printf("[%s]    write error: %v", s.addr(), err)
	}
	return err
}

// sendDirtyUpdate sends a FramebufferUpdate containing CopyRect moves (when the
// client supports it) plus dirty pixel rectangles. Each rect is encoded
// separately; dirty pixel rects use zlib when the client supports it, otherwise
// Raw (EncodeDirtyRect downgrades on zlib failure — CORR-1). A move whose client
// lacks CopyRect support is sent as destination pixels instead.
func (s *session) sendDirtyUpdate(img *image.RGBA, moves []rfbcore.CopyRect, dirty []rfbcore.Rect) error {
	useCopyRect := s.clientSupports(encCopyRect)

	// Build each rect (12-byte header + payload) up front. Dirty/move rects are
	// already small (<= DirtyTileSize / detected moves), so they rarely need
	// strip-splitting, but encodePixelRects handles over-wide rects (e.g. a
	// coalesced dirty rect or a >2048px move) identically to the full-frame path.
	parts := make([]rectPart, 0, len(moves)+len(dirty))

	addCopyRect := func(mv rfbcore.CopyRect) {
		var p rectPart
		binary.BigEndian.PutUint16(p.hdr[0:2], uint16(mv.DstX))
		binary.BigEndian.PutUint16(p.hdr[2:4], uint16(mv.DstY))
		binary.BigEndian.PutUint16(p.hdr[4:6], uint16(mv.W))
		binary.BigEndian.PutUint16(p.hdr[6:8], uint16(mv.H))
		binary.BigEndian.PutUint32(p.hdr[8:12], uint32(encCopyRect))
		payload := make([]byte, 4) // srcX, srcY (big-endian uint16 each)
		binary.BigEndian.PutUint16(payload[0:2], uint16(mv.SrcX))
		binary.BigEndian.PutUint16(payload[2:4], uint16(mv.SrcY))
		p.payload = payload
		parts = append(parts, p)
	}
	addPixels := func(x, y, w, h int) {
		parts = append(parts, s.encodePixelRects(img, x, y, w, h)...)
	}

	for _, mv := range moves {
		if useCopyRect {
			addCopyRect(mv)
		} else {
			addPixels(mv.DstX, mv.DstY, mv.W, mv.H) // no CopyRect: send dst pixels
		}
	}
	for _, r := range dirty {
		addPixels(r.X, r.Y, r.W, r.H)
	}

	return s.writeUpdate(parts)
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

	// Encode the rectangle with the client's negotiated encoding (Tight when
	// supported, else zlib, else Raw). Tight caps each rect at 2048px wide, so a
	// 2560px-wide full frame is split into <=2048px vertical strips here — each
	// its own Tight rect — instead of collapsing to a 12 MB Raw frame (which
	// saturated the link and tripped the 30s read deadline). For a client that
	// also advertises Zlib/Tight the whole frame stays compressed.
	parts := s.encodePixelRects(img, x, y, w, h)
	return s.writeUpdate(parts)
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
// Guarded by encMu so the cursor push goroutine can call it concurrently with
// SetEncodings.
func (s *session) clientSupports(enc int32) bool {
	s.encMu.Lock()
	defer s.encMu.Unlock()
	for _, e := range s.clientEncodings {
		if e == enc {
			return true
		}
	}
	return false
}

// zlibStream returns the connection's persistent EncZlib deflate context,
// creating it lazily on first use. Only the message loop (which runs
// handleFBUpdateRequest -> send*Update -> encodePixelRect) calls this, so it is
// single-goroutine by construction; closeZlibStream runs at session teardown
// after the loop has exited. ZLIB-FIX (RFC 6143 §7.7.5).
func (s *session) getZlibStream() *rfbcore.ZlibStream {
	if s.zlibStream == nil {
		s.zlibStream = rfbcore.NewZlibStream(6)
	}
	return s.zlibStream
}

// closeZlibStream releases the persistent deflate context at session end. It is
// a no-op when the client never used EncZlib (no stream was ever created).
func (s *session) closeZlibStream() {
	if s.zlibStream != nil {
		s.zlibStream.Close()
	}
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
