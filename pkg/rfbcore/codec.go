package rfbcore

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"image"
	"io"
)

// RFB rectangle encodings used by this package.
const (
	EncRaw  int32 = 0
	EncZlib int32 = 6
)

// ZlibStream wraps a persistent zlib deflater. RFC 6143 §7.7.5 requires the
// Zlib encoding to reuse ONE deflate stream for the whole connection so the
// client keeps a single decompressor primed and benefits from cross-rectangle
// dictionary reuse.
//
// The previous implementation called zlib.NewWriter()+Close() per rectangle,
// which finalizes a standalone zlib stream each time; a strict client's
// persistent decompressor reaches end-of-stream after the first rect and then
// chokes on the next rect's fresh zlib header, goes silent, and trips the
// server's read deadline ("vnc connection timeout" / i/o timeout).
//
// ZlibStream keeps one writer alive for the session. For each rectangle it
// writes the pixels and then Flushes (Z_SYNC_FLUSH), which emits a sync point
// so the decoder can reproduce those pixels now while keeping the deflate
// context open for the next rectangle. It never calls Close mid-session.
type ZlibStream struct {
	buf    bytes.Buffer // accumulates all compressed output for the session
	zw     *zlib.Writer // single persistent deflater, never Reset on the live path
	mark   int          // buffer offset where this rect's compressed bytes begin
	closed bool
}

// NewZlibStream creates a persistent zlib stream at the given compression level
// (1-9). Use 6 when in doubt (the historical default). The writer is bound to
// the stream's buffer once and reused for every rectangle.
func NewZlibStream(level int) *ZlibStream {
	if level < 1 {
		level = 1
	}
	if level > 9 {
		level = 9
	}
	zs := &ZlibStream{}
	zs.zw, _ = zlib.NewWriterLevel(&zs.buf, level)
	return zs
}

// Compress feeds src into the persistent deflate stream, flushes it so the bytes
// are decodable on their own, and returns the compressed bytes that belong to
// this rectangle. The returned slice aliases the internal buffer and is only
// valid until the next call.
//
// A Flush (Z_SYNC_FLUSH), not a Close, keeps the stream open so the client
// decompressor never sees an end-of-stream marker mid-connection; the next
// rectangle continues the same dictionary. This is the single fix that makes
// EncZlib conform to RFB. The buffer is never Reset, so all compressed output
// accumulates; mark tracks where the current rect's output begins so we can
// slice out exactly its bytes.
func (z *ZlibStream) Compress(src []byte) ([]byte, error) {
	if z.closed {
		return nil, errStreamClosed
	}
	z.mark = z.buf.Len()
	if _, err := z.zw.Write(src); err != nil {
		return nil, err
	}
	// Z_SYNC_FLUSH: emit a sync point so the decoder can reproduce the pixels
	// now, WITHOUT closing the stream (the dictionary stays alive for the next
	// rect). This is exactly what RFC 6143's Zlib encoding expects.
	if err := z.zw.Flush(); err != nil {
		return nil, err
	}
	return z.buf.Bytes()[z.mark:], nil
}

// Close releases the underlying compressor. Safe to call multiple times.
func (z *ZlibStream) Close() error {
	if z.closed {
		return nil
	}
	z.closed = true
	if z.zw != nil {
		err := z.zw.Close()
		z.zw = nil
		return err
	}
	return nil
}

var errStreamClosed = io.ErrClosedPipe

// EncodeDirtyRect encodes one changed rectangle and returns the RFB encoding
// actually used plus the payload. CORR-1: on zlib failure it downgrades to
// EncRaw rather than emitting raw bytes under an EncZlib header (which would
// corrupt the client stream).
//
// CORR-6 / ZLIB-FIX: the EncZlib payload is RFC 6143 §7.7.5 wire format — a
// 4-byte big-endian length prefix (the number of compressed bytes that follow)
// then a fragment of the connection's single persistent zlib stream. When stream
// is non-nil the caller-supplied persistent context is used (correct RFB
// behaviour, dictionary reuse across rectangles); when stream is nil the
// rectangle is compressed with a fresh per-rect stream (kept only so legacy
// tests and single-shot callers still work — NOT for live clients).
func EncodeDirtyRect(img *image.RGBA, r Rect, stride int, pf PixelFormat, useZlib bool, stream *ZlibStream) (encoding int32, payload []byte) {
	px := EncodeRectPixels(img, r.X, r.Y, r.W, r.H, stride, pf)
	if useZlib {
		var cx []byte
		var err error
		if stream != nil {
			cx, err = stream.Compress(px)
		} else {
			cx, err = zlibCompressOnce(px)
		}
		if err == nil {
			out := make([]byte, 4+len(cx))
			binary.BigEndian.PutUint32(out[0:4], uint32(len(cx)))
			copy(out[4:], cx)
			return EncZlib, out
		}
		// fall through to Raw on error
	}
	return EncRaw, px
}

// zlibCompressOnce compresses src with a one-shot zlib writer. Kept for
// stateless callers; live clients must use ZlibStream so the connection shares
// one deflate context (RFC 6143 §7.7.5).
func zlibCompressOnce(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(src); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ZlibCompress is retained for backwards compatibility with older callers and
// tests. It compresses with a standalone stream (Close after each call) and is
// therefore NOT suitable for live VNC clients, which need the persistent
// ZlibStream. Prefer ZlibStream for new code.
func ZlibCompress(src []byte) ([]byte, error) {
	return zlibCompressOnce(src)
}

// Latin1ToUTF8 converts RFB Latin-1 (ISO 8859-1) bytes to a UTF-8 string.
func Latin1ToUTF8(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

// UTF8ToLatin1 encodes a UTF-8 string to Latin-1 bytes. Non-Latin-1 runes
// become '?'. (FUNC-1 in M2 replaces this with UTF-8 passthrough.)
func UTF8ToLatin1(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 256 {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return out
}
