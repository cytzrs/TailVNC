package rfbcore

import (
	"bytes"
	"compress/zlib"
	"image"
)

// RFB rectangle encodings used by this package.
const (
	EncRaw  int32 = 0
	EncZlib int32 = 6
)

// ZlibCompress compresses src with zlib. Returns an error on failure so the
// caller can react — the original pkg/vnc version swallowed the error and
// returned raw bytes, which the caller then mislabeled as encZlib (CORR-1).
func ZlibCompress(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(src); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeDirtyRect encodes one changed rectangle and returns the RFB encoding
// actually used plus the payload. CORR-1: on zlib failure it downgrades to
// EncRaw rather than emitting raw bytes under an EncZlib header (which would
// corrupt the client stream).
func EncodeDirtyRect(img *image.RGBA, r Rect, stride int, pf PixelFormat, useZlib bool) (encoding int32, payload []byte) {
	px := EncodeRectPixels(img, r.X, r.Y, r.W, r.H, stride, pf)
	if useZlib {
		if cx, err := ZlibCompress(px); err == nil {
			return EncZlib, cx
		}
		// fall through to Raw on error
	}
	return EncRaw, px
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
