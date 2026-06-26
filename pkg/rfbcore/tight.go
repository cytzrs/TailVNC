package rfbcore

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"image/jpeg"
)

// EncTight is the RFB Tight encoding type (rfbproto.rst "Tight Encoding").
const EncTight int32 = 7

// Tight compression-control byte flags (rfbproto.rst). bits 0-3 are independent
// per-stream reset flags; bit 7 selects BasicCompression (0) vs Fill/JPEG (1).
const (
	tightResetStream0 = 0x01 // bit0: client resets zlib stream 0 before decoding
	tightFill         = 0x80 // bits7-4 = 1000: FillCompression
	tightJPEG         = 0x90 // bits7-4 = 1001: JpegCompression
)

// tightMaxWidth is the Tight protocol's hard limit; the caller must split any
// wider rectangle before encoding (EncodeTight returns an error otherwise).
const tightMaxWidth = 2048

// encodeCompactLen writes n in the Tight compact 1-3 byte length representation:
//
//	0xxxxxxx                 0..127
//	1xxxxxxx 0yyyyyyy        128..16383
//	1xxxxxxx 1yyyyyyy zzz... 16384..4194303
//
// with xxxxxxx = bits 0-6, yyyyyyy = bits 7-13, zzzzzzzz = bits 14-21.
func encodeCompactLen(n int) []byte {
	switch {
	case n <= 127:
		return []byte{byte(n)}
	case n <= 16383:
		return []byte{byte(n&0x7f) | 0x80, byte((n >> 7) & 0x7f)}
	default:
		return []byte{byte(n&0x7f) | 0x80, byte((n>>7)&0x7f) | 0x80, byte((n >> 14) & 0xff)}
	}
}

// decodeCompactLen is the inverse of encodeCompactLen (used in tests).
func decodeCompactLen(b []byte) (n int, used int) {
	if len(b) == 0 {
		return 0, 0
	}
	for i := 0; i < 3; i++ {
		if i >= len(b) {
			return 0, 0
		}
		c := b[i]
		if i < 2 {
			n |= int(c&0x7f) << uint(7*i)
			if c&0x80 == 0 {
				return n, i + 1
			}
		} else {
			n |= int(c) << 14
			return n, 3
		}
	}
	return n, 3
}

// tightUses3BytePixel reports whether the Tight TPIXEL is the 3-byte R,G,B form
// (true-colour, 32bpp, depth 24, 8-bit channels). The canonical server format
// matches this.
func tightUses3BytePixel(pf PixelFormat) bool {
	return pf.Bpp == 32 && pf.RMax == 255 && pf.GMax == 255 && pf.BMax == 255 &&
		pf.RShift == 16 && pf.GShift == 8 && pf.BShift == 0
}

// tightPixels emits a rectangle's pixels in TPIXEL format: 3 bytes (R,G,B) for
// the canonical 32bpp layout, otherwise the full PIXEL via EncodeRectPixels.
func tightPixels(img *image.RGBA, r Rect, stride int, pf PixelFormat) []byte {
	if tightUses3BytePixel(pf) {
		out := make([]byte, r.W*r.H*3)
		off := 0
		for row := 0; row < r.H; row++ {
			base := (r.Y+row)*stride + r.X*4
			for col := 0; col < r.W; col++ {
				p := base + col*4
				out[off] = img.Pix[p]
				out[off+1] = img.Pix[p+1]
				out[off+2] = img.Pix[p+2]
				off += 3
			}
		}
		return out
	}
	return EncodeRectPixels(img, r.X, r.Y, r.W, r.H, stride, pf)
}

// tightIsUniform reports whether every pixel in the rect equals the first.
func tightIsUniform(img *image.RGBA, r Rect, stride int) bool {
	o := r.Y*stride + r.X*4
	r0, r1, r2, r3 := img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3]
	for row := 0; row < r.H; row++ {
		base := (r.Y+row)*stride + r.X*4
		for col := 0; col < r.W; col++ {
			p := base + col*4
			if img.Pix[p] != r0 || img.Pix[p+1] != r1 || img.Pix[p+2] != r2 || img.Pix[p+3] != r3 {
				return false
			}
		}
	}
	return true
}

// EncodeTightFill emits a FillCompression rect (one TPIXEL fills the whole
// rectangle). Caller must guarantee r.W <= tightMaxWidth.
func EncodeTightFill(img *image.RGBA, r Rect, stride int, pf PixelFormat) []byte {
	pix := tightPixels(img, Rect{X: r.X, Y: r.Y, W: 1, H: 1}, stride, pf)
	out := make([]byte, 1+len(pix))
	out[0] = tightFill | tightResetStream0 // 0x81
	copy(out[1:], pix)
	return out
}

// EncodeTightBasic emits a BasicCompression (CopyFilter) Tight rect on zlib
// stream 0, reset before this rect (the encoder uses a fresh dictionary each
// call; the reset bit tells the client to do the same). Filtered data smaller
// than 12 bytes is sent uncompressed (no length prefix). Caller must guarantee
// r.W <= tightMaxWidth.
func EncodeTightBasic(img *image.RGBA, r Rect, stride int, pf PixelFormat, level int) ([]byte, error) {
	if level < 0 {
		level = 0
	}
	if level > 9 {
		level = 9
	}
	pix := tightPixels(img, r, stride, pf)
	if len(pix) < 12 {
		out := make([]byte, 1+len(pix))
		out[0] = tightResetStream0 // basic, stream0, CopyFilter, reset
		copy(out[1:], pix)
		return out, nil
	}
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(pix); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	cx := buf.Bytes()
	out := make([]byte, 1, 1+3+len(cx))
	out[0] = tightResetStream0
	out = append(out, encodeCompactLen(len(cx))...)
	out = append(out, cx...)
	return out, nil
}

// EncodeTightJPEG emits a JpegCompression Tight rect: a JFIF stream of the
// sub-rectangle at the given quality (1-100). Only valid when bits-per-pixel is
// 16 or 32 (caller must gate). Caller must guarantee r.W <= tightMaxWidth.
func EncodeTightJPEG(img *image.RGBA, r Rect, quality int) ([]byte, error) {
	if quality < 1 {
		quality = 1
	}
	if quality > 100 {
		quality = 100
	}
	sub := img.SubImage(image.Rect(r.X, r.Y, r.X+r.W, r.Y+r.H))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, sub, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	data := buf.Bytes()
	out := make([]byte, 1, 1+3+len(data))
	out[0] = tightJPEG // 0x90 (JpegCompression)
	out = append(out, encodeCompactLen(len(data))...)
	out = append(out, data...)
	return out, nil
}

// EncodeTight encodes one Tight rectangle and returns the full payload (including
// the compression-control byte; the 12-byte rect header is added by the caller).
// It picks Fill for solid rects, JPEG for photo regions when useJPEG is set and
// the pixel depth allows, otherwise BasicCompression (CopyFilter zlib).
func EncodeTight(img *image.RGBA, r Rect, stride int, pf PixelFormat, level int, useJPEG bool, jpegQuality int) ([]byte, error) {
	if r.W > tightMaxWidth {
		return nil, fmt.Errorf("rfbcore: tight width %d exceeds %d (caller must split)", r.W, tightMaxWidth)
	}
	if tightIsUniform(img, r, stride) {
		return EncodeTightFill(img, r, stride, pf), nil
	}
	if useJPEG && (pf.Bpp == 32 || pf.Bpp == 16) {
		return EncodeTightJPEG(img, r, jpegQuality)
	}
	return EncodeTightBasic(img, r, stride, pf, level)
}
