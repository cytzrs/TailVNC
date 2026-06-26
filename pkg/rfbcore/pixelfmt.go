package rfbcore

import "image"

// PixelFormat captures the client-negotiated pixel format used by the encoders.
type PixelFormat struct {
	Bpp                    uint8
	BigEndian              uint8
	RMax, GMax, BMax       uint16
	RShift, GShift, BShift uint8
}

// BytesPerPixel returns bytes-per-pixel with a minimum of 1.
func (pf PixelFormat) BytesPerPixel() int {
	b := int(pf.Bpp) / 8
	if b < 1 {
		b = 1
	}
	return b
}

// CanUseFastPath reports whether pf matches the canonical 32bpp RGB-255
// 16/8/0 layout closely enough for the bulk-copy fast path.
func CanUseFastPath(pf PixelFormat) bool {
	return pf.BytesPerPixel() == 4 &&
		pf.RMax == 255 && pf.GMax == 255 && pf.BMax == 255 &&
		pf.RShift == 16 && pf.GShift == 8 && pf.BShift == 0
}

// PixelFormat565 is the canonical 16bpp RGB-565 layout (5/6/5 bits, big-endian).
// A client that opts into 16bpp gets half the raw payload of 32bpp — useful for
// text/UI admin work where 565 is visually adequate.
var PixelFormat565 = PixelFormat{
	Bpp:       16,
	BigEndian: 1,
	RMax:      31,
	GMax:      63,
	BMax:      31,
	RShift:    11,
	GShift:    5,
	BShift:    0,
}

// CanUseFastPath565 reports whether pf is an RGB-565 layout (endian-agnostic;
// the encoder handles both byte orders).
func CanUseFastPath565(pf PixelFormat) bool {
	return pf.BytesPerPixel() == 2 &&
		pf.RMax == 31 && pf.GMax == 63 && pf.BMax == 31 &&
		pf.RShift == 11 && pf.GShift == 5 && pf.BShift == 0
}

// EncodePixelsFast copies a sub-rectangle row-by-row into out, swapping bytes
// per the client endianness. Caller must guarantee CanUseFastPath(pf) and that
// out has w*h*4 bytes.
func EncodePixelsFast(img *image.RGBA, x, y, w, h, stride int, bigEndian bool, out []byte) {
	rowBytes := w * 4
	for row := 0; row < h; row++ {
		src := img.Pix[(y+row)*stride+x*4 : (y+row)*stride+x*4+rowBytes]
		dst := out[row*rowBytes : (row+1)*rowBytes]
		if bigEndian {
			for i := 0; i < rowBytes; i += 4 {
				dst[i], dst[i+1], dst[i+2], dst[i+3] = 0, src[i], src[i+1], src[i+2]
			}
		} else {
			for i := 0; i < rowBytes; i += 4 {
				dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 0
			}
		}
	}
}

// EncodePixelsFast565 packs a sub-rectangle into RGB-565 (2 bytes/pixel) using
// the same linear R*Max/255 scaling as EncodePixelsGeneric, so the two are
// byte-identical for 565 (only the packing loop is tighter). Caller must
// guarantee CanUseFastPath565 and that out has w*h*2 bytes.
func EncodePixelsFast565(img *image.RGBA, x, y, w, h, stride int, bigEndian bool, out []byte) {
	off := 0
	for row := 0; row < h; row++ {
		base := (y+row)*stride + x*4
		for col := 0; col < w; col++ {
			p := base + col*4
			rv := uint32(img.Pix[p]) * 31 / 255
			gv := uint32(img.Pix[p+1]) * 63 / 255
			bv := uint32(img.Pix[p+2]) * 31 / 255
			pix := uint16((rv << 11) | (gv << 5) | bv)
			if bigEndian {
				out[off] = byte(pix >> 8)
				out[off+1] = byte(pix)
			} else {
				out[off] = byte(pix)
				out[off+1] = byte(pix >> 8)
			}
			off += 2
		}
	}
}

// EncodePixelsGeneric is the per-pixel fallback for non-canonical formats.
func EncodePixelsGeneric(img *image.RGBA, x, y, w, h, stride, bpp int, pf PixelFormat, out []byte) {
	off := 0
	for row := y; row < y+h; row++ {
		for col := x; col < x+w; col++ {
			p := row*stride + col*4
			r, g, b := img.Pix[p+0], img.Pix[p+1], img.Pix[p+2]
			rv := uint32(r) * uint32(pf.RMax) / 255
			gv := uint32(g) * uint32(pf.GMax) / 255
			bv := uint32(b) * uint32(pf.BMax) / 255
			pixel := (rv << pf.RShift) | (gv << pf.GShift) | (bv << pf.BShift)
			if pf.BigEndian != 0 {
				for i := 0; i < bpp; i++ {
					out[off+i] = byte(pixel >> uint((bpp-1-i)*8))
				}
			} else {
				for i := 0; i < bpp; i++ {
					out[off+i] = byte(pixel >> uint(i*8))
				}
			}
			off += bpp
		}
	}
}

// EncodeRectPixels encodes a sub-rectangle to wire bytes using pf. Returns the
// pixel payload (no rect header).
func EncodeRectPixels(img *image.RGBA, x, y, w, h, stride int, pf PixelFormat) []byte {
	bpp := pf.BytesPerPixel()
	out := make([]byte, w*h*bpp)
	switch {
	case bpp == 4 && CanUseFastPath(pf):
		EncodePixelsFast(img, x, y, w, h, stride, pf.BigEndian != 0, out)
	case bpp == 2 && CanUseFastPath565(pf):
		EncodePixelsFast565(img, x, y, w, h, stride, pf.BigEndian != 0, out)
	default:
		EncodePixelsGeneric(img, x, y, w, h, stride, bpp, pf, out)
	}
	return out
}
