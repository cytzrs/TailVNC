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
	if bpp == 4 && CanUseFastPath(pf) {
		EncodePixelsFast(img, x, y, w, h, stride, pf.BigEndian != 0, out)
	} else {
		EncodePixelsGeneric(img, x, y, w, h, stride, bpp, pf, out)
	}
	return out
}
