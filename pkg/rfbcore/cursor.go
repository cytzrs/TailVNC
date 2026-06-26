package rfbcore

import (
	"encoding/binary"
	"image"
)

// EncCursor is the RFB Cursor pseudo-encoding (-239, RFC 6143 §7.7.5): the server
// ships the cursor's shape once and the client renders it locally, so subsequent
// mouse motion costs no bandwidth and tracks smoothly.
const EncCursor int32 = -239

// EncodeCursorPseudoRect builds a full Cursor pseudo-rectangle:
//
//   - a 12-byte rect header (x,y = cursor position; w,h = cursor size;
//     encoding = -239)
//   - the cursor pixels in pf (w*h, one per cell, in the negotiated format)
//   - a 1bpp visibility bitmask (1 byte per 8 pixels, MSB-first, each scanline
//     padded to a byte boundary; bit set = the pixel is opaque/visible)
//
// Visibility is derived from the source alpha: a pixel with alpha != 0 is shown.
//
// hotX/hotY (the hotspot offset within the cursor image) are accepted for API
// symmetry; the basic Cursor pseudo-encoding does not transmit them, so the
// caller should pass x,y as the screen position at which the image's hotspot
// should land.
func EncodeCursorPseudoRect(x, y, w, h, hotX, hotY int, pf PixelFormat, img *image.RGBA) []byte {
	pixels := EncodeRectPixels(img, 0, 0, w, h, img.Stride, pf)
	maskRowBytes := (w + 7) / 8
	mask := make([]byte, maskRowBytes*h)
	for row := 0; row < h; row++ {
		for col := 0; col < w; col++ {
			if img.Pix[row*img.Stride+col*4+3] != 0 { // alpha != 0 -> visible
				mask[row*maskRowBytes+col/8] |= 0x80 >> uint(col%8)
			}
		}
	}

	out := make([]byte, 12+len(pixels)+len(mask))
	binary.BigEndian.PutUint16(out[0:2], uint16(x))
	binary.BigEndian.PutUint16(out[2:4], uint16(y))
	binary.BigEndian.PutUint16(out[4:6], uint16(w))
	binary.BigEndian.PutUint16(out[6:8], uint16(h))
	// EncCursor is negative (-239); route through a variable so the int32->uint32
	// conversion is a runtime two's-complement cast (0xFFFFFF11), not a constant
	// conversion (which would overflow).
	encCode := EncCursor
	binary.BigEndian.PutUint32(out[8:12], uint32(encCode))
	copy(out[12:], pixels)
	copy(out[12+len(pixels):], mask)
	return out
}
