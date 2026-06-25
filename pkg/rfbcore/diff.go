package rfbcore

import (
	"bytes"
	"image"
)

// Rect is a dirty rectangle in framebuffer coordinates.
type Rect struct{ X, Y, W, H int }

// DirtyTileSize is the granularity of per-tile change detection.
const DirtyTileSize = 32

// MaxDirtyRects caps dirty rects per frame; exceeding it collapses to a full
// update (returned as nil).
const MaxDirtyRects = 256

// DiffFrames compares two equally-sized RGBA frames tile-by-tile and returns
// the bounding rectangles of changed tiles. nil means "full update needed"
// (nil prev, size change, or too many changes).
//
// Comparison uses bytes.Equal per tile row — vet-clean (no unsafe.Pointer
// arithmetic, unlike the original pkg/vnc version) and fast (memequal).
func DiffFrames(prev, cur *image.RGBA) []Rect {
	if prev == nil || cur == nil {
		return nil
	}
	w, h := cur.Rect.Dx(), cur.Rect.Dy()
	if prev.Rect.Dx() != w || prev.Rect.Dy() != h || len(prev.Pix) != len(cur.Pix) {
		return nil
	}

	var rects []Rect
	for ty := 0; ty < h; ty += DirtyTileSize {
		tileH := DirtyTileSize
		if ty+tileH > h {
			tileH = h - ty
		}
		for tx := 0; tx < w; tx += DirtyTileSize {
			tileW := DirtyTileSize
			if tx+tileW > w {
				tileW = w - tx
			}
			rowBytes := tileW * 4
			dirty := false
			for row := 0; row < tileH; row++ {
				off := (ty+row)*cur.Stride + tx*4
				if !bytes.Equal(cur.Pix[off:off+rowBytes], prev.Pix[off:off+rowBytes]) {
					dirty = true
					break
				}
			}
			if dirty {
				rects = append(rects, Rect{X: tx, Y: ty, W: tileW, H: tileH})
				if len(rects) >= MaxDirtyRects {
					return nil
				}
			}
		}
	}
	return rects
}
