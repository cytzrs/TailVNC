package rfbcore

import (
	"bytes"
	"image"
)

// Rect is a dirty rectangle in framebuffer coordinates.
type Rect struct{ X, Y, W, H int }

// DirtyTileSize is the granularity of per-tile change detection.
const DirtyTileSize = 32

// MaxDirtyRects caps the dirty-tile count per frame; exceeding it signals a full
// update (DiffFrames returns full=true) so the caller delivers the whole frame
// instead of thousands of small rects — or worse, nothing at all.
const MaxDirtyRects = 256

// DiffFrames compares two equally-sized RGBA frames tile-by-tile and returns
// the bounding rectangles of changed tiles. It is three-state:
//
//	rects == nil && !full  -> no change (caller sends an empty update)
//	rects != nil && !full  -> dirty tiles (caller sends a dirty-rect update)
//	rects == nil && full   -> full update needed (caller sends the whole frame)
//
// "full" is returned for a nil prev (first frame), a size change (desktop
// transition), or more than MaxDirtyRects changed tiles. The full state is what
// keeps full-screen motion visible: previously "too many changes" was
// indistinguishable from "no change" and the client received empty updates
// until the screen appeared frozen.
//
// Comparison uses bytes.Equal per tile row — vet-clean (no unsafe.Pointer
// arithmetic, unlike the original pkg/vnc version) and fast (memequal).
func DiffFrames(prev, cur *image.RGBA) (rects []Rect, full bool) {
	if prev == nil || cur == nil {
		return nil, true
	}
	w, h := cur.Rect.Dx(), cur.Rect.Dy()
	if prev.Rect.Dx() != w || prev.Rect.Dy() != h || len(prev.Pix) != len(cur.Pix) {
		return nil, true
	}

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
				if len(rects) > MaxDirtyRects {
					return nil, true
				}
			}
		}
	}
	return rects, false
}

// CoalesceRects merges rects that overlap or share an edge when the union wastes
// no more than 2x the summed area. It cuts rect count (and the 12-byte header
// per rect) for coherent changes — e.g. a window scrolling through many tiles
// becomes a few large rects rather than hundreds. Rects that are far apart are
// left alone. Input may be empty; a fixed-point pass collapses chains of
// adjacent rects to their bounding box.
func CoalesceRects(in []Rect) []Rect {
	out := append([]Rect(nil), in...)
	merged := true
	for merged {
		merged = false
		for i := 0; i < len(out); i++ {
			for j := i + 1; j < len(out); j++ {
				u, ok := unionIfCheap(out[i], out[j])
				if !ok {
					continue
				}
				out[i] = u
				out = append(out[:j], out[j+1:]...)
				merged = true
				j--
			}
		}
	}
	return out
}

// unionIfCheap returns the union of a and b when they touch (overlap or share an
// edge) and the union area is at most twice their combined area — a waste guard
// so a stray rect never absorbs a distant neighbour.
func unionIfCheap(a, b Rect) (Rect, bool) {
	x0 := min(a.X, b.X)
	y0 := min(a.Y, b.Y)
	x1 := max(a.X+a.W, b.X+b.W)
	y1 := max(a.Y+a.H, b.Y+b.H)
	u := Rect{x0, y0, x1 - x0, y1 - y0}
	// Closed-interval AABB test (<=) treats a shared edge as touching.
	touches := a.X <= b.X+b.W && b.X <= a.X+a.W && a.Y <= b.Y+b.H && b.Y <= a.Y+a.H
	if !touches {
		return u, false
	}
	if int(u.W)*int(u.H) > 2*(int(a.W)*int(a.H)+int(b.W)*int(b.H)) {
		return u, false
	}
	return u, true
}
