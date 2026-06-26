package rfbcore

import (
	"hash/crc32"
	"image"
)

// EncCopyRect is the RFB CopyRect encoding type (RFC 6143 §7.6.3): the rect's
// pixels are copied from another position in the existing framebuffer, so only
// the 4-byte source coordinate is sent instead of pixel data.
const EncCopyRect int32 = 1

// CopyRect describes a rectangle in the new frame whose content is an exact copy
// of the (SrcX, SrcY)-origin region of the previous frame.
type CopyRect struct{ DstX, DstY, W, H, SrcX, SrcY int }

// DetectMoves partitions a set of dirty tiles into CopyRect moves and genuinely
// changed rects. For each dirty tile it hashes the tile's content in cur and
// looks it up in an index of prev's tiles; an exact content match at a different
// position is a move (the client already rendered that content at src, so we send
// a 4-byte CopyRect instead of pixels).
//
// Uniform (solid-colour) tiles are deliberately excluded from both the index and
// the move results: identical solid tiles collide everywhere — without this guard
// any background-to-background tile would register as a spurious "move". Solids
// compress to ~nothing under zlib, so reporting them as plain dirty rects is
// cheaper and avoids the false positives.
//
// dirty must be tile-aligned (as produced by DiffFrames); the returned realDirty
// is suitable for CoalesceRects.
func DetectMoves(prev, cur *image.RGBA, dirty []Rect) (moves []CopyRect, realDirty []Rect) {
	if prev == nil || cur == nil {
		return nil, dirty
	}
	// Nothing changed -> skip building the per-frame index (avoids scanning the
	// whole prev framebuffer every frame on a static screen).
	if len(dirty) == 0 {
		return nil, nil
	}

	// Index prev's non-uniform tiles by content hash -> first position.
	type cell struct{ x, y int }
	index := make(map[uint32]cell, 256)
	for ty := 0; ty < prev.Rect.Dy(); ty += DirtyTileSize {
		for tx := 0; tx < prev.Rect.Dx(); tx += DirtyTileSize {
			if uniform, _ := isUniformTile(prev, tx, ty); uniform {
				continue
			}
			h := hashTile(prev, tx, ty)
			if _, exists := index[h]; !exists {
				index[h] = cell{tx, ty}
			}
		}
	}

	for _, d := range dirty {
		if uniform, _ := isUniformTile(cur, d.X, d.Y); uniform {
			realDirty = append(realDirty, d)
			continue
		}
		src, ok := index[hashTile(cur, d.X, d.Y)]
		if ok && (src.x != d.X || src.y != d.Y) {
			moves = append(moves, CopyRect{DstX: d.X, DstY: d.Y, W: d.W, H: d.H, SrcX: src.x, SrcY: src.y})
		} else {
			realDirty = append(realDirty, d)
		}
	}
	return moves, realDirty
}

// hashTile returns a CRC32 over one tile's pixel bytes (top-down rows). Equal
// hashes imply equal tile content (collisions are astronomically unlikely).
func hashTile(img *image.RGBA, tx, ty int) uint32 {
	w := min(DirtyTileSize, img.Rect.Dx()-tx)
	h := min(DirtyTileSize, img.Rect.Dy()-ty)
	c := crc32.NewIEEE()
	for row := 0; row < h; row++ {
		off := (ty+row)*img.Stride + tx*4
		c.Write(img.Pix[off : off+w*4])
	}
	return c.Sum32()
}

// isUniformTile reports whether every pixel in the tile equals the first, and
// returns that solid colour. Used to skip trivial CopyRect sources/dests.
func isUniformTile(img *image.RGBA, tx, ty int) (uniform bool, solid [4]byte) {
	w := min(DirtyTileSize, img.Rect.Dx()-tx)
	h := min(DirtyTileSize, img.Rect.Dy()-ty)
	if w <= 0 || h <= 0 {
		return true, solid
	}
	o := ty*img.Stride + tx*4
	solid = [4]byte{img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3]}
	for row := 0; row < h; row++ {
		off := (ty+row)*img.Stride + tx*4
		for col := 0; col < w; col++ {
			p := off + col*4
			if img.Pix[p] != solid[0] || img.Pix[p+1] != solid[1] ||
				img.Pix[p+2] != solid[2] || img.Pix[p+3] != solid[3] {
				return false, solid
			}
		}
	}
	return true, solid
}
