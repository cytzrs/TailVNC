package rfbcore

import (
	"bytes"
	"compress/zlib"
	"image"
	"image/color"
	"io"
	"testing"
)

func TestReverseBits(t *testing.T) {
	cases := []struct{ in, want byte }{
		{0x00, 0x00},
		{0xff, 0xff},
		{0x80, 0x01}, // 10000000 -> 00000001
		{0x12, 0x48}, // 00010010 -> 01001000
		{0xe1, 0x87}, // 11100001 -> 10000111
	}
	for _, c := range cases {
		if got := ReverseBits(c.in); got != c.want {
			t.Errorf("ReverseBits(0x%02x) = 0x%02x, want 0x%02x", c.in, got, c.want)
		}
	}
}

func TestVncAuthEncrypt(t *testing.T) {
	// password "secret" over a zero challenge: first and second 8-byte halves
	// are identical because both challenge halves are zero.
	challenge := make([]byte, 16)
	got, err := VncAuthEncrypt(challenge, "secret")
	if err != nil {
		t.Fatalf("VncAuthEncrypt: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("len = %d, want 16", len(got))
	}
	wantHalf := got[:8]
	for i := 0; i < 8; i++ {
		if got[8+i] != wantHalf[i] {
			t.Fatalf("second half byte %d = 0x%02x, want 0x%02x (challenge halves both zero)", i, got[8+i], wantHalf[i])
		}
	}
	// Empty password -> all-zero key -> still 16 bytes of deterministic ciphertext.
	if empty, _ := VncAuthEncrypt(challenge, ""); len(empty) != 16 {
		t.Fatalf("empty password: len = %d, want 16", len(empty))
	}
}

func TestVncAuthEncryptErrors(t *testing.T) {
	// QUAL-4: validate input rather than silently misbehaving.
	if _, err := VncAuthEncrypt(make([]byte, 15), "x"); err == nil {
		t.Fatal("expected error for 15-byte challenge, got nil")
	}
}

func TestDiffFramesThreeStates(t *testing.T) {
	// DiffFrames is three-state: (nil,false)=no change, ([...],false)=dirty,
	// (nil,true)=full update needed. The full state is what un-freezes full-screen
	// motion (previously indistinguishable from "no change" -> empty update -> freeze).
	w, h := 64, 64
	prev := image.NewRGBA(image.Rect(0, 0, w, h))

	// (nil, false): identical frames = no change.
	cur := image.NewRGBA(prev.Rect)
	if rects, full := DiffFrames(prev, cur); full || len(rects) != 0 {
		t.Fatalf("identical: rects=%v full=%v, want empty/not-full", rects, full)
	}

	// ([...], false): one pixel changed = one dirty tile, geometry aligned to the grid.
	cur.Set(1, 1, color.RGBA{R: 255, A: 255})
	rects, full := DiffFrames(prev, cur)
	if full || len(rects) != 1 {
		t.Fatalf("one tile: rects=%v full=%v, want 1 dirty / not-full", rects, full)
	}
	if got := rects[0]; got != (Rect{0, 0, DirtyTileSize, DirtyTileSize}) {
		t.Fatalf("tile rect = %+v, want {0 0 %d %d}", got, DirtyTileSize, DirtyTileSize)
	}

	// (nil, true): nil prev = full update (NOT "no change").
	if rects, full := DiffFrames(nil, cur); !full || rects != nil {
		t.Fatalf("nil prev: rects=%v full=%v, want nil/full", rects, full)
	}

	// (nil, true): size mismatch = full update.
	big := image.NewRGBA(image.Rect(0, 0, 128, 128))
	if rects, full := DiffFrames(prev, big); !full || rects != nil {
		t.Fatalf("size mismatch: rects=%v full=%v, want nil/full", rects, full)
	}
}

func TestDiffFramesCollapseOnTooMany(t *testing.T) {
	// More than MaxDirtyRects disjoint tiles dirty -> (nil, true): caller must issue
	// a FULL update (delivers content), not an empty one (which froze the screen).
	bigW := DirtyTileSize * (MaxDirtyRects + 1)
	prev := image.NewRGBA(image.Rect(0, 0, bigW, DirtyTileSize))
	cur := image.NewRGBA(prev.Rect)
	for tx := 0; tx < bigW; tx += DirtyTileSize {
		cur.Set(tx, 0, color.RGBA{G: 255, A: 255})
	}
	rects, full := DiffFrames(prev, cur)
	if !full || rects != nil {
		t.Fatalf("too many dirty tiles: rects=%v full=%v, want nil/full", rects, full)
	}

	// Exactly MaxDirtyRects dirty tiles stays under the cap -> dirty, not full.
	capPrev := image.NewRGBA(image.Rect(0, 0, DirtyTileSize*MaxDirtyRects, DirtyTileSize))
	capCur := image.NewRGBA(capPrev.Rect)
	for tx := 0; tx < capCur.Rect.Dx(); tx += DirtyTileSize {
		capCur.Set(tx, 0, color.RGBA{G: 255, A: 255})
	}
	rects, full = DiffFrames(capPrev, capCur)
	if full || rects == nil || len(rects) != MaxDirtyRects {
		t.Fatalf("at-cap: rects=%d full=%v, want %d dirty / not-full", len(rects), full, MaxDirtyRects)
	}
}

func TestCoalesceRects(t *testing.T) {
	// Two horizontally-adjacent 32x32 tiles merge into one 64x32 rect.
	got := CoalesceRects([]Rect{{0, 0, 32, 32}, {32, 0, 32, 32}})
	if len(got) != 1 || got[0] != (Rect{0, 0, 64, 32}) {
		t.Fatalf("adjacent merge: got %+v, want [{0 0 64 32}]", got)
	}
	// Two vertically-adjacent tiles merge into one 32x64 rect.
	got = CoalesceRects([]Rect{{0, 0, 32, 32}, {0, 32, 32, 32}})
	if len(got) != 1 || got[0] != (Rect{0, 0, 32, 64}) {
		t.Fatalf("vertical merge: got %+v, want [{0 0 32 64}]", got)
	}
	// Two far-apart rects do NOT merge (waste guard).
	far := CoalesceRects([]Rect{{0, 0, 32, 32}, {1000, 1000, 32, 32}})
	if len(far) != 2 {
		t.Fatalf("far apart: got %d rects, want 2", len(far))
	}
	// Empty input -> empty output, no panic.
	if got := CoalesceRects(nil); len(got) != 0 {
		t.Fatalf("nil input: got %+v, want empty", got)
	}
	// A chain of adjacent tiles collapses to its bounding box.
	chain := CoalesceRects([]Rect{{0, 0, 32, 32}, {32, 0, 32, 32}, {64, 0, 32, 32}})
	if len(chain) != 1 || chain[0] != (Rect{0, 0, 96, 32}) {
		t.Fatalf("chain merge: got %+v, want [{0 0 96 32}]", chain)
	}
}

func TestDetectMovesTranslatedBlock(t *testing.T) {
	// 128x32 frame (4 tiles). prev has a non-uniform gradient block at tile
	// (0,0); cur has the SAME gradient at tile (64,0). Tile (0,0) is now solid
	// background. DiffFrames reports both (0,0) and (64,0) dirty.
	w, h := 128, 32
	paint := func(img *image.RGBA, ox int) {
		for x := 0; x < 32; x++ {
			for y := 0; y < 32; y++ {
				img.Set(ox+x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 50, A: 255})
			}
		}
	}
	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	paint(prev, 0)
	cur := image.NewRGBA(prev.Rect)
	paint(cur, 64)

	dirty, _ := DiffFrames(prev, cur) // tiles (0,0) [gradient gone] and (64,0) [gradient appeared]
	moves, realDirty := DetectMoves(prev, cur, dirty)

	if len(moves) != 1 {
		t.Fatalf("moves=%+v, want exactly 1 (gradient moved 0,0 -> 64,0)", moves)
	}
	m := moves[0]
	if m.SrcX != 0 || m.SrcY != 0 || m.DstX != 64 || m.DstY != 0 || m.W != 32 || m.H != 32 {
		t.Fatalf("move=%+v, want Src(0,0)->Dst(64,0) 32x32", m)
	}
	// The vacated source tile (0,0) is now solid background -> reported as
	// realDirty (NOT a spurious background "move").
	if len(realDirty) != 1 || realDirty[0] != (Rect{0, 0, 32, 32}) {
		t.Fatalf("realDirty=%+v, want [{0 0 32 32}] (vacated source)", realDirty)
	}
}

func TestDetectMovesNoMatchIsAllDirty(t *testing.T) {
	// A genuinely new non-uniform tile with no identical prev tile -> all dirty.
	prev := image.NewRGBA(image.Rect(0, 0, 64, 32))
	cur := image.NewRGBA(prev.Rect)
	for x := 0; x < 32; x++ {
		cur.Set(x, 0, color.RGBA{R: uint8(x + 1), A: 255})
	}
	dirty, _ := DiffFrames(prev, cur)
	moves, realDirty := DetectMoves(prev, cur, dirty)
	if len(moves) != 0 || len(realDirty) != 1 {
		t.Fatalf("no-match: moves=%d realDirty=%d, want 0/1", len(moves), len(realDirty))
	}
}

func TestDetectMovesNilFrames(t *testing.T) {
	// Nil prev/cur -> no moves, dirty returned unchanged.
	dirty := []Rect{{0, 0, 32, 32}}
	if moves, realDirty := DetectMoves(nil, nil, dirty); len(moves) != 0 || len(realDirty) != 1 {
		t.Fatalf("nil frames: moves=%d realDirty=%d, want 0/1", len(moves), len(realDirty))
	}
}

func TestPixelFormatBytesPerPixel(t *testing.T) {
	cases := []struct {
		bpp  uint8
		want int
	}{
		{32, 4},
		{16, 2},
		{8, 1},
		{0, 1}, // guarded: minimum 1
	}
	for _, c := range cases {
		pf := PixelFormat{Bpp: c.bpp}
		if got := pf.BytesPerPixel(); got != c.want {
			t.Errorf("bpp=%d: BytesPerPixel=%d, want %d", c.bpp, got, c.want)
		}
	}
}

func TestCanUseFastPath(t *testing.T) {
	canonical := PixelFormat{Bpp: 32, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}
	if !CanUseFastPath(canonical) {
		t.Fatal("canonical 32bpp RGB-255 16/8/0 should use fast path")
	}
	if CanUseFastPath(PixelFormat{Bpp: 16, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}) {
		t.Fatal("16bpp must not use fast path")
	}
}

func TestEncodeRectPixelsFastPathLittleEndian(t *testing.T) {
	// 2x1 image: pixel (0,0)=red, (1,0)=green. Canonical 32bpp, little-endian.
	img := image.NewRGBA(image.Rect(0, 0, 2, 1))
	img.Set(0, 0, color.RGBA{R: 0xff, A: 0xff})
	img.Set(1, 0, color.RGBA{G: 0xff, A: 0xff})
	pf := PixelFormat{Bpp: 32, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}
	out := EncodeRectPixels(img, 0, 0, 2, 1, img.Stride, pf)
	if len(out) != 8 {
		t.Fatalf("len=%d, want 8", len(out))
	}
	// Little-endian word {B,G,R,0}: red pixel -> {0,0,255,0}; green -> {0,255,0,0}.
	want := []byte{0, 0, 255, 0, 0, 255, 0, 0}
	if !bytes.Equal(out, want) {
		t.Fatalf("out=%v, want %v", out, want)
	}
}

func TestZlibCompressRoundTrip(t *testing.T) {
	src := bytes.Repeat([]byte{0xaa, 0x55, 0x00, 0xff}, 1000)
	cx, err := ZlibCompress(src)
	if err != nil {
		t.Fatalf("ZlibCompress: %v", err)
	}
	if len(cx) >= len(src) {
		t.Logf("warning: compressed (%d) not smaller than src (%d)", len(cx), len(src))
	}
	zr, err := zlib.NewReader(bytes.NewReader(cx))
	if err != nil {
		t.Fatalf("zlib.NewReader: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatal("round-trip mismatch")
	}
}

func TestEncodeDirtyRectRawAndZlib(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	pf := PixelFormat{Bpp: 32, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}
	r := Rect{X: 0, Y: 0, W: 4, H: 4}

	enc, payload := EncodeDirtyRect(img, r, img.Stride, pf, false)
	if enc != EncRaw {
		t.Fatalf("useZlib=false: enc=%d, want EncRaw(%d)", enc, EncRaw)
	}
	if len(payload) != 4*4*4 {
		t.Fatalf("raw payload len=%d, want 64", len(payload))
	}

	enc2, payload2 := EncodeDirtyRect(img, r, img.Stride, pf, true)
	if enc2 != EncZlib {
		t.Fatalf("useZlib=true: enc=%d, want EncZlib(%d)", enc2, EncZlib)
	}
	// CORR-1 contract: an encZlib payload must decompress to the raw pixels.
	zr, _ := zlib.NewReader(bytes.NewReader(payload2))
	defer zr.Close()
	round, _ := io.ReadAll(zr)
	if !bytes.Equal(round, payload) {
		t.Fatal("CORR-1: encZlib payload must decompress to the raw pixels")
	}
}

func TestLatin1RoundTrip(t *testing.T) {
	// ASCII round-trips losslessly.
	got := Latin1ToUTF8([]byte{'A', 'Z', 0xc3}) // 0xc3 = Ã
	if got != "AZÃ" {
		t.Fatalf("Latin1ToUTF8 = %q", got)
	}
	// Non-Latin-1 runes become '?' (FUNC-1 fixes this in M2; M1 preserves behavior).
	out := UTF8ToLatin1("héllo→x")
	if !bytes.Contains(out, []byte{'?'}) {
		t.Fatalf("expected '?' substitution for non-Latin-1, got %v", out)
	}
}

func TestEncodePixelsFastPathBigEndian(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 0xff, A: 0xff}) // red
	pf := PixelFormat{Bpp: 32, BigEndian: 1, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}
	out := EncodeRectPixels(img, 0, 0, 1, 1, img.Stride, pf)
	// Big-endian word MSB->LSB {0,R,G,B}: red -> {0,255,0,0}.
	want := []byte{0, 255, 0, 0}
	if !bytes.Equal(out, want) {
		t.Fatalf("big-endian out=%v, want %v", out, want)
	}
}

func TestEncodePixelsGeneric8bpp(t *testing.T) {
	// 8bpp non-canonical -> generic path. Maxes 255, shifts 0/0/0 pack to a luminance-ish byte.
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 0xff, G: 0x80, B: 0x40, A: 0xff})
	pf := PixelFormat{Bpp: 8, RMax: 255, GMax: 255, BMax: 255, RShift: 0, GShift: 0, BShift: 0}
	out := EncodeRectPixels(img, 0, 0, 1, 1, img.Stride, pf)
	if len(out) != 1 {
		t.Fatalf("8bpp len=%d, want 1", len(out))
	}
	// All channels shifted by 0 and OR'd together with max 255: each channel
	// is scaled by 255/255 = identity, then OR'd: 0xff|0x80|0x40 = 0xff.
	if out[0] != 0xff {
		t.Fatalf("8bpp out=0x%02x, want 0xff", out[0])
	}
}
