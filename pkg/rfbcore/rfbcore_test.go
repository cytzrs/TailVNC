package rfbcore

import (
	"image"
	"image/color"
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

func TestDiffFrames(t *testing.T) {
	w, h := 64, 64
	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))

	// Identical frames -> no dirty rects.
	if got := DiffFrames(prev, cur); len(got) != 0 {
		t.Fatalf("identical frames: got %d rects, want 0", len(got))
	}

	// Change one pixel at (1,1) -> exactly one tile rect covers it.
	cur.Set(1, 1, color.RGBA{R: 255, A: 255})
	got := DiffFrames(prev, cur)
	if len(got) != 1 {
		t.Fatalf("single-pixel change: got %d rects, want 1", len(got))
	}
	r := got[0]
	if r.X != 0 || r.Y != 0 || r.W != DirtyTileSize || r.H != DirtyTileSize {
		t.Fatalf("tile rect = %+v, want {0 0 %d %d}", r, DirtyTileSize, DirtyTileSize)
	}

	// nil prev -> nil (signals full update to caller).
	if DiffFrames(nil, cur) != nil {
		t.Fatal("nil prev should return nil")
	}

	// Different size -> nil.
	big := image.NewRGBA(image.Rect(0, 0, 128, 128))
	if DiffFrames(prev, big) != nil {
		t.Fatal("size mismatch should return nil")
	}
}

func TestDiffFramesCollapseOnTooMany(t *testing.T) {
	// MaxDirtyRects+1 disjoint tiles dirty -> returns nil (caller issues full update).
	w := DirtyTileSize * (MaxDirtyRects + 1)
	h := DirtyTileSize
	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))
	for tx := 0; tx < w; tx += DirtyTileSize {
		cur.Set(tx, 0, color.RGBA{G: 255, A: 255})
	}
	if got := DiffFrames(prev, cur); got != nil {
		t.Fatalf("too many dirty tiles: got %d rects, want nil (full update)", len(got))
	}
}
