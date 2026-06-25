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
