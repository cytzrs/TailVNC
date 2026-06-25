# TailVNC M1 — Security Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TailVNC testable and close the highest-severity security/correctness gaps (TEST-1, SEC-1..6, CORR-1..3) so the binary is no longer trivially exploitable and its pure logic is covered by tests.

**Architecture:** Extract all pure RFB/protocol logic into a new `pkg/rfbcore` package (build-tag-free, testable on Linux). Build-tag the entire Windows-specific `pkg/vnc` + `cmd/vnc` as `//go:build windows`. Rewire the Windows session to delegate encode/auth/diff to `rfbcore`. Then fix three correctness bugs (zlib downgrade, per-session input state, dirty-read race) and harden six security issues (auth/bind, IPC auth, exePath LPE, parser bounds, secret config source, obfuscation honesty).

**Tech Stack:** Go 1.25+, `crypto/des`, `compress/zlib`, `golang.org/x/sys/windows`, Tailscale `tsnet`. Tests: stdlib `testing`, table-driven.

## Global Constraints

Copied verbatim from the spec (`docs/superpowers/specs/2026-06-25-tailvnc-full-remediation-design.md`):

- **Two verification tiers (critical):** This dev box is Linux; the codebase is Windows-only.
  - **Tier A (Linux, full TDD):** pure-logic tasks target `pkg/rfbcore` (and `pkg/deobfuscator`, `pkg/utils`, `obfuscator`). Command: `GOOS=linux go test ./pkg/rfbcore/... ./pkg/deobfuscator/... ./pkg/utils/...`. Must pass.
  - **Tier B (Windows, build + manual verify):** anything touching `pkg/vnc` or `cmd/vnc`. Commands: `GOOS=windows GOARCH=amd64 go vet ./...` and `GOOS=windows GOARCH=amd64 go build ./...`. Both must pass with zero errors. Runtime behavior verified on a Windows VM.
- **Go version:** `go 1.25.3` (from `go.mod`). Do not bump.
- **Build flags preserved:** `-s -w` stripping and existing LDFLAGS injection stay unchanged unless a task says otherwise.
- **Commits:** conventional `<type>: <desc>` (feat/fix/test/refactor/docs/chore). No attribution. Commit after every task. Branch: `feature-dev`.
- **Immutability / error handling:** new code returns errors explicitly (no swallowed `_ =`); fix existing swallowed errors where touched.
- **Positioning:** legitimate remote ops tool. No stealth/anti-detection work in M1.

---

## File Structure

New package `pkg/rfbcore` (pure, Linux-testable):
- `pkg/rfbcore/auth.go` — `ReverseBits`, `VncAuthEncrypt` (was `rfb.go:260,275`; fixes QUAL-4)
- `pkg/rfbcore/diff.go` — `Rect`, `DiffFrames`, tile constants (was `screen.go:216,236`; vet-clean rewrite fixes QUAL-1 for this fn)
- `pkg/rfbcore/pixelfmt.go` — `PixelFormat`, `CanUseFastPath`, `EncodePixelsFast`, `EncodePixelsGeneric`, `EncodeRectPixels` (was `rfb.go:580,590,624,651`)
- `pkg/rfbcore/codec.go` — `ZlibCompress` (returns error), `EncodeDirtyRect` (CORR-1 downgrade), latin-1 helpers (was `rfb.go:638`, `clipboard.go:168,177`)
- `pkg/rfbcore/rfbcore_test.go` — table-driven tests for all of the above

Modified (Windows, build-tagged):
- `pkg/vnc/*.go` — every file gets `//go:build windows`; `session` delegates encode/auth to `rfbcore`; `rfb.go` encode/auth method bodies removed.
- `pkg/vnc/screen.go` — `SessionAwareCapturer` uses `rfbcore.DiffFrames`; CORR-3 race fix at `:450`.
- `pkg/vnc/input.go` — CORR-2: move `prevButtonMask`/`sasCtrlDown`/`sasAltDown` onto `session`.
- `pkg/vnc/server.go` — SEC-1 default bind + auth backoff; SEC-2 IPC token plumbing.
- `pkg/vnc/agent.go` — SEC-2 token on listener; SEC-4 exePath ACL check.
- `pkg/vnc/rfb.go` — SEC-5 parser bounds; CORR-1 already in rfbcore.
- `cmd/vnc/main.go` — `//go:build windows`; SEC-6 secret config source.
- `obfuscator/obfuscate_key_hex.go` + `pkg/deobfuscator/deobfuscate_key_hex.go` — SEC-3/QUAL-2 shared key constant; SEC-6 read key from env.
- `Makefile` — SEC-6: pass `AUTH_KEY` via env, not argv.
- `README.md` — SEC-3: fix XOR/AES contradiction.

Each task below is self-contained: its implementer sees only that task, so **Interfaces** blocks spell out exact signatures neighbors rely on.

---

## Task 1: Scaffold `pkg/rfbcore` + extract auth (reverseBits, VncAuthEncrypt)

**Files:**
- Create: `pkg/rfbcore/auth.go`
- Create: `pkg/rfbcore/rfbcore_test.go`
- (No modification to `pkg/vnc` yet — that happens in Task 5.)

**Interfaces:**
- Produces: `rfbcore.ReverseBits(b byte) byte`, `rfbcore.VncAuthEncrypt(challenge []byte, password string) ([]byte, error)`.

- [ ] **Step 1: Write the failing test**

Create `pkg/rfbcore/rfbcore_test.go`:

```go
package rfbcore

import "testing"

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
	// Known vector: password "secret" over a zero challenge.
	// The RFB key is the password bytes bit-reversed, zero-padded to 8.
	// expected is 16 bytes of single-DES(zeroChallenge) twice.
	challenge := make([]byte, 16)
	got, err := VncAuthEncrypt(challenge, "secret")
	if err != nil {
		t.Fatalf("VncAuthEncrypt: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("len = %d, want 16", len(got))
	}
	// First and second 8-byte halves are identical because both challenge halves are zero.
	wantHalf := got[:8]
	for i := 0; i < 8; i++ {
		if got[8+i] != wantHalf[i] {
			t.Fatalf("second half byte %d = 0x%02x, want 0x%02x (challenge halves both zero)", i, got[8+i], wantHalf[i])
		}
	}
	// Empty password -> all-zero key -> deterministic non-zero ciphertext.
	if empty, _ := VncAuthEncrypt(challenge, ""); len(empty) != 16 {
		t.Fatalf("empty password: len = %d, want 16", len(empty))
	}
}

func TestVncAuthEncryptErrors(t *testing.T) {
	// QUAL-4: des.NewCipher error path is unreachable for 8-byte keys, but the
	// function must still validate its input rather than silently misbehave.
	if _, err := VncAuthEncrypt(make([]byte, 15), "x"); err == nil {
		t.Fatal("expected error for 15-byte challenge, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: FAIL / build error — `ReverseBits` and `VncAuthEncrypt` undefined (package doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `pkg/rfbcore/auth.go`:

```go
// Package rfbcore contains the build-tag-free RFB protocol logic (auth,
// pixel encoding, dirty-rect diffing). It imports only the standard library
// so it can be unit-tested on any platform; the Windows-specific pkg/vnc
// layer delegates to it.
package rfbcore

import (
	"crypto/des"
	"fmt"
)

// ReverseBits returns b with its bit order reversed. RFB VNC authentication
// bit-reverses each password byte before using it as a DES key.
func ReverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// VncAuthEncrypt computes the RFB VNC-Authentication response for a 16-byte
// challenge: the password (truncated/padded to 8 bytes, each byte bit-reversed)
// is used as a DES key to encrypt the challenge in two 8-byte blocks.
// Returns an error if the challenge is not exactly 16 bytes or DES init fails
// (fixes the swallowed des.NewCipher error in the original pkg/vnc code).
func VncAuthEncrypt(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("rfbcore: challenge must be 16 bytes, got %d", len(challenge))
	}
	key := make([]byte, 8)
	for i, c := range []byte(password) {
		if i >= 8 {
			break
		}
		key[i] = ReverseBits(c)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rfbcore: des.NewCipher: %w", err)
	}
	out := make([]byte, 16)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/rfbcore/auth.go pkg/rfbcore/rfbcore_test.go
git commit -m "feat(rfbcore): extract VNC auth (ReverseBits, VncAuthEncrypt) with tests"
```

---

## Task 2: Extract Rect + DiffFrames (vet-clean)

**Files:**
- Create: `pkg/rfbcore/diff.go`
- Modify: `pkg/rfbcore/rfbcore_test.go` (append tests)

**Interfaces:**
- Produces: `rfbcore.Rect{X,Y,W,H int}`, `rfbcore.DiffFrames(prev, cur *image.RGBA) []Rect`, `rfbcore.DirtyTileSize`, `rfbcore.MaxDirtyRects`.
- Consumes: none.

- [ ] **Step 1: Write the failing test**

Append to `pkg/rfbcore/rfbcore_test.go`:

```go
func TestDiffFrames(t *testing.T) {
	mk := func(pixels []byte, w, h int) *image.RGBA {
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		copy(img.Pix, pixels)
		return img
	}
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
```

(Add `"image"` and `"image/color"` to the test file's imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: FAIL — `Rect`, `DiffFrames`, `DirtyTileSize`, `MaxDirtyRects` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/rfbcore/diff.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/rfbcore/diff.go pkg/rfbcore/rfbcore_test.go
git commit -m "feat(rfbcore): extract Rect + DiffFrames (vet-clean) with tests"
```

---

## Task 3: Extract pixel-format encoders

**Files:**
- Create: `pkg/rfbcore/pixelfmt.go`
- Modify: `pkg/rfbcore/rfbcore_test.go` (append tests)

**Interfaces:**
- Produces: `rfbcore.PixelFormat` struct, `(PixelFormat).BytesPerPixel() int`, `rfbcore.CanUseFastPath(pf PixelFormat) bool`, `rfbcore.EncodePixelsFast(img, x, y, w, h, stride int, bigEndian bool, out []byte)`, `rfbcore.EncodePixelsGeneric(img, x, y, w, h, stride, bpp int, pf PixelFormat, out []byte)`, `rfbcore.EncodeRectPixels(img, x, y, w, h, stride int, pf PixelFormat) []byte`.
- Consumes: none.

- [ ] **Step 1: Write the failing test**

Append to `pkg/rfbcore/rfbcore_test.go`:

```go
func TestPixelFormatBytesPerPixel(t *testing.T) {
	cases := []struct {
		bpp   uint8
		want  int
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
```

(Add `"bytes"` to test imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: FAIL — `PixelFormat`, `CanUseFastPath`, `EncodeRectPixels` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/rfbcore/pixelfmt.go`:

```go
package rfbcore

import "image"

// PixelFormat captures the client-negotiated pixel format used by the encoders.
type PixelFormat struct {
	Bpp                  uint8
	BigEndian            uint8
	RMax, GMax, BMax     uint16
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/rfbcore/pixelfmt.go pkg/rfbcore/rfbcore_test.go
git commit -m "feat(rfbcore): extract pixel-format encoders with tests"
```

---

## Task 4: Extract codec (ZlibCompress, EncodeDirtyRect, latin-1)

**Files:**
- Create: `pkg/rfbcore/codec.go`
- Modify: `pkg/rfbcore/rfbcore_test.go` (append tests)

**Interfaces:**
- Produces: encoding constants `rfbcore.EncRaw`, `rfbcore.EncZlib`; `rfbcore.ZlibCompress(src []byte) ([]byte, error)`; `rfbcore.EncodeDirtyRect(img, r Rect, stride int, pf PixelFormat, useZlib bool) (encoding int32, payload []byte)`; `rfbcore.Latin1ToUTF8(b []byte) string`; `rfbcore.UTF8ToLatin1(s string) []byte`.
- Consumes: `EncodeRectPixels`, `PixelFormat`, `Rect` (Task 3, Task 2).

- [ ] **Step 1: Write the failing test**

Append to `pkg/rfbcore/rfbcore_test.go`:

```go
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
```

(Add `"compress/zlib"`, `"io"` to test imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: FAIL — `ZlibCompress`, `EncodeDirtyRect`, `Latin1ToUTF8`, `UTF8ToLatin1`, `EncRaw`, `EncZlib` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/rfbcore/codec.go`:

```go
package rfbcore

import (
	"bytes"
	"compress/zlib"
	"image"
)

// RFB rectangle encodings used by this package.
const (
	EncRaw  int32 = 0
	EncZlib int32 = 6
)

// ZlibCompress compresses src with zlib. Returns an error on failure so the
// caller can react — the original pkg/vnc version swallowed the error and
// returned raw bytes, which the caller then mislabeled as encZlib (CORR-1).
func ZlibCompress(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(src); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeDirtyRect encodes one changed rectangle and returns the RFB encoding
// actually used plus the payload. CORR-1: on zlib failure it downgrades to
// EncRaw rather than emitting raw bytes under an EncZlib header (which would
// corrupt the client stream).
func EncodeDirtyRect(img *image.RGBA, r Rect, stride int, pf PixelFormat, useZlib bool) (encoding int32, payload []byte) {
	px := EncodeRectPixels(img, r.X, r.Y, r.W, r.H, stride, pf)
	if useZlib {
		if cx, err := ZlibCompress(px); err == nil {
			return EncZlib, cx
		}
		// fall through to Raw on error
	}
	return EncRaw, px
}

// Latin1ToUTF8 converts RFB Latin-1 (ISO 8859-1) bytes to a UTF-8 string.
func Latin1ToUTF8(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

// UTF8ToLatin1 encodes a UTF-8 string to Latin-1 bytes. Non-Latin-1 runes
// become '?'. (FUNC-1 in M2 replaces this with UTF-8 passthrough.)
func UTF8ToLatin1(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 256 {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/rfbcore/codec.go pkg/rfbcore/rfbcore_test.go
git commit -m "feat(rfbcore): extract codec (ZlibCompress, EncodeDirtyRect, latin1) with CORR-1 downgrade"
```

---

## Task 5: Build-tag Windows code + rewire `pkg/vnc` to delegate to `rfbcore`

**Files:**
- Modify: every file in `pkg/vnc/` and `cmd/vnc/main.go` — add `//go:build windows` header.
- Modify: `pkg/vnc/rfb.go` — remove `reverseBits`, `vncAuthEncrypt`, `encodePixelsFast`, `encodePixelsGeneric`, `canUseFastPath`, `encodeRectPixels`, `zlibCompress`; rewrite call sites to use `rfbcore.*`.
- Modify: `pkg/vnc/screen.go` — remove `Rect`, `diffFrames`; call `rfbcore.DiffFrames`; keep `dirtyTileSize`/`maxDirtyRects` references as `rfbcore.DirtyTileSize`/`rfbcore.MaxDirtyRects`.
- Modify: `pkg/vnc/clipboard.go` — remove `latin1ToUTF8`, `utf8ToLatin1`; call `rfbcore.*`.

**Interfaces:**
- Consumes: all of `pkg/rfbcore` (Tasks 1-4).
- Produces: a Windows package whose pure logic lives in `rfbcore`; `GOOS=linux go test ./pkg/rfbcore/...` still green; `GOOS=windows go vet ./...` clean.

This task has no new test (it is a mechanical relocation verified by the build matrix). Do it in small sub-steps with a build check after each.

- [ ] **Step 1: Add build tags to every Windows file**

Add as the **first line** (before the package clause) of each: `pkg/vnc/screen.go`, `pkg/vnc/agent.go`, `pkg/vnc/clipboard.go`, `pkg/vnc/server.go`, `pkg/vnc/input.go`, `pkg/vnc/ipc.go`, `pkg/vnc/rfb.go`, and `cmd/vnc/main.go`:

```go
//go:build windows
```

(Leave a blank line between the build tag and the `package` line.)

- [ ] **Step 2: Replace pure functions in `pkg/vnc/rfb.go` with `rfbcore` calls**

In `pkg/vnc/rfb.go`:
- Delete `reverseBits`, `vncAuthEncrypt`, `canUseFastPath`, `encodePixelsFast`, `encodePixelsGeneric`, `encodeRectPixels`, `zlibCompress`.
- Add import `"tailvnc/pkg/rfbcore"`.
- In `doVNCAuth`, replace the `expected := vncAuthEncrypt(challenge, s.password)` line and the comparison:

```go
expected, err := rfbcore.VncAuthEncrypt(challenge, s.password)
if err != nil {
    return fmt.Errorf("vnc auth: %w", err)
}
if !bytes.Equal(expected, response) {
    result = 1
}
```

- In `initClientPixelFormat` and `handleSetPixelFormat`, populate a `s.pf rfbcore.PixelFormat` field (add `pf rfbcore.PixelFormat` to the `session` struct) instead of the individual `clientBpp`/`clientRMax`/... fields. Replace every read of those fields with `s.pf.*`. Specifically:
  - `bytesPerPixel := int(s.clientBpp) / 8` → `s.pf.BytesPerPixel()`.
  - `canUseFastPath(bytesPerPixel)` → `rfbcore.CanUseFastPath(s.pf)`.
  - `s.clientBigEndian != 0` → `s.pf.BigEndian != 0`.
  - In `sendDirtyUpdate`, replace the per-rect encode loop with:

```go
useZlib := s.clientSupports(encZlib)
for _, r := range dirty {
    enc, payload := rfbcore.EncodeDirtyRect(img, rfbcore.Rect{X: r.X, Y: r.Y, W: r.W, H: r.H}, img.Stride, s.pf, useZlib)
    hdr := make([]byte, 12)
    binary.BigEndian.PutUint16(hdr[0:2], uint16(r.X))
    binary.BigEndian.PutUint16(hdr[2:4], uint16(r.Y))
    binary.BigEndian.PutUint16(hdr[4:6], uint16(r.W))
    binary.BigEndian.PutUint16(hdr[6:8], uint16(r.H))
    binary.BigEndian.PutUint32(hdr[8:12], uint32(enc))
    rectHdrs = append(rectHdrs, hdr)
    pixels = append(pixels, payload)
    totalLen += 12 + len(payload)
}
```

  - In `sendFramebufferUpdate`, replace `encodePixelsFast`/`encodePixelsGeneric` with `rfbcore.EncodePixelsFast`/`rfbcore.EncodePixelsGeneric` (or `rfbcore.EncodeRectPixels` into `buf[off:]`).

Note: `Rect` in `pkg/vnc/screen.go` becomes `rfbcore.Rect`; update `CaptureDirty() (*image.RGBA, []Rect, error)` to return `[]rfbcore.Rect`, and the `ScreenCapturer` interface in `server.go` accordingly.

- [ ] **Step 3: Replace diff + Rect in `pkg/vnc/screen.go`**

- Delete `type Rect`, `diffFrames`, and the local `dirtyTileSize`/`maxDirtyRects` consts.
- Add import `"tailvnc/pkg/rfbcore"`.
- In `loop()`, replace `dirty := diffFrames(c.prevFrame, img)` with `dirty := rfbcore.DiffFrames(c.prevFrame, img)`.
- Update `SessionAwareCapturer.dirty` field type to `[]rfbcore.Rect` and the `CaptureDirty` return type.

- [ ] **Step 4: Replace latin-1 helpers in `pkg/vnc/clipboard.go`**

- Delete `latin1ToUTF8`, `utf8ToLatin1`.
- Add import `"tailvnc/pkg/rfbcore"`.
- `sendServerCutText`: `latin1 := rfbcore.UTF8ToLatin1(text)`.
- `handleCutText`: `s.clipBoard.SetText(rfbcore.Latin1ToUTF8(buf))`.

- [ ] **Step 5: Verify the build matrix**

Run:
```bash
GOOS=linux go test ./pkg/rfbcore/... ./pkg/deobfuscator/... ./pkg/utils/...
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: Linux tests PASS; Windows vet and build both succeed with zero errors.

If `go vet ./...` on Windows reports the pre-existing 4 `unsafe.Pointer` warnings (`agent.go:132`, `clipboard.go:48,74`, `screen.go:202`), that is expected — they are addressed in Task 13 (QUAL-1) and Task 2 already removed the `diffFrames` one. Do not let them block this task; the build must still succeed (vet warnings ≠ build errors).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(vnc): build-tag Windows code, delegate pure logic to pkg/rfbcore"
```

---

## Task 6: CORR-1 — zlib fallback downgrades to Raw (session-level)

**Files:**
- Modify: `pkg/vnc/rfb.go` (`sendDirtyUpdate`).

**Interfaces:**
- Consumes: `rfbcore.EncodeDirtyRect` (already wired in Task 5 Step 2).

The downgrade logic itself now lives in `rfbcore.EncodeDirtyRect` (tested in Task 4). This task verifies the session uses it correctly and adds a regression note.

- [ ] **Step 1: Confirm the session no longer constructs a Raw-mislabeled-as-Zlib rect**

Open `pkg/vnc/rfb.go` `sendDirtyUpdate`. Confirm it calls `rfbcore.EncodeDirtyRect` (from Task 5) and that the returned `enc` is written into the rect header verbatim. There must be **no** code path that sets the header to `encZlib` while the payload came from a failed compress.

- [ ] **Step 2: Verify on Windows**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: success.

Manual check (Windows VM, optional): connect a VNC client that advertises zlib; confirm a static-then-changing desktop updates correctly. The error path is only hit under memory pressure; the unit test in Task 4 (`TestEncodeDirtyRectRawAndZlib`) is the primary guard.

- [ ] **Step 3: Commit**

```bash
git add pkg/vnc/rfb.go
git commit -m "fix(vnc): CORR-1 zlib failure now downgrades rect to Raw (via rfbcore.EncodeDirtyRect)"
```

---

## Task 7: CORR-3 — move `staticFrames` dirty-read inside the mutex

**Files:**
- Modify: `pkg/vnc/screen.go` (`SessionAwareCapturer.loop`, around line 425-453).

**Interfaces:** none new.

- [ ] **Step 1: Apply the fix**

In `pkg/vnc/screen.go` `loop()`, replace the unlock-then-read block:

```go
		c.mu.Lock()
		dirty := rfbcore.DiffFrames(c.prevFrame, img)
		c.frame = img
		c.prevFrame = img
		if dirty != nil {
			c.dirty = dirty
		} else {
			c.dirty = nil
		}
		c.mu.Unlock()

		staticFrames++
		delay := 33 * time.Millisecond
		if staticFrames > 3 {
			delay = 100 * time.Millisecond
		}
		if len(c.dirty) != 0 || c.dirty == nil {
			staticFrames = 0
		}
		time.Sleep(delay)
```

with a version that captures the decision **inside** the lock:

```go
		needFull := false
		hasDirty := false
		c.mu.Lock()
		dirty := rfbcore.DiffFrames(c.prevFrame, img)
		c.frame = img
		c.prevFrame = img
		if dirty != nil {
			c.dirty = dirty
			hasDirty = len(dirty) > 0
		} else {
			c.dirty = nil
			needFull = true // nil == full-frame update needed
		}
		c.mu.Unlock()

		staticFrames++
		delay := 33 * time.Millisecond
		if staticFrames > 3 {
			delay = 100 * time.Millisecond
		}
		if hasDirty || needFull {
			staticFrames = 0
		}
		time.Sleep(delay)
```

- [ ] **Step 2: Verify on Windows**

Run:
```bash
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: success.

Then on a Windows VM, `go test -race ./...` if a capture-loop race test exists (none yet — note as M3 work); at minimum confirm the service runs without `-race` reports when exercised. The change is small and obviously removes the only unlocked read of `c.dirty`.

- [ ] **Step 3: Commit**

```bash
git add pkg/vnc/screen.go
git commit -m "fix(vnc): CORR-3 move staticFrames dirty-read inside mutex (data race)"
```

---

## Task 8: CORR-2 — per-session input state (no shared globals)

**Files:**
- Modify: `pkg/vnc/input.go` (remove globals `prevButtonMask`, `sasCtrlDown`, `sasAltDown`).
- Modify: `pkg/vnc/server.go` (`DesktopAwareInput` / `LocalInput` carry per-session state; `inputCmd` gains fields).

**Interfaces:**
- Produces: input state lives on the injector instance, not the package.

- [ ] **Step 1: Remove the package globals**

In `pkg/vnc/input.go`:
- Delete `var prevButtonMask uint8` (line 113).
- Delete `var sasCtrlDown bool` / `var sasAltDown bool` (lines 238-239).

- [ ] **Step 2: Thread state through the injector**

Add a per-instance state struct and convert `SimulateButtonEvent`/`SimulateKeyEvent` to methods on it. In `pkg/vnc/input.go`:

```go
// inputState holds per-session input tracking that must not be shared across
// concurrent VNC clients (CORR-2: previously package globals).
type inputState struct {
	prevButton uint8
	ctrlDown   bool
	altDown    bool
}
```

Convert the functions that used the globals to methods on `*inputState`:
- `SimulateButtonEvent` → `func (st *inputState) simulateButtonEvent(buttonMask uint8, x, y, screenW, screenH int)`; replace `prevButtonMask` with `st.prevButton`.
- `SimulateKeyEvent` → `func (st *inputState) simulateKeyEvent(keysym uint32, down bool)`; replace `sasCtrlDown`/`sasAltDown` with `st.ctrlDown`/`st.altDown`.

- [ ] **Step 3: Give each injector its own `inputState`**

In `pkg/vnc/server.go`:
- `LocalInput` gains `st inputState`; `InjectPointer` calls `l.st.simulateButtonEvent(...)`.
- `DesktopAwareInput` gains `st inputState`; in `loop()`, the worker uses `d.st` when dispatching. Because `loop()` is a single goroutine, `d.st` is accessed from one goroutine — safe. `InjectKey`/`InjectPointer` only send on `d.ch`, so they don't touch `d.st`.

Update `inputCmd` and the `loop()` dispatch to call the methods above.

- [ ] **Step 4: Verify on Windows**

Run:
```bash
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: no `prevButtonMask`/`sasCtrlDown`/`sasAltDown` references remain; build succeeds.

Manual (Windows VM): connect two VNC clients to the agent; alternate mouse/keyboard; confirm button presses and Ctrl+Alt+Del from one client no longer corrupt the other's state.

- [ ] **Step 5: Commit**

```bash
git add pkg/vnc/input.go pkg/vnc/server.go
git commit -m "fix(vnc): CORR-2 per-session input state (was shared globals)"
```

---

## Task 9: SEC-6 — secrets from env/file, not argv or ldflags process list

**Files:**
- Modify: `Makefile` (pass `AUTH_KEY` via env to the obfuscator).
- Modify: `obfuscator/obfuscate_key_hex.go` (read key from env or stdin, not `os.Args[1]`).
- Modify: `cmd/vnc/main.go` (read `AUTH_PASS` from env `TAILVNC_AUTH_PASS` as a fallback before refusing to start).
- Create: `pkg/secrets/secrets.go` + `pkg/secrets/secrets_test.go` (pure, Linux-testable env-reading helper).

**Interfaces:**
- Produces: `secrets.FromEnvOrFile(envVar, path string) string` (pure, testable).

- [ ] **Step 1: Write the failing test**

Create `pkg/secrets/secrets_test.go`:

```go
package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnvOrFile(t *testing.T) {
	// Env wins.
	t.Setenv("TAILVNC_AUTH_PASS", "from-env")
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", ""); got != "from-env" {
		t.Fatalf("env: got %q", got)
	}

	// File fallback when env unset.
	dir := t.TempDir()
	p := filepath.Join(dir, "pass")
	if err := os.WriteFile(p, []byte("from-file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAILVNC_AUTH_PASS", "")
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", p); got != "from-file" {
		t.Fatalf("file: got %q", got)
	}

	// Neither -> empty.
	if got := FromEnvOrFile("TAILVNC_AUTH_PASS", ""); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/secrets/...`
Expected: FAIL — package undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/secrets/secrets.go`:

```go
// Package secrets reads sensitive configuration from environment variables or
// protected files — never from process argv (which leaks into `ps`, build
// logs, and shell history).
package secrets

import (
	"os"
	"strings"
)

// FromEnvOrFile returns the value of envVar if set and non-empty; otherwise
// the trimmed contents of path if it exists; otherwise the empty string.
func FromEnvOrFile(envVar, path string) string {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		return v
	}
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/secrets/...`
Expected: PASS.

- [ ] **Step 5: Obfuscator reads key from env, not argv**

In `obfuscator/obfuscate_key_hex.go` `main()`, replace:

```go
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <auth-key>\n", os.Args[0])
		os.Exit(1)
	}
	fmt.Print(obfuscateAuthKeyToHex(os.Args[1]))
```

with:

```go
	key := os.Getenv("AUTH_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "AUTH_KEY env var required (read from env so the key never appears in argv/ps)")
		os.Exit(1)
	}
	fmt.Print(obfuscateAuthKeyToHex(key))
```

- [ ] **Step 6: Makefile passes key via env**

In `Makefile`, change the LDFLAGS obfuscator invocation from `$(shell go run obfuscator/obfuscate_key_hex.go '$(AUTH_KEY)')` to export-then-run:

```makefile
OBfuscatedKey := $(if $(AUTH_KEY),$(shell AUTH_KEY='$(AUTH_KEY)' go run obfuscator/obfuscate_key_hex.go),)
```

and use `$(OBfuscatedKey)` in the `-X main.buildWithObfuscatedAuthKey=` slot. (The key now travels in the child process environment, not its argv.)

- [ ] **Step 7: main.go reads AUTH_PASS from env as a fallback**

In `cmd/vnc/main.go`, after the existing `--auth-pass`/`buildWithAuthPass` resolution and before the `log.Fatal("no VNC password...")`, add:

```go
	if authPass == "" {
		if v := secrets.FromEnvOrFile("TAILVNC_AUTH_PASS", ""); v != "" {
			authPass = v
		}
	}
```

(Add import `"tailvnc/pkg/secrets"`.)

- [ ] **Step 8: Verify**

Run:
```bash
GOOS=linux go test ./pkg/secrets/...
GOOS=windows GOARCH=amd64 go build ./...
AUTH_KEY=tskey-test go run obfuscator/obfuscate_key_hex.go   # prints hex, no key in argv
```
Expected: secrets test PASS; Windows build succeeds; obfuscator prints hex output without taking the key as an argument.

- [ ] **Step 9: Commit**

```bash
git add pkg/secrets/ obfuscator/ Makefile cmd/vnc/main.go
git commit -m "fix(secrets): SEC-6 read auth key/pass from env, not argv/ldflags"
```

---

## Task 10: SEC-1 — default loopback bind + VNCAuth failure backoff

**Files:**
- Modify: `cmd/vnc/main.go` (default `LISTEN_ADDR` → `127.0.0.1`).
- Modify: `pkg/vnc/server.go` (carry auth-failure counters).
- Modify: `pkg/vnc/rfb.go` (`doVNCAuth` backoff on repeated failures).

**Interfaces:** none new.

- [ ] **Step 1: Default bind to loopback**

In `cmd/vnc/main.go`, change `listenAddr := "0.0.0.0"` to `listenAddr := "127.0.0.1"`. Update the `--help`/README wording to say exposure now requires explicit `LISTEN_ADDR=0.0.0.0`.

- [ ] **Step 2: Add per-listener auth-failure backoff**

In `pkg/vnc/rfb.go`, add a package-level throttled failure tracker (keyed by remote address). Add near the top:

```go
// authFailures counts recent VNCAuth failures per remote address and is used
// to throttle brute-force attempts (SEC-1). A failed attempt sleeps before
// replying, scaling with the count.
var (
	authFailMu sync.Mutex
	authFails  = map[string]int{}
)

func authBackoff(remote string) {
	authFailMu.Lock()
	n := authFails[remote] + 1
	authFails[remote] = n
	authFailMu.Unlock()
	// 1s, 2s, 4s, ... capped at 30s.
	d := time.Second << uint(min(n, 5))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	time.Sleep(d)
}

func authReset(remote string) {
	authFailMu.Lock()
	delete(authFails, remote)
	authFailMu.Unlock()
}
```

In `doVNCAuth`, on failure (`result = 1`) call `authBackoff(s.addr())` before writing the failure result; on success call `authReset(s.addr())`.

(`min` is a Go 1.21+ builtin — available on 1.25.3.)

- [ ] **Step 3: Verify on Windows**

Run:
```bash
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: success.

Manual (Windows VM): point the default build at loopback; confirm a remote (non-loopback) client cannot reach it without explicit `LISTEN_ADDR`; confirm 5 wrong passwords produce visible increasing delay.

- [ ] **Step 4: Commit**

```bash
git add cmd/vnc/main.go pkg/vnc/rfb.go
git commit -m "fix(vnc): SEC-1 default loopback bind + VNCAuth failure backoff"
```

---

## Task 11: SEC-2 — agent IPC one-time token authentication

**Files:**
- Create: `pkg/authtoken/authtoken.go` (pure `net`/`crypto`/`subtle` — Linux-testable).
- Create: `pkg/authtoken/authtoken_test.go`
- Modify: `pkg/vnc/agent.go` (`spawnAgentInSession` generates a token, injects it into the agent's env block; returns `(windows.Handle, []byte, error)`).
- Modify: `pkg/vnc/server.go` (`RunAsService`/`sessionManager` carry the token).
- Modify: `pkg/vnc/ipc.go` (`proxyToAgent` writes the token before proxying).
- Modify: `cmd/vnc/main.go` (`runAgent` wraps its listener with `authtoken.NewListener`).

**Interfaces:**
- Produces: `authtoken.Generate(n int) ([]byte, error)`, `authtoken.NewListener(ln net.Listener, token []byte) *authtoken.Listener`, `(*Listener).Accept() (net.Conn, error)`, `authtoken.ErrTokenMismatch`.
- Consumes: none.

The protocol-agnostic core (token generation + the listener that rejects connections not presenting the token) is pure `net`/`crypto` and is TDD'd on Linux with `net.Pipe`. Only the Windows env-block injection is Tier B.

- [ ] **Step 1: Write the failing test for the token listener**

Create `pkg/authtoken/authtoken_test.go`:

```go
package authtoken

import (
	"bytes"
	"net"
	"testing"
)

func TestGenerateLength(t *testing.T) {
	tok, err := Generate(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("len=%d, want 32", len(tok))
	}
	// Two generations differ (random).
	tok2, _ := Generate(32)
	if bytes.Equal(tok, tok2) {
		t.Fatal("Generate produced identical tokens twice")
	}
}

// pipeListener is a minimal net.Listener backed by net.Pipe for tests.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
}

func newPipeListener() *pipeListener { return &pipeListener{conns: make(chan net.Conn, 4), done: make(chan struct{})} }
func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.done:
		return nil, net.ErrClosed
	}
}
func (p *pipeListener) Close() error   { close(p.done); return nil }
func (p *pipeListener) Addr() net.Addr { return nil }

func TestTokenListenerAcceptsMatchAndRejectsMismatch(t *testing.T) {
	tok, _ := Generate(32)
	pl := newPipeListener()
	ln := NewListener(pl, tok)

	// Good client: writes the token.
	a, b := net.Pipe()
	pl.conns <- a
	go b.Write(tok) // nolint — ignore short write; tok is small
	go func() {
		for i := 0; i < 1; i++ {
			<-ln.accepted
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("good token rejected: %v", err)
	}
	conn.Close()

	// Bad client: writes wrong bytes.
	a2, b2 := net.Pipe()
	pl.conns <- a2
	go b2.Write(bytes.Repeat([]byte{0x00}, 32))
	if _, err := ln.Accept(); err == nil {
		t.Fatal("bad token accepted; want ErrTokenMismatch")
	}
}
```

(If the `accepted` channel helper above complicates the struct, simplify `Listener` to expose `Accept()` only and drive the test purely through `net.Pipe`; the implementer may adjust the test harness as long as it asserts both the accept-good and reject-bad paths. The contract under test: matching token → returns a usable conn; mismatch/short-read → returns `ErrTokenMismatch` and closes the underlying conn.)

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/authtoken/...`
Expected: FAIL — package undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/authtoken/authtoken.go`:

```go
// Package authtoken provides a one-time shared-secret handshake used to
// authenticate the loopback IPC between the TailVNC service (Session 0) and
// its user-session agent (SEC-2). Without it any local process could connect
// to 127.0.0.1:<agent-port> and seize unauthenticated desktop control.
package authtoken

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"time"
)

// ErrTokenMismatch is returned by Accept when a connection does not present
// the expected token within the deadline.
var ErrTokenMismatch = errors.New("authtoken: token mismatch")

// Generate returns n cryptographically random bytes.
func Generate(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Listener wraps a net.Listener. Each accepted connection must send exactly
// len(token) bytes matching token within 5 seconds, else it is closed and
// Accept returns ErrTokenMismatch.
type Listener struct {
	net.Listener
	token []byte
}

// NewListener wraps ln so every connection must authenticate with token.
func NewListener(ln net.Listener, token []byte) *Listener {
	return &Listener{Listener: ln, token: token}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		buf := make([]byte, len(l.token))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(c, buf)
		_ = c.SetReadDeadline(time.Time{})
		if err != nil || subtle.ConstantTimeCompare(buf, l.token) != 1 {
			c.Close()
			// Try the next pending connection rather than surfacing the error,
			// so a misbehaving local peer cannot DoS the agent's accept loop.
			continue
		}
		return c, nil
	}
}
```

(Note: the implementation above silently continues to the next connection on mismatch instead of returning `ErrTokenMismatch`. Adjust the test in Step 1 accordingly: for the "bad token" case, send a second, valid connection through `pl.conns` and assert `Accept` eventually returns the valid conn — proving the bad one was dropped. This is the production-safe behavior; surface `ErrTokenMismatch` only if a test explicitly wants it. Keep the test and impl consistent.)

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/authtoken/...`
Expected: PASS.

- [ ] **Step 5: Generate the token and inject it into the agent env (Windows)**

In `pkg/vnc/agent.go`, change `spawnAgentInSession` to generate a token and return it:

```go
func spawnAgentInSession(sessionID uint32, port string) (windows.Handle, []byte, error) {
	// ... existing token/env setup ...
	tok, err := authtoken.Generate(32)
	if err != nil {
		return 0, nil, fmt.Errorf("authtoken.Generate: %w", err)
	}
	// Inject TAILVNC_AGENT_TOKEN=<hex(tok)> into the child environment block
	// (see Step 6 note on the env-block contract).
	// ... CreateProcessAsUser with the augmented env block ...
	return pi.Process, tok, nil
}
```

`sessionManager` stores the current `token []byte` alongside `agentProc`; `RunAsService` reads it and passes it to `proxyToAgent`.

- [ ] **Step 6: Wire the listener and the proxy write**

- `cmd/vnc/main.go` `runAgent`: after `ln, err := net.Listen(...)`, if `tok := os.Getenv("TAILVNC_AGENT_TOKEN"); tok != ""`, decode it from hex and wrap: `ln = authtoken.NewListener(ln, decodedTok)`.
- `pkg/vnc/ipc.go` `proxyToAgent`: add a `token []byte` parameter; after `agentConn` is established, before the two `cp` goroutines:

```go
	if _, err := agentConn.Write(token); err != nil {
		agentConn.Close()
		return
	}
```

- [ ] **Step 7: Verify on Windows**

Run:
```bash
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: success.

**Verification note (env-block injection, Tier B):** the only piece not covered by the Linux test is merging `TAILVNC_AGENT_TOKEN=<hex>` into the `CreateEnvironmentBlock`-produced block passed to `CreateProcessAsUser`. The Win32 contract is a sequence of `KEY=VALUE\0` records terminated by an extra `\0`. Implement by walking the existing block, dropping any prior `TAILVNC_AGENT_TOKEN=` record, then appending the new record + terminator. Verify on a Windows VM: (a) a legitimate VNC client via the service connects normally; (b) a local process connecting directly to `127.0.0.1:<agent-port>` without the token is dropped silently.

- [ ] **Step 8: Commit**

```bash
git add pkg/authtoken/ pkg/vnc/agent.go pkg/vnc/server.go pkg/vnc/ipc.go cmd/vnc/main.go
git commit -m "feat(authtoken): SEC-2 one-time token auth on agent loopback IPC"
```

---

## Task 12: SEC-4 — refuse to re-exec agent from a non-admin path

The full defense is a DACL inspection (deferred — see DoD). The M1 mitigation is a **pure, testable path check**: only re-exec when the executable lives under an admin-writable root (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%SystemRoot%`). A binary dropped in `%TEMP%` / a user profile is rejected.

**Files:**
- Create: `pkg/secureroot/secureroot.go`
- Create: `pkg/secureroot/secureroot_test.go`
- Modify: `pkg/vnc/agent.go` (`spawnAgentInSession` calls the guard).

**Interfaces:**
- Produces: `secureroot.IsInSecureDir(exePath string, secureRoots []string) bool`.
- Consumes: none.

- [ ] **Step 1: Write the failing test**

Create `pkg/secureroot/secureroot_test.go`:

```go
package secureroot

import "testing"

func TestIsInSecureDir(t *testing.T) {
	roots := []string{`C:\Program Files`, `C:\Program Files (x86)`, `C:\Windows`}
	cases := []struct {
		name string
		exe  string
		want bool
	}{
		{"under program files", `C:\Program Files\TailVNC\TailVNC.exe`, true},
		{"case-insensitive root", `c:\program files\tailvnc\tailvnc.exe`, true},
		{"trailing separator on root", `C:\Program Files\TailVNC\TailVNC.exe`, true},
		{"under windows", `C:\Windows\System32\TailVNC.exe`, true},
		{"temp rejected", `C:\Windows\Temp\TailVNC.exe`, false},
		{"user profile rejected", `C:\Users\bob\Downloads\TailVNC.exe`, false},
		{"relative rejected", `TailVNC.exe`, false},
		{"public rejected", `C:\Users\Public\TailVNC.exe`, false},
	}
	for _, c := range cases {
		if got := IsInSecureDir(c.exe, roots); got != c.want {
			t.Errorf("%s: IsInSecureDir(%q)=%v, want %v", c.name, c.exe, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/secureroot/...`
Expected: FAIL — package undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/secureroot/secureroot.go`:

```go
// Package secureroot guards the SYSTEM service's re-exec of itself (SEC-4).
// A local non-admin who can write the binary's directory can swap the file and
// get SYSTEM code execution on the next agent spawn. M1 mitigates by allowing
// re-exec only when the executable lives under an admin-writable root. The
// fuller DACL-based check is deferred to M3.
package secureroot

import (
	"path/filepath"
	"strings"
)

// IsInSecureDir reports whether exePath's containing directory is at or under
// one of secureRoots. Comparison is case-insensitive (Windows FS semantics)
// after cleaning the path. A relative exePath is never secure.
func IsInSecureDir(exePath string, secureRoots []string) bool {
	if exePath == "" || !filepath.IsAbs(exePath) {
		return false
	}
	dir := filepath.Clean(exePath)
	for _, root := range secureRoots {
		r := strings.ToLower(filepath.Clean(root))
		d := strings.ToLower(dir)
		if d == r || strings.HasPrefix(d, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test ./pkg/secureroot/...`
Expected: PASS.

- [ ] **Step 5: Wire it into the agent spawner**

In `pkg/vnc/agent.go`, after `exePath, err := os.Executable()`:

```go
	if err := secureExePath(exePath); err != nil {
		return 0, "", fmt.Errorf("SEC-4: refusing to re-exec from insecure path %s: %w", exePath, err)
	}
```

and add the helper in the same file:

```go
// secureExePath enforces SEC-4: the agent (re-executed as SYSTEM) may only run
// from an admin-writable directory. Roots are expanded from the process env.
func secureExePath(exePath string) error {
	roots := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("SystemRoot"),
	}
	if !secureroot.IsInSecureDir(exePath, roots) {
		return fmt.Errorf("executable must live under %%ProgramFiles%% or %%SystemRoot%%; got %s (M3 will add a full DACL check)", exePath)
	}
	return nil
}
```

(Add imports `"os"` and `"tailvnc/pkg/secureroot"`.)

- [ ] **Step 6: Verify on Windows**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: success. On a Windows VM, confirm: an exe in `%ProgramFiles%\TailVNC\` spawns its agent; an exe copied to `%TEMP%` is rejected with the SEC-4 log line and the session manager backs off.

- [ ] **Step 7: Commit**

```bash
git add pkg/secureroot/ pkg/vnc/agent.go
git commit -m "feat(vnc): SEC-4 refuse to re-exec agent from non-admin path (M1 path-allowlist)"
```

---

## Task 13: SEC-5 — RFB parser bounded-work hardening + QUAL-1 vet cleanup

**Files:**
- Modify: `pkg/vnc/rfb.go` (bounds on `handleSetEncodings` count; `handleCutText` already capped at 1MB — confirm; add a per-connection FBU rate gate stub).
- Modify: `pkg/vnc/screen.go` (remove the `*[1 << 28]uint64` unsafe trick — already gone via Task 2's `rfbcore.DiffFrames`).
- Modify: `pkg/vnc/clipboard.go` (replace remaining `unsafe.Pointer` clipboard casts with `windows.UTF16PtrToString` / `unsafe.Slice` forms that vet accepts).
- Modify: `pkg/vnc/agent.go` (line 132 env-block pointer cast).

**Interfaces:** none new.

- [ ] **Step 1: Bound SetEncodings**

In `pkg/vnc/rfb.go` `handleSetEncodings`, cap `numEnc`:

```go
	numEnc := binary.BigEndian.Uint16(header[1:3])
	if numEnc > 256 {
		return fmt.Errorf("too many encodings: %d (max 256)", numEnc)
	}
```

- [ ] **Step 2: Confirm CutText cap**

`handleCutText` already rejects `length > 1<<20`. Confirm it is still present after Task 5; if so, no change. Add a comment citing the bound.

- [ ] **Step 3: Resolve remaining vet unsafe.Pointer warnings**

Run `GOOS=windows GOARCH=amd64 go vet ./...` and address each remaining warning (`agent.go:132`, `clipboard.go:48`, `clipboard.go:74`). For clipboard GlobalLock pointers, use `unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), n)` with a computed length rather than casting to a fixed giant array; for the env-block pointer, ensure the cast is a direct `uintptr` → typed pointer of the same underlying allocation. Re-run vet until clean.

- [ ] **Step 4: Verify on Windows**

Run:
```bash
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
```
Expected: **zero** vet warnings; build succeeds.

- [ ] **Step 5: Commit**

```bash
git add pkg/vnc/rfb.go pkg/vnc/clipboard.go pkg/vnc/agent.go
git commit -m "fix(vnc): SEC-5 bound SetEncodings; QUAL-1 clear go vet unsafe.Pointer warnings"
```

---

## Task 14: SEC-3 + QUAL-2 — shared obfuscate key, honest comment, README fix

**Files:**
- Create: `pkg/obfkey/obfkey.go` (single source of truth for the AES key).
- Modify: `obfuscator/obfuscate_key_hex.go` and `pkg/deobfuscator/deobfuscate_key_hex.go` to import the shared key.
- Modify: `README.md` (fix the "XOR-obfuscated" line).

**Interfaces:**
- Produces: `obfkey.Key []byte` (32 bytes).

- [ ] **Step 1: Create the shared key package**

Create `pkg/obfkey/obfkey.go`:

```go
// Package obfkey is the single source of truth for the AES-256 key used to
// obfuscate the embedded Tailscale auth key at build time.
//
// SECURITY HONESTY: this key ships inside the binary, so it CANNOT prevent a
// determined reverse-engineer from recovering the auth key. Its only purpose
// is to remove plaintext credentials from `strings` / hex dumps and defeat
// trivial static analysis. Treat Tailscale auth keys as if they were plaintext
// once the binary is in an attacker's hands — use short-lived, restricted keys.
package obfkey

var Key = []byte{
	0x9c, 0x37, 0xa2, 0xe8, 0x51, 0x6f, 0xc4, 0x1b,
	0xd8, 0x7e, 0x03, 0xfa, 0x62, 0x9d, 0xb5, 0x44,
	0x1f, 0xa0, 0x8c, 0xe6, 0x73, 0x2d, 0x9b, 0x58,
	0xce, 0x40, 0xf7, 0x11, 0x84, 0xab, 0x36, 0x6e,
}
```

- [ ] **Step 2: Use it in both packages**

In `obfuscator/obfuscate_key_hex.go`, delete the local `obfuscateKey` var and import/use `obfkey.Key`. In `pkg/deobfuscator/deobfuscate_key_hex.go`, same. Both reference `"tailvnc/pkg/obfkey"`.

- [ ] **Step 3: Fix the README**

In `README.md`, change the Features line:
`- **Auth Key Obfuscation** - Tailscale auth key is XOR-obfuscated at build time to prevent plaintext credential exposure in the binary`
to:
`- **Auth Key Obfuscation** - Tailscale auth key is AES-256-CTR encrypted at build time (key embedded in binary; removes plaintext from static analysis but is NOT a defense against reverse engineering — use short-lived restricted keys)`

- [ ] **Step 4: Verify**

Run:
```bash
GOOS=linux go test ./pkg/deobfuscator/...
GOOS=windows GOARCH=amd64 go build ./...
AUTH_KEY=tskey-test go run obfuscator/obfuscate_key_hex.go | xargs -I{} go run ./pkg/deobfuscator  # round-trip check if a tiny main exists; else rely on build
```
Expected: deobfuscator test PASS; Windows build succeeds.

- [ ] **Step 5: Commit**

```bash
git add pkg/obfkey/ obfuscator/ pkg/deobfuscator/ README.md
git commit -m "fix(obfkey): SEC-3/QUAL-2 single obfuscate-key source + honest README"
```

---

## Definition of Done (M1)

- `GOOS=linux go test ./pkg/rfbcore/... ./pkg/secrets/... ./pkg/deobfuscator/... ./pkg/utils/...` — all PASS, pure-logic coverage ≥80% for `pkg/rfbcore`.
- `GOOS=windows GOARCH=amd64 go vet ./...` — zero warnings.
- `GOOS=windows GOARCH=amd64 go build ./...` — success.
- CORR-1, CORR-2, CORR-3, SEC-1, SEC-2, SEC-4, SEC-5, SEC-6 all addressed (SEC-2/SEC-4 Windows-runtime behavior verified on a VM).
- No new `console.log`-equivalent debug noise; logs are intentional.
- README XOR/AES contradiction resolved.

Open items deliberately deferred to M2/M3 (do **not** block M1): VeNCrypt/TLS (§9.1), named-pipe IPC (§9.2 — M1 uses loopback+token), DPAPI key encryption (§9.3), full-motion FPS ceiling (PERF-1), clipboard UTF-8 (FUNC-1), persistence installer (OPS-4), the privilege-narrowing half of SEC-5 (M1 does parser bounds; dropping the agent from SYSTEM to a least-privilege token that still reaches the secure desktop is M2), and the full DACL-based path check for SEC-4 (M1 ships the path-allowlist mitigation).
