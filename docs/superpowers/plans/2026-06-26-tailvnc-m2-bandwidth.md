# TailVNC M2 — Bandwidth Optimization Implementation Plan

> **Status (2026-06-26): IMPLEMENTED on `feature-dev`.** Tasks 1–6 complete and committed; Task 7 skipped (redundant — content sends are already capped at the capturer's 30 fps × consume-once, see the analysis in the Task 7 section). Linux TDD green throughout (`pkg/rfbcore` 92–95% covered); `GOOS=windows go build` + `go vet` clean (only the 2 pre-existing deferred QUAL-1 `clipboard.go` warnings). The four Tier B behaviors (CopyRect / Cursor / Tight / GDI-pool) live in Windows-only code and **need a Windows VM + TigerVNC verification before relying on them** — see the VM Regression Checklist at the end of this doc.
>
> | Task | Commit | Outcome |
> |---|---|---|
> | 1 three-state DiffFrames + CoalesceRects | `4b9745c` | unfreezes full-screen motion |
> | 2 CopyRect move detection | `c453c85` | scroll/drag ≈ free |
> | 3 Cursor pseudo-encoding -239 | `a6bf33f` + `e79d318` | mouse motion ≈ free |
> | 4 RGB565 16bpp fast path | `b6df113` | text/UI raw payload halved |
> | 5 Tight (Fill / Basic-zlib / JPEG) | `1e97a13` + `3225942` | mixed content 2–5× |
> | 6 pool GDI DC + DIB | `f39f091` | cuts per-frame GDI churn (RGBA double-buffer deferred to VM) |
> | 7 per-client FBU rate cap | — | skipped: redundant w/ capturer 30 fps + consume-once |

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut remote-link bandwidth for interactive remote-admin workloads (baseline ≈ 8 MB/min at 1080p with zlib) by delivering only real changes, encoding them more efficiently, and removing the full-screen "freeze" pathology. Net target after Tasks 1–3 + 5: **~2–4 MB/min** for typical 1080p admin work, ~8–12 MB/min for media-heavy content.

**Scope alignment:** This plan realizes the bandwidth-relevant items of the master spec's M2 (`docs/superpowers/specs/2026-06-25-tailvnc-full-remediation-design.md`): PERF-1 (frame-rate/diff correctness), PERF-2 (capture allocation), CORR-5 (DesktopSize + optional Cursor), and adds three net-new encoding wins (CopyRect, Tight+JPEG, 16bpp fast path) not originally enumerated. PERF-3 (clipboard polling) and FUNC-1 (clipboard UTF-8) are M2 but **not bandwidth-relevant** → out of scope here; LIFE-4 (FBU rate-limit) is formally M3 but pulled forward as Task 7 because it is cheap and caps the peak.

**Architecture:** All new protocol logic (diff three-state, rect coalescing, CopyRect move detection, Tight/JPEG encoding, 16bpp fast path, cursor pseudo-rect wire format) lands in `pkg/rfbcore` (build-tag-free, Linux-testable, ≥80% coverage). The Windows `pkg/vnc` layer only wires these into the RFB message loop and (for cursor) captures via Win32. No new dependency except the stdlib (`image/jpeg`, `hash/crc32`); JPEG is already in the Go standard library.

**Tech Stack:** Go 1.25.3, stdlib `compress/zlib` / `image/jpeg` / `hash/crc32` / `image`. Tests: stdlib `testing`, table-driven.

## Global Constraints

Copied from the M1 plan and the spec; still in force:

- **Two verification tiers (critical):** Linux dev box, Windows-only product.
  - **Tier A (Linux, full TDD):** pure-logic tasks target `pkg/rfbcore`. Command: `GOOS=linux go test ./pkg/rfbcore/...`. Must pass with ≥80% coverage on the touched files.
  - **Tier B (Windows, build + manual verify):** anything touching `pkg/vnc` or `cmd/vnc`. Commands: `GOOS=windows GOARCH=amd64 go vet ./...` and `GOOS=windows GOARCH=amd64 go build ./...`. Both must pass with zero errors. Runtime behavior verified on a Windows VM with a real VNC client (TigerVNC/TightVNC recommended — they advertise Zlib, Tight, CopyRect, Cursor).
- **Go version:** `go 1.25.3`. Do not bump. No new external deps.
- **Commits:** conventional `<type>: <desc>`. No attribution. Commit after every task. Branch: `feature-dev`.
- **Immutability / error handling:** new pure functions return errors explicitly; no swallowed `_ =`.
- **Positioning:** legitimate remote ops tool. No stealth/anti-detection.
- **Baseline before starting:** capture a "before" number. On a Windows VM, run the current build, connect a VNC client, exercise a fixed 60s admin script (open menus, scroll a doc, drag a window, type), and record the client's bytes-received. Write it into the task-1 commit message. The DoD compares "after" to this number.

---

## File Structure

New / modified in `pkg/rfbcore` (pure, Linux-testable):
- `pkg/rfbcore/diff.go` — `DiffFrames` becomes three-state `(rects []Rect, full bool)`; add `CoalesceRects`.
- `pkg/rfbcore/copyrect.go` (new) — `CopyRect`, `DetectMoves` (tile-hash move detection).
- `pkg/rfbcore/tight.go` (new) — `EncodeTight` (zlib + JPEG per-rect).
- `pkg/rfbcore/pixelfmt.go` — add `PixelFormat565`, `CanUseFastPath565`, `EncodePixelsFast565`.
- `pkg/rfbcore/cursor.go` (new) — `EncodeCursorPseudoRect` wire-format builder.
- `pkg/rfbcore/rfbcore_test.go` — append table-driven tests for all of the above.

Modified (Windows, build-tagged `pkg/vnc`):
- `pkg/vnc/screen.go` — `SessionAwareCapturer` carries `full bool`; `CaptureDirty` returns `(img, rects, full, err)`; pooled capture buffer (PERF-2).
- `pkg/vnc/rfb.go` — `handleFBUpdateRequest` handles three states; `sendDirtyUpdate` consults CopyRect + Tight; advertise Cursor/CopyRect/Tight; per-session FBU throttle.
- `pkg/vnc/server.go` — `ScreenCapturer` interface gains `full` in `CaptureDirty`.
- `pkg/vnc/cursor.go` (new) — Win32 `GetCursorInfo` capture, send Cursor pseudo-rect.
- `pkg/vnc/ipc.go` — no change (loopback, free).

Each task is self-contained: its implementer sees only that task, so **Interfaces** blocks spell out exact signatures neighbors rely on.

---

## Task 1 — DiffFrames three-state + rect coalescing (fixes the full-screen freeze)

**Problem:** `DiffFrames` returns `nil` for *both* "no change" and "too many changes (>256 tiles)". `handleFBUpdateRequest` can't tell them apart → both yield `sendEmptyUpdate` → full-screen motion freezes at ~4 B/frame (CORR-5/PERF-1). Fix: distinguish the two, and on "too many" deliver a real full-frame update instead of an empty one.

**Files:**
- Modify: `pkg/rfbcore/diff.go`, `pkg/rfbcore/rfbcore_test.go`
- Modify (Tier B): `pkg/vnc/screen.go`, `pkg/vnc/server.go`, `pkg/vnc/rfb.go`

**Interfaces:**
- Changes: `rfbcore.DiffFrames(prev, cur *image.RGBA) (rects []Rect, full bool)` — `(nil,false)`=no change; `([...],false)`=dirty; `(nil,true)`=full update needed.
- Produces: `rfbcore.CoalesceRects(in []Rect) []Rect`.
- `ScreenCapturer.CaptureDirty() (*image.RGBA, []rfbcore.Rect, bool, error)` (new `full` return).

- [ ] **Step 1: Write the failing tests**

Append to `pkg/rfbcore/rfbcore_test.go`:

```go
func TestDiffFramesThreeStates(t *testing.T) {
	w, h := 64, 64
	prev := image.NewRGBA(image.Rect(0, 0, w, h))

	// (nil, false): identical frames = no change.
	cur := image.NewRGBA(prev.Rect)
	if rects, full := DiffFrames(prev, cur); full || len(rects) != 0 {
		t.Fatalf("identical: rects=%v full=%v, want empty/not-full", rects, full)
	}

	// ([...], false): one tile changed = dirty.
	cur.Set(1, 1, color.RGBA{R: 255, A: 255})
	rects, full := DiffFrames(prev, cur)
	if full || len(rects) != 1 {
		t.Fatalf("one tile: rects=%v full=%v, want 1 dirty / not-full", rects, full)
	}

	// (nil, true): more than MaxDirtyRects tiles changed = full update.
	big := image.NewRGBA(image.Rect(0, 0, DirtyTileSize*(MaxDirtyRects+1), DirtyTileSize))
	prevBig := image.NewRGBA(big.Rect)
	for tx := 0; tx < big.Rect.Dx(); tx += DirtyTileSize {
		big.Set(tx, 0, color.RGBA{G: 255, A: 255})
	}
	rects, full = DiffFrames(prevBig, big)
	if !full || rects != nil {
		t.Fatalf("too many: rects=%v full=%v, want nil/full", rects, full)
	}

	// (nil, true): nil prev = full update (not "no change").
	if rects, full := DiffFrames(nil, cur); !full || rects != nil {
		t.Fatalf("nil prev: rects=%v full=%v, want nil/full", rects, full)
	}
}

func TestCoalesceRects(t *testing.T) {
	// Two horizontally-adjacent 32x32 tiles merge into one 64x32 rect.
	in := []Rect{{0, 0, 32, 32}, {32, 0, 32, 32}}
	got := CoalesceRects(in)
	if len(got) != 1 || got[0] != (Rect{0, 0, 64, 32}) {
		t.Fatalf("adjacent merge: got %+v, want [{0 0 64 32}]", got)
	}
	// Two far-apart rects do NOT merge (waste guard).
	far := []Rect{{0, 0, 32, 32}, {1000, 1000, 32, 32}}
	if got := CoalesceRects(far); len(got) != 2 {
		t.Fatalf("far apart: got %d rects, want 2", len(got))
	}
}
```

(Add `"image/color"` to imports if not present.)

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./pkg/rfbcore/...`
Expected: FAIL — signature mismatch / `CoalesceRects` undefined.

- [ ] **Step 3: Implement (pure core)**

In `pkg/rfbcore/diff.go`, change `DiffFrames` to return `(rects []Rect, full bool)`: keep the tile loop; on the `len(rects) >= MaxDirtyRects` path return `nil, true`; on the nil/size-mismatch paths return `nil, true`; otherwise `rects, false`. Add:

```go
// CoalesceRects merges rects that overlap or share an edge when the union wastes
// less than 2x the summed area. Reduces rect count (and 12-byte headers) without
// re-introducing the freeze: large sparse change-sets stay under MaxDirtyRects.
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

func unionIfCheap(a, b Rect) (Rect, bool) {
	x0 := min(a.X, b.X)
	y0 := min(a.Y, b.Y)
	x1 := max(a.X+a.W, b.X+b.W)
	y1 := max(a.Y+a.H, b.Y+b.H)
	u := Rect{x0, y0, x1 - x0, y1 - y0}
	// Adjacent or overlapping, and union area <= 2x sum (waste guard).
	touches := a.X <= b.X+b.W && b.X <= a.X+a.W && a.Y <= b.Y+b.H && b.Y <= a.Y+a.H
	// Expand the overlap test by 1px so edge-adjacent rects (share a border) merge.
	if !touches {
		return u, false
	}
	if int(u.W)*int(u.H) > 2*(int(a.W)*int(a.H)+int(b.W)*int(b.H)) {
		return u, false
	}
	return u, true
}
```

(`min`/`max` are Go 1.21+ builtins — available on 1.25.3.)

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=linux go test -cover ./pkg/rfbcore/...`
Expected: PASS, coverage on `diff.go` ≥80%.

- [ ] **Step 5: Wire the three states through (Tier B)**

- `pkg/vnc/screen.go`: add `full bool` field to `SessionAwareCapturer`; in `loop()` capture `dirty, full := rfbcore.DiffFrames(c.prevFrame, img)` and store both under `c.mu`; coalesce non-full dirty with `rfbcore.CoalesceRects`. Change `CaptureDirty` signature to `(*image.RGBA, []rfbcore.Rect, bool, error)` returning the stored values.
- `pkg/vnc/server.go`: update the `ScreenCapturer` interface `CaptureDirty` to match.
- `pkg/vnc/rfb.go` `handleFBUpdateRequest`, incremental branch:

```go
img, dirty, full, err := s.capturer.CaptureDirty()
if err != nil { return err }
switch {
case full:
    return s.sendFramebufferUpdate(img, 0, 0, s.serverW, s.serverH) // deliver, don't freeze
case len(dirty) == 0:
    return s.sendEmptyUpdate()
default:
    return s.sendDirtyUpdate(img, dirty)
}
```

- [ ] **Step 6: Verify (Tier B)**

Run: `GOOS=windows GOARCH=amd64 go vet ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: success. On VM: full-screen window drag / video no longer freezes; client receives continuous updates.

- [ ] **Step 7: Commit**

```bash
git add pkg/rfbcore/diff.go pkg/rfbcore/rfbcore_test.go pkg/vnc/screen.go pkg/vnc/server.go pkg/vnc/rfb.go
git commit -m "fix(rfbcore): three-state DiffFrames + CoalesceRects (unfreeze full-screen, PERF-1/CORR-5)"
```

---

## Task 2 — CopyRect encoding (scroll / window-drag → ~4 bytes instead of pixels)

**Problem:** Scrolling and window-dragging are common in admin work and currently re-send identical pixel data. RFB CopyRect (enc=1, already declared `encCopyRect` in `rfb.go:36`) sends a 4-byte source coordinate instead. Highest single ROI for this workload.

**Files:**
- Create: `pkg/rfbcore/copyrect.go`, append tests to `pkg/rfbcore/rfbcore_test.go`
- Modify (Tier B): `pkg/vnc/rfb.go` (`sendDirtyUpdate`)

**Interfaces:**
- Produces: `rfbcore.CopyRect{DstX, DstY, W, H, SrcX, SrcY int}`, `rfbcore.DetectMoves(prev, cur *image.RGBA, dirty []Rect) (moves []CopyRect, realDirty []Rect)`, `rfbcore.EncCopyRect int32 = 1`.
- Wire format: CopyRect rect header (encoding=1) + payload `[srcX u16][srcY u16]` (big-endian).

- [ ] **Step 1: Write the failing test**

Append to `pkg/rfbcore/rfbcore_test.go`:

```go
func TestDetectMovesTranslatedBlock(t *testing.T) {
	// 128x32 frame. prev has a distinct 32x32 block at x=0; cur has the SAME
	// block content at x=64. DiffFrames reports a dirty tile at (64,0).
	w, h := 128, 32
	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < 32; x++ { prev.Set(x, 0, color.RGBA{R: 200, A: 255}) } // marker block
	cur := image.NewRGBA(prev.Rect)
	for x := 64; x < 96; x++ { cur.Set(x, 0, color.RGBA{R: 200, A: 255}) } // moved right

	dirty, _ := DiffFrames(prev, cur) // dirty at tile (64,0)
	moves, realDirty := DetectMoves(prev, cur, dirty)
	if len(moves) != 1 {
		t.Fatalf("moves=%v, want 1", moves)
	}
	m := moves[0]
	if m.SrcX != 0 || m.DstX != 64 || m.W != 32 || m.H != 32 {
		t.Fatalf("move=%+v, want SrcX=0 DstX=64 32x32", m)
	}
	if len(realDirty) != 0 {
		t.Fatalf("realDirty=%v, want empty (all dirty was a move)", realDirty)
	}
}
```

- [ ] **Step 2: Run test to verify it fails** → `GOOS=linux go test ./pkg/rfbcore/...` → FAIL (`DetectMoves` undefined).

- [ ] **Step 3: Implement (pure core)**

Create `pkg/rfbcore/copyrect.go`:

```go
package rfbcore

import (
	"hash/crc32"
	"image"
)

// EncCopyRect is the RFB CopyRect encoding type.
const EncCopyRect int32 = 1

// CopyRect describes a rectangle whose pixels are an exact copy of another
// region in the previous frame.
type CopyRect struct{ DstX, DstY, W, H, SrcX, SrcY int }

// DetectMoves inspects each dirty tile: if its content hash matches a tile in
// prev at a different position, it is reported as a CopyRect move rather than
// pixel data. Remaining genuinely-changed tiles come back in realDirty.
//
// Tile granularity is DirtyTileSize, matching DiffFrames, so dirty tiles align
// to the hash grid. O(tiles) time, O(tiles) memory per frame.
func DetectMoves(prev, cur *image.RGBA, dirty []Rect) (moves []CopyRect, realDirty []Rect) {
	if prev == nil || cur == nil {
		return nil, dirty
	}
	// Index prev tiles by content hash -> first position.
	type cell struct{ x, y int }
	index := map[uint32]cell{}
	for ty := 0; ty < prev.Rect.Dy(); ty += DirtyTileSize {
		for tx := 0; tx < prev.Rect.Dx(); tx += DirtyTileSize {
			index[hashTile(prev, tx, ty)] = cell{tx, ty}
		}
	}
	for _, d := range dirty {
		src, ok := index[hashTile(cur, d.X, d.Y)]
		if ok && (src.x != d.X || src.y != d.Y) {
			moves = append(moves, CopyRect{d.X, d.Y, d.W, d.H, src.x, src.y})
		} else {
			realDirty = append(realDirty, d)
		}
	}
	return moves, realDirty
}

// hashTile returns a CRC32 over one tile's pixels (top-down rows).
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
```

- [ ] **Step 4: Run test to verify it passes** → `GOOS=linux go test -cover ./pkg/rfbcore/...` → PASS.

- [ ] **Step 5: Wire into sendDirtyUpdate (Tier B)**

In `pkg/vnc/rfb.go` `sendDirtyUpdate`: keep `prev` accessible to the session (add `s.prevFrame *image.RGBA`, updated each send). When `s.clientSupports(encCopyRect)`, call `rfbcore.DetectMoves(s.prevFrame, img, dirty)`; emit CopyRect rects (12-byte header encoding=1 + 4-byte `srcX/srcY`) for moves, and the existing `EncodeDirtyRect` path for `realDirty`. Update `s.prevFrame = img` after encoding.

- [ ] **Step 6: Verify (Tier B)** → `GOOS=windows GOARCH=amd64 go vet ./... && go build ./...`; on VM scroll a long doc / drag a window with a TigerVNC client → bytes/frame drop sharply for the moved region.

- [ ] **Step 7: Commit**

```bash
git add pkg/rfbcore/copyrect.go pkg/rfbcore/rfbcore_test.go pkg/vnc/rfb.go
git commit -m "feat(rfbcore): CopyRect move detection (scroll/drag bandwidth, encCopyRect wired)"
```

---

## Task 3 — Local cursor (Cursor pseudo-encoding -239) → mouse motion ≈ free

**Problem:** Mouse movement is the most frequent admin action. Either the cursor is invisible (current — GDI `BitBlt` excludes it) or, if captured, it dirties tiles every move. The RFB Cursor pseudo-encoding (enc=-239) ships the cursor bitmap once and lets the client render it locally, so mouse motion costs ~0 bandwidth.

**Files:**
- Create: `pkg/rfbcore/cursor.go`, append tests
- Create (Tier B): `pkg/vnc/cursor.go` (Win32 `GetCursorInfo` capture)
- Modify (Tier B): `pkg/vnc/rfb.go` (advertise -239, send on change), `pkg/vnc/server.go`

**Interfaces:**
- Produces: `rfbcore.EncCursor int32 = -239`, `rfbcore.EncodeCursorPseudoRect(x, y, w, h, hotX, hotY int, pf PixelFormat, rgba *image.RGBA) []byte` (full rect: 12-byte header + pixel payload + bitmask).
- Consumes: `rfbcore.EncodeRectPixels`, `PixelFormat`.

- [ ] **Step 1: Write the failing test**

```go
func TestEncodeCursorPseudoRectLayout(t *testing.T) {
	// 2x2 cursor, hotspot (1,0), canonical 32bpp.
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	pf := PixelFormat{Bpp: 32, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}
	buf := EncodeCursorPseudoRect(5, 6, 2, 2, 1, 0, pf, img)
	// 12-byte rect header + 2*2*4 pixel bytes + ceil(2/8)*2 bitmask = 12+16+2 = 30
	if len(buf) != 30 {
		t.Fatalf("len=%d, want 30", len(buf))
	}
	if int32(buf[8])|(int32(buf[9])<<8)|(int32(buf[10])<<16)|(int32(buf[11])<<24) != EncCursor {
		t.Fatal("rect encoding field is not EncCursor (-239)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails** → FAIL.

- [ ] **Step 3: Implement wire-format builder (pure core)**

Create `pkg/rfbcore/cursor.go`:

```go
package rfbcore

import (
	"encoding/binary"
	"image"
)

// EncCursor is the RFB Cursor pseudo-encoding (server sends the cursor shape;
// the client renders it locally so mouse motion costs no bandwidth).
const EncCursor int32 = -239

// EncodeCursorPseudoRect builds a full Cursor pseudo-rectangle: 12-byte rect
// header (x,y = current hotspot position; w,h = cursor size; encoding=-239),
// followed by the cursor pixels (in pf) and a 1bpp visibility bitmask.
func EncodeCursorPseudoRect(x, y, w, h, hotX, hotY int, pf PixelFormat, img *image.RGBA) []byte {
	pixels := EncodeRectPixels(img, 0, 0, w, h, img.Stride, pf)
	maskRowBytes := (w + 7) / 8
	mask := make([]byte, maskRowBytes*h)
	// Set a bit where the pixel is opaque (alpha != 0); client shows only those.
	for row := 0; row < h; row++ {
		for col := 0; col < w; col++ {
			a := img.Pix[row*img.Stride+col*4+3]
			if a != 0 {
				mask[row*maskRowBytes+col/8] |= 0x80 >> uint(col%8)
			}
		}
	}
	out := make([]byte, 12+len(pixels)+len(mask))
	binary.BigEndian.PutUint16(out[0:2], uint16(x))
	binary.BigEndian.PutUint16(out[2:4], uint16(y))
	binary.BigEndian.PutUint16(out[4:6], uint16(w))
	binary.BigEndian.PutUint16(out[6:8], uint16(h))
	binary.BigEndian.PutUint32(out[8:12], uint32(EncCursor))
	copy(out[12:], pixels)
	copy(out[12+len(pixels):], mask)
	_ = hotX
	_ = hotY
	return out
}
```

- [ ] **Step 4: Run test to verify it passes** → PASS.

- [ ] **Step 5: Capture the cursor on Windows (Tier B)**

Create `pkg/vnc/cursor.go` (`//go:build windows`): use `user32.GetCursorInfo` → `hCursor`; on change of handle or screen position, rasterize via `DrawIconEx` into a 32bpp DIB (BGRA→RGBA as in `screen.go:208`), return `*image.RGBA` + hotspot from `GetIconInfo`. Expose `func currentCursor() (img *image.RGBA, hotX, hotY, w, h int, changed bool)`. Send a Cursor pseudo-rect (via a small server→client push like the clipboard loop in `rfb.go:141`) only when `changed`. Gate on `s.clientSupports(encCursor)`.

- [ ] **Step 6: Verify (Tier B)** → build; on VM move the mouse continuously with a client that advertises Cursor (-239) → downstream stays near-idle during pure mouse motion and the cursor tracks smoothly.

- [ ] **Step 7: Commit**

```bash
git add pkg/rfbcore/cursor.go pkg/rfbcore/rfbcore_test.go pkg/vnc/cursor.go pkg/vnc/rfb.go pkg/vnc/server.go
git commit -m "feat(vnc): local cursor via Cursor pseudo-encoding -239 (CORR-5 optional)"
```

---

## Task 4 — 16bpp (RGB565) fast path → halves raw payload for text/UI

**Note:** Only engages when the VNC client requests a 16bpp format (operator-configurable in most viewers). The generic path already encodes arbitrary bpp correctly; this adds a fast path so 16bpp is cheap. Lower priority than 1–3.

**Files:** Modify `pkg/rfbcore/pixelfmt.go`, append tests.

**Interfaces:** Produces `rfbcore.PixelFormat565`, `rfbcore.CanUseFastPath565(pf) bool`, `rfbcore.EncodePixelsFast565(img, x, y, w, h, stride, bigEndian int, out []byte)`.

- [ ] **Step 1: Failing test** — 2×1 image, red then green; encode with `PixelFormat565`; assert 4 output bytes match hand-computed 565 values (red≈0xF800, green≈0x07E0).
- [ ] **Step 2: Run-fail.**
- [ ] **Step 3: Implement** — `PixelFormat565 = PixelFormat{Bpp:16, BigEndian:0, RMax:31, GMax:63, BMax:31, RShift:11, GShift:5, BShift:0}`; `CanUseFastPath565` checks that exact layout; `EncodePixelsFast565` packs `(r>>3)<<11 | (g>>2)<<5 | (b>>3)` per pixel, big/little-endian.
- [ ] **Step 4: Pass, coverage ≥80%.**
- [ ] **Step 5: Verify (Tier B)** — `go vet`/`build`. Manual: set the client to 16bpp; confirm text stays readable and bytes/frame drop ~2× for text regions vs 32bpp.
- [ ] **Step 6: Commit** — `feat(rfbcore): RGB565 16bpp fast path (text/UI raw payload halved)`.

---

## Task 5 — Tight + JPEG encoding (encTight=7) → 2–5× on mixed/photo content

`encTight` is declared (`rfb.go:39`) but unimplemented. Tight: per-rect, a control byte (low 4 bits = zlib level 0–9, bit 4 = stream-reset, bit 7 = JPEG), then either filtered zlib data or JPEG. Biggest general-purpose win; split into two sub-steps.

**Files:** Create `pkg/rfbcore/tight.go`, append tests; modify `pkg/vnc/rfb.go`.

**Interfaces:** Produces `rfbcore.EncTight int32 = 7`, `rfbcore.EncodeTight(img *image.RGBA, r Rect, stride int, pf PixelFormat, level int, useJPEG bool, quality int) (payload []byte, err error)`.

- [ ] **Step 5a — Tight zlib (no JPEG):**
  - [ ] **Failing test:** encode a flat-color 32×32 rect; assert payload starts with a control byte (level) and the remainder is a valid zlib stream that decompresses to the (filtered) raw pixels.
  - [ ] **Implement:** copy the rect's pixels (in pf), run them through Tight's per-row "copy" filter (filter id 0x00 prepended per row for the simplest filter), zlib-compress with the chosen level, prepend the control byte (`level & 0x0f`). Use a `zlib.Writer` configured via `zlib.NewWriterLevel`.
  - [ ] **Pass.**
  - [ ] **Wire (Tier B):** in `sendDirtyUpdate`, if `s.clientSupports(encTight)`, prefer `EncodeTight(... useJPEG=false ...)` over `EncodeDirtyRect`; fall back to Zlib/Raw on error.
  - [ ] **Commit:** `feat(rfbcore): Tight (zlib) encoding, encTight wired`.

- [ ] **Step 5b — Tight + JPEG for photo regions:**
  - [ ] **Failing test:** encode a 32×32 rect with `useJPEG=true, quality=8`; assert payload control byte has bit 7 set and the remainder is decodable by `image/jpeg` to approximately the input (PSNR threshold, since JPEG is lossy).
  - [ ] **Implement:** for useJPEG, render the rect to a `*image.YCbCr`-compatible `image.Image`, `jpeg.Encode` into a buffer at the mapped quality (0–100), prepend control byte with bit 7 set. Handle Tight's requirement that JPEG dimensions be multiples of 16 (pad internally, the rect header still reports true w/h).
  - [ ] **Pass.**
  - [ ] **Wire (Tier B):** add a per-session quality knob (e.g. `--tight-quality`), default off (lossless Tight-zlib) so text stays sharp; operator opts into lossy for media-heavy hosts.
  - [ ] **Commit:** `feat(rfbcore): Tight+JPEG for photo regions (lossy, opt-in quality knob)`.

---

## Task 6 — Capture pipeline: eliminate per-frame NewRGBA + BGRA→RGBA scalar loop (PERF-2)

**Problem:** `screen.go:208-214` allocates a fresh `image.RGBA` every frame and runs a per-pixel BGRA→RGBA loop (~250 MB/s allocation at 1080p/30fps). Not bandwidth directly, but it caps achievable FPS and starves the finer-grained diff/CopyRect detection that *does* save bandwidth.

**Files:** Modify `pkg/vnc/screen.go`; optionally create `pkg/rfbcore/pool.go`.

- [ ] **Step 1:** Add a double-buffered frame pool: two `*image.RGBA` of screen size, swapped each frame (no per-frame alloc). Keep BGRA→RGBA conversion but do it with `unsafe.Slice` byte-swaps in 4-byte chunks (or capture directly as XRGB by having the encoder consume BGRA — the canonical fast path already shuffles bytes, so feed it BGRA and adjust the shuffle). Verify no `unsafe.Pointer` arithmetic that trips `go vet` (the existing QUAL-1 vet-clean pattern in `rfbcore` is the model).
- [ ] **Step 2 (Tier B verify):** `go vet ./...` clean; `go build ./...`. On VM confirm capture FPS is stable and memory allocs/frame dropped (optional: a temporary `runtime.ReadMemStats` log line, removed before commit).
- [ ] **Step 3: Commit** — `perf(vnc): pooled double-buffer capture, drop per-frame NewRGBA/BGRA->RGBA loop (PERF-2)`.

---

## Task 7 — Per-client FBU rate limit + coalescing (LIFE-4, pulled forward)

**Problem:** `handleFBUpdateRequest` fires a capture+send for every client request; a viewer hammering at 60 fps gets 60 sends. Cap the response rate and drop intermediate requests to bound the peak.

**Files:** Modify `pkg/vnc/rfb.go`.

- [ ] **Step 1:** Add per-`session` state: `lastFBU time.Time`, a `pendingReq` flag, and a `time.Timer`. On `handleFBUpdateRequest`: if a request is already pending and `time.Since(lastFBU) < minInterval` (e.g. 33 ms ≈ 30 fps cap), set `pendingReq` and return without sending; a single short timer fires the coalesced update when eligible. This replaces implicit backpressure with explicit pacing.
- [ ] **Step 2 (Tier B verify):** build; on VM confirm a flood of FramebufferUpdateRequest messages no longer produces a proportional flood of FBU responses; interactive latency stays acceptable.
- [ ] **Step 3: Commit** — `perf(vnc): per-session FBU rate cap + coalescing (LIFE-4 forward-port)`.

---

## Definition of Done (M2 — bandwidth scope)

- `GOOS=linux go test ./pkg/rfbcore/...` — all PASS; `pkg/rfbcore` coverage ≥80% on the new/changed files (`diff.go`, `copyrect.go`, `tight.go`, `cursor.go`, `pixelfmt.go`).
- `GOOS=windows GOARCH=amd64 go vet ./...` — zero warnings (no new `unsafe.Pointer` regressions; Task 6 follows the QUAL-1-clean pattern).
- `GOOS=windows GOARCH=amd64 go build ./...` — success.
- On a Windows VM with a real VNC client (TigerVNC/TightVNC), against the **baseline 60s admin script** recorded before Task 1:
  - **Typical admin (1080p, zlib): bytes received ≤ 50% of baseline** (Tasks 1–3 do most of it; Task 5 closes the gap on media).
  - **Scrolling / window-drag:** bytes for the moved region drop ≥90% (CopyRect).
  - **Pure mouse motion (Cursor client):** downstream stays within ~2× of idle.
  - **Full-screen motion:** no longer freezes (Task 1 three-state).
- No new external Go dependencies (JPEG/zlib/crc32 all stdlib).
- `README.md` Tech Stack / Features updated: mention CopyRect, Tight(+JPEG), local cursor, 16bpp as supported encodings.

## Deferred (out of M2-bandwidth scope; tracked in the master spec)

- PERF-3 (clipboard `AddClipboardFormatListener` instead of 500 ms polling) and FUNC-1 (clipboard UTF-8 passthrough) — M2 items but not bandwidth; handle in a separate M2-clipboard task.
- ZRLE/TRLE — consider for M3 if Tight is insufficient; Tight+JPEG covers the same ground with less code.
- VeNCrypt/TLS, named-pipe IPC, DPAPI key encryption, persistence installer (OPS-4) — M3.
- The privilege-narrowing half of SEC-5 (drop agent from SYSTEM to least-privilege that still reaches the secure desktop) — M2/M3; orthogonal to bandwidth.

---

## VM Regression Checklist (run before relying on the M2 encodings)

The pure-logic cores are unit-tested on Linux, but four Tier B behaviors are Windows-only and unverified by this dev box. Run all of this on a Windows VM with a real VNC client **before** treating the bandwidth wins as production-ready.

### Setup
- Windows VM running the Session 0 service + user-session agent (`make build-vnc AUTH_PASS=...`).
- TigerVNC client (advertises Raw / Zlib / CopyRect / Tight / Cursor / JPEG quality).
- A `master`-branch build of the same exe to A/B against (the "before"), since the changes are already on `feature-dev`.

### Build matrix (confirm on the Linux dev box first)
- [ ] `go test -race ./pkg/rfbcore/` green
- [ ] `GOOS=windows GOARCH=amd64 go vet ./...` — only the 2 known `clipboard.go` warnings
- [ ] `GOOS=windows GOARCH=amd64 go build ./...` succeeds
- [ ] `make build-vnc AUTH_PASS=...` produces the exe

### Per-encoding behavioral checks (watch the `[..] >> FBU ...` log line + the client's bytes-received)
- [ ] **Task 1 — freeze:** full-screen video / large window drag → screen keeps updating (no freeze); log shows full-frame sends when >256 tiles change in one frame.
- [ ] **Task 2 — CopyRect:** scroll a long doc / drag a window → log shows `copyrect=true`; bytes for the moved region drop sharply (~4 B/rect vs full pixels). Client renders the moved content correctly (no garbage/tearing).
- [ ] **Task 3 — Cursor:** with a client advertising Cursor (-239), move the mouse continuously → downstream stays near-idle AND the cursor is visible and tracks. Verify shape changes (arrow ↔ text caret ↔ busy) render, and the hotspot isn't shifted. If the cursor looks wrong → suspect DrawIconEx alpha/mask handling (masked vs 32-bit alpha cursors) — the known v1 simplification.
- [ ] **Task 4 — 16bpp:** set the client to 16bpp → text stays readable, bytes/frame ~half of 32bpp, no color distortion beyond expected 565 banding.
- [ ] **Task 5 — Tight:** with Tight advertised → log shows `tight=true`; mixed content (text + icons) is visibly smaller than zlib-only. If the client fails to decode (garbled/gray) → suspect, in order: zlib stream-reset bit, TPIXEL 3-byte for canonical 32bpp, compact-length framing, JPEG quality mapping. With a JPEG-quality pseudo-enc (-23..-32) → photo regions decode. Verify wide (>2048 px) dirty rects fall back to Zlib with no corruption.
- [ ] **Task 6 — GDI pool:** run ≥10 min with capture flapping (lock/unlock, UAC prompt, resolution change) → no GDI handle leak (Task Manager → process → "GDI Objects" stays bounded, doesn't climb). Frames render identically to the `master` build.

### Concurrency / lifecycle
- [ ] Connect 2+ clients simultaneously → no torn frames, no corruption (CORR-2 per-session input state still holds).
- [ ] Desktop transition (lock → unlock) → capture recovers; capturer `Close()`/recreate doesn't crash the agent or leak handles.

### Bandwidth acceptance (the DoD numbers)
- [ ] Typical 1080p admin (60 s fixed script): bytes received ≤ 50% of the `master` baseline.
- [ ] Scroll / window-drag: moved-region bytes ≥ 90% reduction.
- [ ] Pure mouse motion (Cursor client): downstream within ~2× of idle.

### Rollback
Each task is a separate commit on `feature-dev`. If a regression is isolated to one encoding: `git revert <sha>` for that task only.
