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
