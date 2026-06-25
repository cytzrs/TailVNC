package obfkey

import "testing"

func TestKeyIsAES256(t *testing.T) {
	if len(Key) != 32 {
		t.Fatalf("Key len=%d, want 32 (AES-256)", len(Key))
	}
}
