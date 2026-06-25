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
