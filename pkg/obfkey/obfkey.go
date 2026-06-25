// Package obfkey is the single source of truth for the AES-256 key used to
// obfuscate the embedded Tailscale auth key at build time.
//
// SECURITY HONESTY: this key ships inside the binary, so it CANNOT prevent a
// determined reverse-engineer from recovering the auth key. Its only purpose
// is to remove plaintext credentials from `strings` / hex dumps and defeat
// trivial static analysis. Treat Tailscale auth keys as if they were plaintext
// once the binary is in an attacker's hands — use short-lived, restricted keys.
package obfkey

// Key is the shared AES-256 obfuscation key used by obfuscator/ and pkg/deobfuscator.
var Key = []byte{
	0x9c, 0x37, 0xa2, 0xe8, 0x51, 0x6f, 0xc4, 0x1b,
	0xd8, 0x7e, 0x03, 0xfa, 0x62, 0x9d, 0xb5, 0x44,
	0x1f, 0xa0, 0x8c, 0xe6, 0x73, 0x2d, 0x9b, 0x58,
	0xce, 0x40, 0xf7, 0x11, 0x84, 0xab, 0x36, 0x6e,
}
