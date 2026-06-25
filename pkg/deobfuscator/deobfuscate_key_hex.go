package deobfuscator

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// obfuscateKey must match obfuscator/obfuscate_key_hex.go exactly.
var obfuscateKey = []byte{
	0x9c, 0x37, 0xa2, 0xe8, 0x51, 0x6f, 0xc4, 0x1b,
	0xd8, 0x7e, 0x03, 0xfa, 0x62, 0x9d, 0xb5, 0x44,
	0x1f, 0xa0, 0x8c, 0xe6, 0x73, 0x2d, 0x9b, 0x58,
	0xce, 0x40, 0xf7, 0x11, 0x84, 0xab, 0x36, 0x6e,
}

func DeobfuscateAuthKey(obfuscatedKey string) string {
	if obfuscatedKey == "" {
		return ""
	}
	data, err := hex.DecodeString(obfuscatedKey)
	if err != nil {
		return ""
	}
	// Layout is hex(nonce || ciphertext); the nonce length equals the AES
	// block size (16 bytes).  Anything shorter is malformed.
	block, err := aes.NewCipher(obfuscateKey)
	if err != nil {
		return ""
	}
	nonceLen := block.BlockSize()
	if len(data) < nonceLen {
		return ""
	}
	nonce, ct := data[:nonceLen], data[nonceLen:]
	stream := cipher.NewCTR(block, nonce)
	pt := make([]byte, len(ct))
	stream.XORKeyStream(pt, ct)
	return string(pt)
}
