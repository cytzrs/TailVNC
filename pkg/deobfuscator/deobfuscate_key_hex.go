package deobfuscator

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"

	"tailvnc/pkg/obfkey"
)

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
	block, err := aes.NewCipher(obfkey.Key)
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
