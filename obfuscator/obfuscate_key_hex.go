package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"tailvnc/pkg/obfkey"
)

// obfuscateAuthKeyToHex encrypts the auth key with AES-CTR and returns
// hex(nonce || ciphertext). A fresh random nonce is generated per build.
func obfuscateAuthKeyToHex(key string) string {
	block, err := aes.NewCipher(obfkey.Key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, block.BlockSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, nonce)
	ct := make([]byte, len(key))
	stream.XORKeyStream(ct, []byte(key))
	return hex.EncodeToString(append(nonce, ct...))
}

func main() {
	key := os.Getenv("AUTH_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "AUTH_KEY env var required (read from env so the key never appears in argv/ps)")
		os.Exit(1)
	}
	fmt.Print(obfuscateAuthKeyToHex(key))
}
