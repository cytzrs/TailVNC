package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// obfuscateKey is a 32-byte AES-256 key used to encrypt the auth key at build
// time.  The matching key is embedded verbatim in pkg/deobfuscator so the
// service can decrypt at runtime.  Because the key must live inside the binary,
// this cannot defeat a determined reverse-engineer with the binary in hand; it
// does, however, remove the plaintext credential and defeat trivial static
// analysis (strings, hex dumps, XOR-byte searches).
var obfuscateKey = []byte{
	0x9c, 0x37, 0xa2, 0xe8, 0x51, 0x6f, 0xc4, 0x1b,
	0xd8, 0x7e, 0x03, 0xfa, 0x62, 0x9d, 0xb5, 0x44,
	0x1f, 0xa0, 0x8c, 0xe6, 0x73, 0x2d, 0x9b, 0x58,
	0xce, 0x40, 0xf7, 0x11, 0x84, 0xab, 0x36, 0x6e,
}

// obfuscateAuthKeyToHex encrypts the auth key with AES-CTR and returns
// hex(nonce || ciphertext). A fresh random nonce is generated per build.
func obfuscateAuthKeyToHex(key string) string {
	block, err := aes.NewCipher(obfuscateKey)
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
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <auth-key>\n", os.Args[0])
		os.Exit(1)
	}
	fmt.Print(obfuscateAuthKeyToHex(os.Args[1]))
}
