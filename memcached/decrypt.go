package memcached

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
)

// CTRDecrypter decrypts the cipher text encrypted using AES-CTR-256
// 'key' is the secret key used to encrypt the cipher text ('ct')
func CTRDecrypter(key string, ct string) string {
	// Generate Hash key from the key string
	h := sha256.New()
   	h.Write([]byte(key))
	hashedKey := h.Sum(nil)

	// Convert cipher text to byte array
	cipherText, _ := hex.DecodeString(ct)

	// Extract initialization vector and original cipher text
	// IV Length is equal to Block Size, and is prefixed in the cipher text
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// AES CTR doesn't require the plain/cipher text to be multiple of block-size
	// however, the implementation in GO requires the plaintext, that is to be encrypted, to be multiple of block-size(16) .
	// But, it is not required while decrypting. Need to take care of this if we encrypt the data as well.

	block, err := aes.NewCipher([]byte(hashedKey))
	if err != nil {
	  	panic(err)
	}

	mode := cipher.NewCTR(block, []byte(iv))
	mode.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}
