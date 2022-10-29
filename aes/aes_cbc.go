package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptAesCbc returns a cipher text.
//
//	saltSize := 16
//	salt, err := libcrypto.GenerateSalt(saltSize)
//	if err != nil {
//		t.Errorf("Failed to generate salt: %v", err)
//	}
//
//	// compute a 256-bit password hash with salt and 100000 iterations
//	key := libcrypto.Pbkdf2Hash256("password", salt, 100000)
//
//	clearText := "test to encrypt"
//
//	// encrypt the clear text
//	cipherText, err := EncryptAesCbc(key, clearText)
//	if err != nil {
//		panic(err)
//	}
func EncryptAesCbc(key string, clearText string) (string, error) {
	// decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// encode the clear text into bytes
	clearTextBytes := []byte(clearText)

	// add padding to the clear text
	clearTextBytes = PKCS5Padding(clearTextBytes, block.BlockSize())

	// allocate space in the heap for the cipher text
	cipherText := make([]byte, aes.BlockSize+len(clearTextBytes))

	// add initialization vector to the cipher text
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// returns a BlockMode which encrypts in cipher block chaining mode
	cbc := cipher.NewCBCEncrypter(block, iv)
	// encrypt the clear text
	cbc.CryptBlocks(cipherText[aes.BlockSize:], clearTextBytes)

	// returns the cipher text as a hex string
	return hex.EncodeToString(cipherText), nil
}

// DecryptAesCbc returns a decrypted text.
//
//	key := "key..."
//	cipherText := "cipher text..."
//
//	// decrypt the cipher text
//	cipherText, err := DecryptAesCbc(key, cipherText)
//	if err != nil {
//		panic(err)
//	}
func DecryptAesCbc(key string, cipherText string) (string, error) {
	// decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// decode the cipher text from a hex string
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("error decoding cipher text as hex string: %v", err)
	}

	// create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// get the initialization vector from the cipher key
	iv := cipherTextBytes[:aes.BlockSize]
	// get the cipher key without initialization vector
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	// returns a BlockMode which decrypts in cipher block chaining mode
	cbc := cipher.NewCBCDecrypter(block, iv)
	// decrypt all ciphers blocks
	cbc.CryptBlocks(cipherTextBytes, cipherTextBytes)

	// trim padding from the cipher text
	plainText := PKCS5Trimming(cipherTextBytes)

	// returns the plain text as a string
	return string(plainText), nil
}

// PKCS5Padding returns a padded text.
func PKCS5Padding(clearText []byte, blockSize int) []byte {
	// get padding length
	padding := blockSize - len(clearText)%blockSize

	// create a padding array
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	// add padding to the clear text
	return append(clearText, padtext...)
}

// PKCS5Trimming returns a encrypted bytes without padding.
func PKCS5Trimming(encrypt []byte) []byte {
	// get padding length
	padding := encrypt[len(encrypt)-1]

	// don't panic if encrypted text is invalid
	if padding > 16 {
		return encrypt
	}

	// returns a encrypted bytes without padding
	return encrypt[:len(encrypt)-int(padding)]
}
