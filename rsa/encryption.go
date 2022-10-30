package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

/// Encrypt returns a cipher text of the clear text using RSA-OAEP algorithm.
func Encrypt(pk *rsa.PublicKey, clearText string, label string) (string, error) {
	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	// encrypt the clear text
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rng, pk, []byte(clearText), []byte(label))
	if err != nil {
		return "", err
	}

	// returns the cipher text as a hex string
	return hex.EncodeToString(cipherText), nil
}

/// Decrypt returns a decrypted text using RSA-OAEP algorithm.
func Decrypt(pk *rsa.PrivateKey, cipherText string, label string) (string, error) {
	// decode the cipher text from a hex string
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("error decoding cipher text as hex string: %v", err)
	}

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	// encrypt the clear text
	clearText, err := rsa.DecryptOAEP(sha256.New(), rng, pk, cipherTextBytes, []byte(label))
	if err != nil {
		return "", err
	}

	// returns the cipher text as a hex string
	return string(clearText), nil
}
