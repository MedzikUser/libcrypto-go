package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

// GenerateKey generates an RSA keypair of the given bit size.
func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	publicKey := privateKey.PublicKey

	return privateKey, &publicKey, nil
}
