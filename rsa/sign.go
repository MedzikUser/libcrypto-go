package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
)

// SignRsa returns a message signature.
func SignRsa(message []byte, pk *rsa.PrivateKey) (string, error) {
	// compute a message checksum
	hash := sha256.Sum256(message)

	// sign the message
	signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, hash[:])

	// encode the signature to a hex string
	signatureHex := hex.EncodeToString(signature)

	return signatureHex, err
}

// ValidateSignRsa validates the message signature.
func ValidateSignRsa(message []byte, sign string, pk *rsa.PublicKey) error {
	// compute a message checksum
	hash := sha256.Sum256(message)

	// decode the RSA signature to a byte slice
	signature, err := hex.DecodeString(sign)
	if err != nil {
		return nil
	}

	// verify message signature
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash[:], signature)

	return err
}
