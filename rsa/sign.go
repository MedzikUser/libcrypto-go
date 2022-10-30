package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
)

// Sign returns a message signature.
func Sign(pk *rsa.PrivateKey, message string) (string, error) {
	// compute a message checksum
	hash := sha256.Sum256([]byte(message))

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// signing function.
	rng := rand.Reader

	// sign the message
	signature, err := rsa.SignPKCS1v15(rng, pk, crypto.SHA256, hash[:])

	// encode the signature to a hex string
	signatureHex := hex.EncodeToString(signature)

	return signatureHex, err
}

// ValidateSignRsa validates the message signature.
func ValidateSign(pk *rsa.PublicKey, message string, sign string) error {
	// compute a message checksum
	hash := sha256.Sum256([]byte(message))

	// decode the RSA signature to a byte slice
	signature, err := hex.DecodeString(sign)
	if err != nil {
		return nil
	}

	// verify message signature
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash[:], signature)

	return err
}
