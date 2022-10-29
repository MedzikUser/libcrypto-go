package libcrypto

import "crypto/rand"

// GenerateSalt returns a random salt.
func GenerateSalt(size int) ([]byte, error) {
	// allocate a byte slice of the given size
	salt := make([]byte, size)

	// write random bytes into the slice
	_, err := rand.Read(salt[:])

	return salt, err
}
