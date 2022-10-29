A cryptography utilities for golang

## Installation

This library requires Go 1.17 or newer; add it to your go.mod with:

    go get github.com/MedzikUser/libcrypto-go

## Examples

Hashing using PBKDF2

```go
// example data
password := "very secret passphrase"
salt := []byte("password salt")
iterations := 100

// PBKDF2 with SHA256 algorithm
hash256 := hash.Pbkdf2Hash256(password, salt, iterations)

// PBKDF2 with SHA512 algorithm
hash512 := hash.Pbkdf2Hash512(password, salt, iterations)
```

AES Encryption

```go
// example data
clearText := "hello world"
password := "very secret passphrase"
passwordSalt := []byte("password salt")
passwordIterations := 100

// compute a 256-bit AES key from the password
key := hash.Pbkdf2Hash256(password, passwordSalt, passwordIterations)

// encrypt the clear text using AES-CBC algorithm
cipherText, err := aes.EncryptAesCbc(key, clearText)

// decrypt the cipher text using AES-CBC algorithm
decryptedText, err := aes.EncryptAesCbc(key, cipherText)
```
