package exit

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// encryptPayload encrypts data with ChaCha20-Poly1305 (nonce prepended)
func encryptPayload(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Prepend nonce
	result := make([]byte, 12+len(ciphertext))
	copy(result, nonce)
	copy(result[12:], ciphertext)

	return result, nil
}

// decryptPayload decrypts data with ChaCha20-Poly1305 (nonce prepended)
func decryptPayload(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}

	if len(data) < 12+16 { // nonce(12) + auth_tag(16)
		return nil, fmt.Errorf("data too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
