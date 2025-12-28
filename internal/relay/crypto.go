package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// generateX25519Keypair generates an X25519 keypair for key exchange
func generateX25519Keypair() ([]byte, []byte) {
	var priv, pub [32]byte

	if _, err := rand.Read(priv[:]); err != nil {
		panic(err)
	}

	// Clamp private key for X25519
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return priv[:], pub[:]
}

// computeSharedKey computes the shared secret from X25519 key exchange
func computeSharedKey(privKey, peerPubKey []byte) []byte {
	var priv, peerPub, shared [32]byte

	copy(priv[:], privKey)
	copy(peerPub[:], peerPubKey)

	curve25519.ScalarMult(&shared, &priv, &peerPub)

	// Derive symmetric key from shared secret
	h := sha256.New()
	h.Write(shared[:])
	return h.Sum(nil)
}

// hashKey returns a hash of the key for verification
func hashKey(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}

// encryptLayer encrypts data with ChaCha20-Poly1305
func encryptLayer(data, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(nonce))
	}

	return aead.Seal(nil, nonce, data, nil), nil
}

// decryptLayer decrypts data with ChaCha20-Poly1305
func decryptLayer(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(nonce))
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

// unwrapLayer decrypts one layer of garlic encryption
// Returns: decrypted data, next hop address (if any), isFinal, error
func unwrapLayer(data, key []byte) ([]byte, string, bool, error) {
	if len(data) < 12+16+1 {
		return nil, "", false, fmt.Errorf("data too short")
	}

	// First 12 bytes are nonce
	nonce := data[:12]
	ciphertext := data[12:]

	plaintext, err := decryptLayer(ciphertext, key, nonce)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to decrypt: %w", err)
	}

	if len(plaintext) < 1 {
		return nil, "", false, fmt.Errorf("empty payload")
	}

	// First byte indicates if this is the final hop
	isFinal := plaintext[0] == 1

	if isFinal {
		// Rest is the actual data
		return plaintext[1:], "", true, nil
	}

	// Not final: next 2 bytes are length of next hop address
	if len(plaintext) < 3 {
		return nil, "", false, fmt.Errorf("missing next hop info")
	}

	addrLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if len(plaintext) < 3+addrLen {
		return nil, "", false, fmt.Errorf("truncated next hop address")
	}

	nextHop := string(plaintext[3 : 3+addrLen])
	payload := plaintext[3+addrLen:]

	return payload, nextHop, false, nil
}

// encryptPayload encrypts data with ChaCha20-Poly1305 (nonce prepended)
// This matches the format used by the test client
func encryptPayload(data, key []byte) ([]byte, error) {
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

// wrapLayer encrypts data with one layer of garlic encryption
func wrapLayer(data, key []byte, nextHop string, isFinal bool) ([]byte, error) {
	var payload []byte

	if isFinal {
		payload = make([]byte, 1+len(data))
		payload[0] = 1
		copy(payload[1:], data)
	} else {
		addrBytes := []byte(nextHop)
		payload = make([]byte, 1+2+len(addrBytes)+len(data))
		payload[0] = 0
		binary.BigEndian.PutUint16(payload[1:3], uint16(len(addrBytes)))
		copy(payload[3:], addrBytes)
		copy(payload[3+len(addrBytes):], data)
	}

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted, err := encryptLayer(payload, key, nonce)
	if err != nil {
		return nil, err
	}

	// Prepend nonce
	result := make([]byte, len(nonce)+len(encrypted))
	copy(result, nonce)
	copy(result[len(nonce):], encrypted)

	return result, nil
}
