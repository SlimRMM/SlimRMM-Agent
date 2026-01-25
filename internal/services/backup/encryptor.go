package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// HashAlgorithm defines the hash algorithm to use.
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
)

// Encryptor provides encryption/decryption services.
type Encryptor interface {
	// Encrypt encrypts data using AES-256-GCM.
	Encrypt(data []byte, key []byte) (ciphertext []byte, nonce []byte, err error)

	// Decrypt decrypts data using AES-256-GCM.
	Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error)

	// Hash computes a hash of the data.
	Hash(data []byte, algorithm HashAlgorithm) string
}

// AESEncryptor implements Encryptor using AES-256-GCM.
type AESEncryptor struct{}

// NewAESEncryptor creates a new AES encryptor.
func NewAESEncryptor() *AESEncryptor {
	return &AESEncryptor{}
}

// Encrypt encrypts data using AES-256-GCM.
func (e *AESEncryptor) Encrypt(data []byte, key []byte) ([]byte, []byte, error) {
	if len(key) == 0 {
		return nil, nil, &ErrEncryptionFailed{Reason: "invalid encryption key"}
	}

	if len(key) != 32 {
		return nil, nil, &ErrEncryptionFailed{Reason: "encryption key must be 32 bytes for AES-256"}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, &ErrEncryptionFailed{Reason: "creating cipher", Err: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, &ErrEncryptionFailed{Reason: "creating GCM", Err: err}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, &ErrEncryptionFailed{Reason: "generating nonce", Err: err}
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts data using AES-256-GCM.
func (e *AESEncryptor) Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, &ErrDecryptionFailed{Reason: "invalid encryption key"}
	}

	if len(key) != 32 {
		return nil, &ErrDecryptionFailed{Reason: "encryption key must be 32 bytes for AES-256"}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "creating cipher", Err: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "creating GCM", Err: err}
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, &ErrDecryptionFailed{Reason: "ciphertext too short"}
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "decryption failed", Err: err}
	}

	return plaintext, nil
}

// Hash computes a hash of the data.
func (e *AESEncryptor) Hash(data []byte, algorithm HashAlgorithm) string {
	switch algorithm {
	case HashSHA512:
		hash := sha512.Sum512(data)
		return hex.EncodeToString(hash[:])
	case HashSHA256:
		fallthrough
	default:
		hash := sha256.Sum256(data)
		return hex.EncodeToString(hash[:])
	}
}

// EncryptWithIV encrypts data and returns the IV/nonce as hex string.
func (e *AESEncryptor) EncryptWithIV(data []byte, keyHex string) ([]byte, string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", &ErrEncryptionFailed{Reason: "invalid key format", Err: err}
	}

	ciphertext, nonce, err := e.Encrypt(data, key)
	if err != nil {
		return nil, "", err
	}

	return ciphertext, hex.EncodeToString(nonce), nil
}

// DecryptWithIV decrypts data using hex-encoded key and IV.
func (e *AESEncryptor) DecryptWithIV(ciphertext []byte, keyHex, ivHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "invalid key format", Err: err}
	}

	nonce, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, &ErrDecryptionFailed{Reason: "invalid IV format", Err: err}
	}

	return e.Decrypt(ciphertext, key, nonce)
}
