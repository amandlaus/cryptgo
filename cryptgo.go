package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	numBytes  = 32
	nonceSize = 12 // AES-GCM typically uses a 12-byte nonce
)

type CryptGO struct {
	key        []byte
	fixedNonce []byte
}

type Options struct {
	Key        string
	FixedNonce string
}

func New(o *Options) (*CryptGO, error) {
	key, err := encryptionKeyStob(o.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cryptgo: %v", err)
	}

	fixedNonce, err := hex.DecodeString(o.FixedNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode fixed nonce: %v", err)
	}

	if len(fixedNonce) != nonceSize {
		return nil, fmt.Errorf("fixed nonce must be %d bytes long", nonceSize)
	}

	return &CryptGO{
		key:        key,
		fixedNonce: fixedNonce,
	}, nil
}

// encryptionKeyStob converts an encryption key from a string to a slice of bytes.
// "Stob" stands for string to bytes
func encryptionKeyStob(keyStr string) ([]byte, error) {
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %s", err)
	}

	if len(key) != numBytes {
		return nil, fmt.Errorf("encryption key must be %d bytes long", numBytes)
	}

	return key, nil
}

func (cg *CryptGO) EncryptAES(plaintext string) (string, error) {
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(cipherText), nil
}

func (cg *CryptGO) DecryptAES(ciphertext string) (string, error) {
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherTextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherTextBytes) < nonceSize {
		return "", errors.New("cipher text too short")
	}

	nonce, cipherTextBytes := cipherTextBytes[:nonceSize], cipherTextBytes[nonceSize:]
	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainTextBytes), nil
}

// EncryptAESFixedNonce encrypts plaintext using AES-GCM with a fixed nonce for deterministic encryption.
func (cg *CryptGO) EncryptAESFixedNonce(plaintext string) (string, error) {
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(cg.fixedNonce) != aesGCM.NonceSize() {
		return "", fmt.Errorf("fixed nonce must be %d bytes long", aesGCM.NonceSize())
	}

	cipherText := aesGCM.Seal(cg.fixedNonce, cg.fixedNonce, []byte(plaintext), nil)
	return hex.EncodeToString(cipherText), nil
}

// DecryptAESFixedNonce decrypts ciphertext encrypted with AES-GCM using the fixed nonce.
func (cg *CryptGO) DecryptAESFixedNonce(ciphertext string) (string, error) {
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherTextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(cipherTextBytes) < aesGCM.NonceSize() {
		return "", errors.New("cipher text too short")
	}

	nonce, cipherTextBytes := cipherTextBytes[:aesGCM.NonceSize()], cipherTextBytes[aesGCM.NonceSize():]
	if !equal(nonce, cg.fixedNonce) {
		return "", errors.New("nonce mismatch")
	}

	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainTextBytes), nil
}

// Helper function to compare byte slices
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
