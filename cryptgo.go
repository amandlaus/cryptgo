package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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
	funcname := "cryptgo.New"
	key, err := encryptionKeyStob(o.Key)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to initialize cryptgo: %w", funcname, err)
	}

	fixedNonce, err := hex.DecodeString(o.FixedNonce)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to decode fixed nonce: %w", funcname, err)
	}

	if len(fixedNonce) != nonceSize {
		return nil, fmt.Errorf("%s: fixed nonce must be %d bytes long", funcname, nonceSize)
	}

	return &CryptGO{
		key:        key,
		fixedNonce: fixedNonce,
	}, nil
}

// encryptionKeyStob converts an encryption key from a string to a slice of bytes.
// "Stob" stands for string to bytes
func encryptionKeyStob(keyStr string) ([]byte, error) {
	funcname := "cryptgo.encryptionKeyStob"
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to decode encryption key: %w", funcname, err)
	}

	if len(key) != numBytes {
		return nil, fmt.Errorf("%s: encryption key must be %d bytes long", funcname, numBytes)
	}

	return key, nil
}

func (cg *CryptGO) EncryptAES(plaintext string) (string, error) {
	funcname := "cryptgo.CryptGO.EncryptAES"
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES cipher with key: %w", funcname, err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES-GCM mode: %w", funcname, err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%s: failed to generate nonce: %w", funcname, err)
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(cipherText), nil
}

func (cg *CryptGO) DecryptAES(ciphertext string) (string, error) {
	funcname := "cryptgo.CryptGO.DecryptAES"
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES cipher with key: %w", funcname, err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES-GCM mode: %w", funcname, err)
	}

	cipherTextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%s: failed to decode hex cipher text: %w", funcname, err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherTextBytes) < nonceSize {
		return "", fmt.Errorf("%s: cipher text too short, got %d bytes but expected at least %d", funcname, len(cipherTextBytes), nonceSize)
	}

	nonce, cipherTextBytes := cipherTextBytes[:nonceSize], cipherTextBytes[nonceSize:]
	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%s: decryption failed with provided cipher text and nonce: %w", funcname, err)
	}

	return string(plainTextBytes), nil
}

// EncryptAESFixedNonce encrypts plaintext using AES-GCM with a fixed nonce for deterministic encryption.
func (cg *CryptGO) EncryptAESFixedNonce(plaintext string) (string, error) {
	funcname := "cryptgo.CryptGO.EncryptAESFixedNonce"
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES cipher with key: %w", funcname, err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES-GCM mode: %w", funcname, err)
	}

	if len(cg.fixedNonce) != aesGCM.NonceSize() {
		return "", fmt.Errorf("%s: fixed nonce size mismatch, got %d bytes but expected %d", funcname, len(cg.fixedNonce), aesGCM.NonceSize())
	}

	cipherText := aesGCM.Seal(cg.fixedNonce, cg.fixedNonce, []byte(plaintext), nil)
	return hex.EncodeToString(cipherText), nil
}

// DecryptAESFixedNonce decrypts ciphertext encrypted with AES-GCM using the fixed nonce.
func (cg *CryptGO) DecryptAESFixedNonce(ciphertext string) (string, error) {
	funcname := "cryptgo.CryptGO.DecryptAESFixedNonce"
	block, err := aes.NewCipher(cg.key)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES cipher with key: %w", funcname, err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%s: failed to create AES-GCM mode: %w", funcname, err)
	}

	cipherTextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%s: failed to decode hex cipher text: %w", funcname, err)
	}

	if len(cipherTextBytes) < aesGCM.NonceSize() {
		return "", fmt.Errorf("%s: cipher text too short, got %d bytes but expected at least %d", funcname, len(cipherTextBytes), aesGCM.NonceSize())
	}

	nonce, cipherTextBytes := cipherTextBytes[:aesGCM.NonceSize()], cipherTextBytes[aesGCM.NonceSize():]
	if !equal(nonce, cg.fixedNonce) {
		return "", fmt.Errorf("%s: nonce mismatch, expected fixed nonce but got a different one", funcname)
	}

	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%s: decryption failed with provided cipher text and nonce: %w", funcname, err)
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
