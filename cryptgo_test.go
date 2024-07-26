package cryptgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// An example 32-byte hex key
	encryptionKey = "76a91c59564bd56132304a9fd65913ac96012689f1ab39b9d04e941cda00f08f"

	// An example 12-byte fixed nonce for deterministic encryption
	fixedNonce = "203095d2a50cdbd777b5d8d7"

	plaintext = "Hello, World!"
)

func TestNew(t *testing.T) {
	var cases = []struct {
		name       string
		key        string
		shouldFail bool
	}{
		{
			name:       "will succeed",
			key:        encryptionKey,
			shouldFail: false,
		},
		{
			name:       "will fail",
			key:        "bad_key",
			shouldFail: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(&Options{
				Key:        c.key,
				FixedNonce: fixedNonce,
			})

			if c.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCryptGOEncryptAES(t *testing.T) {
	cg, err := New(&Options{
		Key:        encryptionKey,
		FixedNonce: fixedNonce,
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i+1), func(t *testing.T) {
			output, err := cg.EncryptAES(plaintext)
			assert.NoError(t, err)

			t.Logf("Encrypted output: %s", output)
		})
	}
}

func TestCryptGODecryptAES(t *testing.T) {
	cg, err := New(&Options{
		Key:        encryptionKey,
		FixedNonce: fixedNonce,
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i+1), func(t *testing.T) {
			ct, err := cg.EncryptAES(plaintext)
			assert.NoError(t, err)

			t.Logf("Encrypted output: %s", ct)

			decryptedOutput, err := cg.DecryptAES(ct)
			assert.NoError(t, err)

			t.Logf("Decrypted output: %s", decryptedOutput)
		})
	}
}

func TestCryptGOEncryptAESFixedNonce(t *testing.T) {
	cg, err := New(&Options{
		Key:        encryptionKey,
		FixedNonce: fixedNonce,
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i+1), func(t *testing.T) {
			output, err := cg.EncryptAESFixedNonce(plaintext)
			assert.NoError(t, err)

			t.Logf("Encrypted output: %s", output)
		})
	}
}

func TestCryptGODecryptAESFixedNonce(t *testing.T) {
	cg, err := New(&Options{
		Key:        encryptionKey,
		FixedNonce: fixedNonce,
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i+1), func(t *testing.T) {
			ct, err := cg.EncryptAESFixedNonce(plaintext)
			assert.NoError(t, err)

			t.Logf("Encrypted output: %s", ct)

			decryptedOutput, err := cg.DecryptAESFixedNonce(ct)
			assert.NoError(t, err)

			t.Logf("Decrypted output: %s", decryptedOutput)
		})
	}
}
