package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// EncryptRefreshToken encrypts a refresh token using AES-GCM
func EncryptRefreshToken(token string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY")) // Get AES key from env

	// Debugging: Print key length
	fmt.Println("🔍 Debug: ENCRYPTION_KEY length:", len(key))

	// Validate key length
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Println("❌ Debug: INVALID AES KEY SIZE:", len(key))
		return "", errors.New("invalid AES key size")
	}

	block, err := aes.NewCipher(key)
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

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(token), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptRefreshToken decrypts a refresh token
func DecryptRefreshToken(encryptedToken string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY")) // 32-byte AES key (must be securely stored)
	data, err := base64.StdEncoding.DecodeString(encryptedToken)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
