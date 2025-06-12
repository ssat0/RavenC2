package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
)

// StringEncryptor structure
type StringEncryptor struct {
	enabled bool
	key     []byte
}

func NewStringEncryptor() (*StringEncryptor, error) {
	// Create 256-bit (32 byte) key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("key generation error: %v", err)
	}

	return &StringEncryptor{
		enabled: true,
		key:     key,
	}, nil
}

// Encryption function
func (e *StringEncryptor) Encrypt(plaintext string) (string, error) {
	if !e.enabled {
		return plaintext, nil
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decryption function
func (e *StringEncryptor) Decrypt(ciphertext string) (string, error) {
	if !e.enabled {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Enable/Disable functions
func (e *StringEncryptor) Enable()  { e.enabled = true }
func (e *StringEncryptor) Disable() { e.enabled = false }

// Wrapper for encrypted reading
type EncryptedReader struct {
	conn      net.Conn
	encryptor *StringEncryptor
}

func (e *EncryptedReader) Read(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	n, err = e.conn.Read(buf)
	if err != nil {
		return 0, err
	}

	decrypted, err := e.encryptor.Decrypt(string(buf[:n]))
	if err != nil {
		return 0, err
	}

	copy(p, []byte(decrypted))
	return len(decrypted), nil
}

// Wrapper for encrypted writing
type EncryptedWriter struct {
	conn      net.Conn
	encryptor *StringEncryptor
}

func (e *EncryptedWriter) Write(p []byte) (n int, err error) {
	encrypted, err := e.encryptor.Encrypt(string(p))
	if err != nil {
		return 0, err
	}

	return e.conn.Write([]byte(encrypted))
}
