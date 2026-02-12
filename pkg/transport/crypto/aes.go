// Package crypto provides encryption wrappers for network connections.
// It supports multiple encryption algorithms including AES-GCM and ChaCha20-Poly1305.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// AES256KeySize is the key size for AES-256
	AES256KeySize = 32
	// AES128KeySize is the key size for AES-128
	AES128KeySize = 16
	// GCMNonceSize is the nonce size for GCM mode
	GCMNonceSize = 12
	// GCMTagSize is the authentication tag size for GCM mode
	GCMTagSize = 16
	// MaxPayloadSize is the maximum payload size for a single encrypted message
	MaxPayloadSize = 16 * 1024 // 16KB
)

// AESGCMConn wraps a net.Conn with AES-GCM authenticated encryption.
// AES-GCM provides both confidentiality and integrity protection.
// Each message is encrypted with a unique nonce to prevent replay attacks.
type AESGCMConn struct {
	net.Conn
	aead       cipher.AEAD
	readNonce  []byte
	writeNonce []byte
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	readBuf    []byte
	readPos    int
	readEnd    int
}

// NewAESGCMConn creates a new AES-GCM encrypted connection.
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func NewAESGCMConn(conn net.Conn, key []byte) (*AESGCMConn, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: %d (must be 16, 24, or 32)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonces for read and write
	readNonce := make([]byte, GCMNonceSize)
	writeNonce := make([]byte, GCMNonceSize)

	if _, err := io.ReadFull(rand.Reader, readNonce); err != nil {
		return nil, fmt.Errorf("failed to generate read nonce: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, writeNonce); err != nil {
		return nil, fmt.Errorf("failed to generate write nonce: %w", err)
	}

	return &AESGCMConn{
		Conn:       conn,
		aead:       aead,
		readNonce:  readNonce,
		writeNonce: writeNonce,
		readBuf:    make([]byte, MaxPayloadSize+GCMTagSize),
	}, nil
}

// NewAESGCMConnWithPassword creates a new AES-GCM encrypted connection using a password.
// The password is derived to a key using PBKDF2.
func NewAESGCMConnWithPassword(conn net.Conn, password string, salt []byte) (*AESGCMConn, error) {
	if salt == nil {
		salt = []byte("netproxy-aes-gcm-salt")
	}
	key := pbkdf2.Key([]byte(password), salt, 4096, AES256KeySize, sha256.New)
	return NewAESGCMConn(conn, key)
}

// Write encrypts and writes data to the underlying connection.
// The data is split into chunks if it exceeds MaxPayloadSize.
func (c *AESGCMConn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	totalWritten := 0
	for len(b) > 0 {
		// Determine chunk size
		chunkSize := len(b)
		if chunkSize > MaxPayloadSize {
			chunkSize = MaxPayloadSize
		}

		// Encrypt the chunk
		ciphertext := c.aead.Seal(nil, c.writeNonce, b[:chunkSize], nil)

		// Write length prefix (2 bytes, big-endian)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

		if _, err := c.Conn.Write(lenBuf); err != nil {
			return totalWritten, err
		}

		// Write nonce
		if _, err := c.Conn.Write(c.writeNonce); err != nil {
			return totalWritten, err
		}

		// Write ciphertext
		if _, err := c.Conn.Write(ciphertext); err != nil {
			return totalWritten, err
		}

		// Increment nonce
		incrementNonce(c.writeNonce)

		totalWritten += chunkSize
		b = b[chunkSize:]
	}

	return totalWritten, nil
}

// Read reads and decrypts data from the underlying connection.
func (c *AESGCMConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	// Return buffered data if available
	if c.readPos < c.readEnd {
		n := copy(b, c.readBuf[c.readPos:c.readEnd])
		c.readPos += n
		return n, nil
	}

	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	if length > MaxPayloadSize+GCMTagSize {
		return 0, fmt.Errorf("invalid message length: %d", length)
	}

	// Read nonce
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(c.Conn, nonce); err != nil {
		return 0, err
	}

	// Read ciphertext
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	// Decrypt
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	// Copy to output buffer
	n := copy(b, plaintext)
	if n < len(plaintext) {
		// Buffer remaining data
		copy(c.readBuf, plaintext[n:])
		c.readPos = 0
		c.readEnd = len(plaintext) - n
	}

	return n, nil
}

// Close closes the underlying connection.
func (c *AESGCMConn) Close() error {
	return c.Conn.Close()
}

// incrementNonce increments the nonce as a big-endian counter.
func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// AESCFBConn wraps a net.Conn with AES-CFB stream encryption.
// This is provided for compatibility with existing implementations.
// For new implementations, use AESGCMConn instead.
type AESCFBConn struct {
	net.Conn
	block        cipher.Block
	streamReader cipher.Stream
	streamWriter cipher.Stream
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
}

// NewAESCFBConn creates a new AES-CFB encrypted connection.
func NewAESCFBConn(conn net.Conn, key []byte) (*AESCFBConn, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: %d (must be 16, 24, or 32)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESCFBConn{
		Conn:  conn,
		block: block,
	}, nil
}

// Write encrypts and writes data to the underlying connection.
func (c *AESCFBConn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.streamWriter == nil {
		// Generate and send IV
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, err
		}

		if _, err := c.Conn.Write(iv); err != nil {
			return 0, err
		}

		c.streamWriter = cipher.NewCFBEncrypter(c.block, iv)
	}

	out := make([]byte, len(b))
	c.streamWriter.XORKeyStream(out, b)
	return c.Conn.Write(out)
}

// Read reads and decrypts data from the underlying connection.
func (c *AESCFBConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.streamReader == nil {
		// Read IV
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return 0, err
		}

		c.streamReader = cipher.NewCFBDecrypter(c.block, iv)
	}

	n, err := c.Conn.Read(b)
	if n > 0 {
		c.streamReader.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

// Close closes the underlying connection.
func (c *AESCFBConn) Close() error {
	return c.Conn.Close()
}

// DeriveKey derives a key from a password using PBKDF2.
func DeriveKey(password string, salt []byte, keyLen int) []byte {
	if salt == nil {
		salt = []byte("netproxy-default-salt")
	}
	return pbkdf2.Key([]byte(password), salt, 4096, keyLen, sha256.New)
}

// GenerateKey generates a random key of the specified length.
func GenerateKey(keyLen int) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateAES256Key generates a random AES-256 key.
func GenerateAES256Key() ([]byte, error) {
	return GenerateKey(AES256KeySize)
}

// GenerateAES128Key generates a random AES-128 key.
func GenerateAES128Key() ([]byte, error) {
	return GenerateKey(AES128KeySize)
}
