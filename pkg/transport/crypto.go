package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// CryptoConn wraps a net.Conn with encryption
type CryptoConn struct {
	net.Conn
	key          []byte
	block        cipher.Block
	streamReader cipher.Stream
	streamWriter cipher.Stream
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
}

// NewCryptoConn creates a new encrypted connection using AES-256-CFB
func NewCryptoConn(conn net.Conn, key []byte) (net.Conn, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &CryptoConn{
		Conn:  conn,
		key:   key,
		block: block,
	}, nil
}

// Write wraps the write operation with encryption
func (c *CryptoConn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.streamWriter == nil {
		// Initialize Write Stream
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, err
		}
		
		// Write IV first
		if _, err := c.Conn.Write(iv); err != nil {
			return 0, err
		}
		
		c.streamWriter = cipher.NewCFBEncrypter(c.block, iv)
	}

	out := make([]byte, len(b))
	c.streamWriter.XORKeyStream(out, b)
	return c.Conn.Write(out)
}

// Read wraps the read operation with decryption
func (c *CryptoConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.streamReader == nil {
		// Initialize Read Stream
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
