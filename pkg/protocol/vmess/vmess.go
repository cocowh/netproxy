// Package vmess implements the VMess protocol encoding and decoding.
// VMess is a protocol designed for encrypted communication.
package vmess
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)
// Security represents the encryption method
type Security byte

const (
	SecurityAES128GCM        Security = 3
	SecurityChacha20Poly1305 Security = 4
	SecurityNone             Security = 5
	SecurityZero             Security = 0
)

// Command represents the VMess command type
type Command byte

const (
	CommandTCP Command = 1
	CommandUDP Command = 2
)

// AddressType represents the address type
type AddressType byte

const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 2
	AddressTypeIPv6   AddressType = 3
)

// User represents a VMess user
type User struct {
	UUID    [16]byte
	AlterID uint16
}

// Request represents a VMess request header
type Request struct {
	Version  byte
	Command  Command
	Security Security
	Address  string
	Port     uint16
	User     *User
}

// Response represents a VMess response header
type Response struct {
	ResponseHeader byte
	Command        byte
}

// Client represents a VMess client
type Client struct {
	user     *User
	security Security
}

// NewClient creates a new VMess client
func NewClient(uuid [16]byte, alterID uint16, security Security) *Client {
	return &Client{
		user: &User{
			UUID:    uuid,
			AlterID: alterID,
		},
		security: security,
	}
}

// Dial connects to a VMess server and returns a connection
func (c *Client) Dial(conn net.Conn, target string, port uint16, cmd Command) (net.Conn, error) {
	// Generate request key and IV
	reqKey := make([]byte, 16)
	reqIV := make([]byte, 16)
	if _, err := crand.Read(reqKey); err != nil {
		return nil, fmt.Errorf("generate request key: %w", err)
	}
	if _, err := crand.Read(reqIV); err != nil {
		return nil, fmt.Errorf("generate request IV: %w", err)
	}

	// Generate response key and IV from request key and IV
	respKey := md5Hash(reqKey)
	respIV := md5Hash(reqIV)

	// Build and send request header
	header, err := c.buildRequestHeader(reqKey, reqIV, target, port, cmd)
	if err != nil {
		return nil, fmt.Errorf("build request header: %w", err)
	}

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("write request header: %w", err)
	}

	// Create VMess connection
	vmessConn := &Conn{
		Conn:     conn,
		reqKey:   reqKey,
		reqIV:    reqIV,
		respKey:  respKey,
		respIV:   respIV,
		security: c.security,
		isClient: true,
	}

	if err := vmessConn.initCipher(); err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}

	return vmessConn, nil
}

// buildRequestHeader builds the VMess request header
func (c *Client) buildRequestHeader(reqKey, reqIV []byte, target string, port uint16, cmd Command) ([]byte, error) {
	// Generate timestamp
	timestamp := time.Now().Unix()

	// Generate auth info using HMAC-MD5
	authInfo := generateAuthInfo(c.user.UUID[:], timestamp)

	// Build request body
	var buf []byte
	buf = append(buf, 1) // Version

	// Request IV and Key
	buf = append(buf, reqIV...)
	buf = append(buf, reqKey...)

	// Response header (V)
	responseHeader := byte(rand.Intn(256))
	buf = append(buf, responseHeader)

	// Option
	buf = append(buf, 0x01) // Standard format

	// Padding length and security
	paddingLen := byte(rand.Intn(16))
	buf = append(buf, (paddingLen<<4)|byte(c.security))

	// Reserved
	buf = append(buf, 0)

	// Command
	buf = append(buf, byte(cmd))

	// Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)

	// Address type and address
	ip := net.ParseIP(target)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, byte(AddressTypeIPv4))
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, byte(AddressTypeIPv6))
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, byte(AddressTypeDomain))
		buf = append(buf, byte(len(target)))
		buf = append(buf, []byte(target)...)
	}

	// Padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		crand.Read(padding)
		buf = append(buf, padding...)
	}

	// FNV1a hash for integrity
	fnvHash := fnv.New32a()
	fnvHash.Write(buf)
	buf = append(buf, fnvHash.Sum(nil)...)

	// Encrypt request body
	cmdKey := generateCmdKey(c.user.UUID[:])
	encryptedBody, err := aesEncrypt(cmdKey, authInfo, buf)
	if err != nil {
		return nil, fmt.Errorf("encrypt request body: %w", err)
	}

	// Final header: auth info + encrypted body
	header := append(authInfo, encryptedBody...)
	return header, nil
}

// Server represents a VMess server
type Server struct {
	users    map[[16]byte]*User
	usersMux sync.RWMutex
}

// NewServer creates a new VMess server
func NewServer() *Server {
	return &Server{
		users: make(map[[16]byte]*User),
	}
}

// AddUser adds a user to the server
func (s *Server) AddUser(uuid [16]byte, alterID uint16) {
	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	s.users[uuid] = &User{
		UUID:    uuid,
		AlterID: alterID,
	}
}

// RemoveUser removes a user from the server
func (s *Server) RemoveUser(uuid [16]byte) {
	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	delete(s.users, uuid)
}

// HandleConnection handles an incoming VMess connection
func (s *Server) HandleConnection(conn net.Conn) (*Request, net.Conn, error) {
	// Read auth info (16 bytes)
	authInfo := make([]byte, 16)
	if _, err := io.ReadFull(conn, authInfo); err != nil {
		return nil, nil, fmt.Errorf("read auth info: %w", err)
	}

	// Find user by auth info
	user, timestamp, err := s.findUserByAuth(authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("find user: %w", err)
	}

	// Read encrypted header length (we need to try different lengths)
	// In practice, we read a reasonable amount and try to decrypt
	encryptedHeader := make([]byte, 512)
	n, err := conn.Read(encryptedHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("read encrypted header: %w", err)
	}
	encryptedHeader = encryptedHeader[:n]

	// Decrypt header
	cmdKey := generateCmdKey(user.UUID[:])
	header, err := aesDecrypt(cmdKey, authInfo, encryptedHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt header: %w", err)
	}

	// Parse header
	req, reqKey, reqIV, err := s.parseRequestHeader(header, user, timestamp)
	if err != nil {
		return nil, nil, fmt.Errorf("parse header: %w", err)
	}

	// Generate response key and IV
	respKey := md5Hash(reqKey)
	respIV := md5Hash(reqIV)

	// Create VMess connection
	vmessConn := &Conn{
		Conn:     conn,
		reqKey:   reqKey,
		reqIV:    reqIV,
		respKey:  respKey,
		respIV:   respIV,
		security: req.Security,
		isClient: false,
	}

	if err := vmessConn.initCipher(); err != nil {
		return nil, nil, fmt.Errorf("init cipher: %w", err)
	}

	return req, vmessConn, nil
}

// findUserByAuth finds a user by auth info
func (s *Server) findUserByAuth(authInfo []byte) (*User, int64, error) {
	s.usersMux.RLock()
	defer s.usersMux.RUnlock()

	now := time.Now().Unix()
	// Check timestamps within 120 seconds window
	for delta := int64(-60); delta <= 60; delta++ {
		timestamp := now + delta
		for _, user := range s.users {
			expectedAuth := generateAuthInfo(user.UUID[:], timestamp)
			if hmac.Equal(authInfo, expectedAuth) {
				return user, timestamp, nil
			}
		}
	}

	return nil, 0, errors.New("user not found")
}

// parseRequestHeader parses the decrypted request header
func (s *Server) parseRequestHeader(header []byte, user *User, timestamp int64) (*Request, []byte, []byte, error) {
	if len(header) < 41 {
		return nil, nil, nil, errors.New("header too short")
	}

	pos := 0

	// Version
	version := header[pos]
	pos++

	// Request IV (16 bytes)
	reqIV := header[pos : pos+16]
	pos += 16

	// Request Key (16 bytes)
	reqKey := header[pos : pos+16]
	pos += 16

	// Response header (V)
	_ = header[pos] // responseHeader
	pos++

	// Option
	_ = header[pos] // option
	pos++

	// Padding length and security
	paddingAndSecurity := header[pos]
	paddingLen := paddingAndSecurity >> 4
	security := Security(paddingAndSecurity & 0x0F)
	pos++

	// Reserved
	pos++

	// Command
	cmd := Command(header[pos])
	pos++

	// Port
	port := binary.BigEndian.Uint16(header[pos : pos+2])
	pos += 2

	// Address type
	addrType := AddressType(header[pos])
	pos++

	// Address
	var address string
	switch addrType {
	case AddressTypeIPv4:
		if pos+4 > len(header) {
			return nil, nil, nil, errors.New("invalid IPv4 address")
		}
		address = net.IP(header[pos : pos+4]).String()
		pos += 4
	case AddressTypeIPv6:
		if pos+16 > len(header) {
			return nil, nil, nil, errors.New("invalid IPv6 address")
		}
		address = net.IP(header[pos : pos+16]).String()
		pos += 16
	case AddressTypeDomain:
		domainLen := int(header[pos])
		pos++
		if pos+domainLen > len(header) {
			return nil, nil, nil, errors.New("invalid domain")
		}
		address = string(header[pos : pos+domainLen])
		pos += domainLen
	default:
		return nil, nil, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	// Skip padding
	pos += int(paddingLen)

	// Verify FNV1a hash
	if pos+4 > len(header) {
		return nil, nil, nil, errors.New("missing FNV hash")
	}
	expectedHash := header[pos : pos+4]
	fnvHash := fnv.New32a()
	fnvHash.Write(header[:pos])
	if !hmac.Equal(fnvHash.Sum(nil), expectedHash) {
		return nil, nil, nil, errors.New("FNV hash mismatch")
	}

	req := &Request{
		Version:  version,
		Command:  cmd,
		Security: security,
		Address:  address,
		Port:     port,
		User:     user,
	}

	return req, reqKey, reqIV, nil
}

// Conn represents a VMess connection
type Conn struct {
	net.Conn
	reqKey   []byte
	reqIV    []byte
	respKey  []byte
	respIV   []byte
	security Security
	isClient bool

	readCipher  cipher.AEAD
	writeCipher cipher.AEAD
	readNonce   []byte
	writeNonce  []byte
	readMux     sync.Mutex
	writeMux    sync.Mutex

	readBuf  []byte
	readPos  int
	readEnd  int
}

// initCipher initializes the encryption ciphers
func (c *Conn) initCipher() error {
	var readKey, writeKey []byte
	var readIV, writeIV []byte

	if c.isClient {
		writeKey = c.reqKey
		writeIV = c.reqIV
		readKey = c.respKey
		readIV = c.respIV
	} else {
		readKey = c.reqKey
		readIV = c.reqIV
		writeKey = c.respKey
		writeIV = c.respIV
	}

	switch c.security {
	case SecurityAES128GCM:
		readBlock, err := aes.NewCipher(readKey)
		if err != nil {
			return err
		}
		c.readCipher, err = cipher.NewGCM(readBlock)
		if err != nil {
			return err
		}

		writeBlock, err := aes.NewCipher(writeKey)
		if err != nil {
			return err
		}
		c.writeCipher, err = cipher.NewGCM(writeBlock)
		if err != nil {
			return err
		}

		c.readNonce = make([]byte, c.readCipher.NonceSize())
		c.writeNonce = make([]byte, c.writeCipher.NonceSize())
		copy(c.readNonce, readIV[:c.readCipher.NonceSize()])
		copy(c.writeNonce, writeIV[:c.writeCipher.NonceSize()])

	case SecurityChacha20Poly1305:
		// Generate 32-byte key from 16-byte key
		readKey32 := generateChaChaKey(readKey)
		writeKey32 := generateChaChaKey(writeKey)

		var err error
		c.readCipher, err = chacha20poly1305.New(readKey32)
		if err != nil {
			return err
		}
		c.writeCipher, err = chacha20poly1305.New(writeKey32)
		if err != nil {
			return err
		}

		c.readNonce = make([]byte, c.readCipher.NonceSize())
		c.writeNonce = make([]byte, c.writeCipher.NonceSize())
		copy(c.readNonce, readIV[:c.readCipher.NonceSize()])
		copy(c.writeNonce, writeIV[:c.writeCipher.NonceSize()])

	case SecurityNone, SecurityZero:
		// No encryption needed
	default:
		return fmt.Errorf("unsupported security: %d", c.security)
	}

	return nil
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (int, error) {
	c.readMux.Lock()
	defer c.readMux.Unlock()

	// Return buffered data first
	if c.readPos < c.readEnd {
		n := copy(b, c.readBuf[c.readPos:c.readEnd])
		c.readPos += n
		return n, nil
	}

	if c.security == SecurityNone || c.security == SecurityZero {
		return c.Conn.Read(b)
	}

	// Read length (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
		return 0, err
	}

	// Decrypt
	decrypted, err := c.readCipher.Open(nil, c.readNonce, encrypted, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	// Increment nonce
	incrementNonce(c.readNonce)

	// Buffer the decrypted data
	c.readBuf = decrypted
	c.readPos = 0
	c.readEnd = len(decrypted)

	n := copy(b, c.readBuf[c.readPos:c.readEnd])
	c.readPos += n
	return n, nil
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMux.Lock()
	defer c.writeMux.Unlock()

	if c.security == SecurityNone || c.security == SecurityZero {
		return c.Conn.Write(b)
	}

	// Encrypt data
	encrypted := c.writeCipher.Seal(nil, c.writeNonce, b, nil)

	// Increment nonce
	incrementNonce(c.writeNonce)

	// Write length + encrypted data
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(encrypted)))

	if _, err := c.Conn.Write(lenBuf); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Helper functions

func generateAuthInfo(uuid []byte, timestamp int64) []byte {
	h := hmac.New(md5.New, uuid)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	h.Write(ts)
	return h.Sum(nil)
}

func generateCmdKey(uuid []byte) []byte {
	h := md5.New()
	h.Write(uuid)
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return h.Sum(nil)
}

func md5Hash(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func generateChaChaKey(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}

func aesEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad plaintext to block size
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(ciphertext, padded)

	return ciphertext, nil
}

func aesDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(plaintext, ciphertext)

	// Remove padding
	if len(plaintext) > 0 {
		padding := int(plaintext[len(plaintext)-1])
		if padding > 0 && padding <= aes.BlockSize {
			plaintext = plaintext[:len(plaintext)-padding]
		}
	}

	return plaintext, nil
}

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// ParseUUID parses a UUID string into bytes
func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	if len(s) != 36 {
		return uuid, errors.New("invalid UUID length")
	}

	// Remove hyphens and parse
	hex := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if len(hex) != 32 {
		return uuid, errors.New("invalid UUID format")
	}

	for i := 0; i < 16; i++ {
		var b byte
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("invalid UUID hex: %w", err)
		}
		uuid[i] = b
	}

	return uuid, nil
}
