// Package trojan implements the Trojan protocol encoding and decoding.
// Trojan is designed to bypass GFW by mimicking HTTPS traffic.
// It requires TLS for transport security.
package trojan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Command represents the Trojan command type
type Command byte

const (
	CommandTCP Command = 1
	CommandUDP Command = 3
)

// AddressType represents the address type
type AddressType byte

const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 3
	AddressTypeIPv6   AddressType = 4
)

// CRLF is the line ending used in Trojan protocol
var CRLF = []byte{0x0d, 0x0a}

// Request represents a Trojan request header
type Request struct {
	Password [56]byte // SHA224 hex encoded password
	Command  Command
	Address  string
	Port     uint16
}

// User represents a Trojan user
type User struct {
	Password     string
	PasswordHash [56]byte
	Email        string
	Level        int
}

// NewUser creates a new Trojan user with hashed password
func NewUser(password, email string, level int) *User {
	hash := sha256.Sum224([]byte(password))
	var passwordHash [56]byte
	hex.Encode(passwordHash[:], hash[:])

	return &User{
		Password:     password,
		PasswordHash: passwordHash,
		Email:        email,
		Level:        level,
	}
}

// Client represents a Trojan client
type Client struct {
	passwordHash [56]byte
}

// NewClient creates a new Trojan client
func NewClient(password string) *Client {
	hash := sha256.Sum224([]byte(password))
	var passwordHash [56]byte
	hex.Encode(passwordHash[:], hash[:])

	return &Client{
		passwordHash: passwordHash,
	}
}

// Dial connects to a Trojan server and returns a connection
func (c *Client) Dial(conn net.Conn, target string, port uint16, cmd Command) (net.Conn, error) {
	// Build and send request header
	header, err := c.buildRequestHeader(target, port, cmd)
	if err != nil {
		return nil, fmt.Errorf("build request header: %w", err)
	}

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("write request header: %w", err)
	}

	// Create Trojan connection
	trojanConn := &Conn{
		Conn:     conn,
		isClient: true,
	}

	return trojanConn, nil
}

// buildRequestHeader builds the Trojan request header
func (c *Client) buildRequestHeader(target string, port uint16, cmd Command) ([]byte, error) {
	var buf []byte

	// Password hash (56 bytes hex)
	buf = append(buf, c.passwordHash[:]...)

	// CRLF
	buf = append(buf, CRLF...)

	// Command (1 byte)
	buf = append(buf, byte(cmd))

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
		if len(target) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = append(buf, byte(AddressTypeDomain))
		buf = append(buf, byte(len(target)))
		buf = append(buf, []byte(target)...)
	}

	// Port (2 bytes, big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)

	// CRLF
	buf = append(buf, CRLF...)

	return buf, nil
}

// Server represents a Trojan server
type Server struct {
	users    map[[56]byte]*User
	usersMux sync.RWMutex
	fallback string // Fallback address for non-Trojan traffic
}

// NewServer creates a new Trojan server
func NewServer(fallback string) *Server {
	return &Server{
		users:    make(map[[56]byte]*User),
		fallback: fallback,
	}
}

// AddUser adds a user to the server
func (s *Server) AddUser(password, email string, level int) {
	user := NewUser(password, email, level)
	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	s.users[user.PasswordHash] = user
}

// RemoveUser removes a user from the server by password
func (s *Server) RemoveUser(password string) {
	hash := sha256.Sum224([]byte(password))
	var passwordHash [56]byte
	hex.Encode(passwordHash[:], hash[:])

	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	delete(s.users, passwordHash)
}

// GetUser gets a user by password hash
func (s *Server) GetUser(passwordHash [56]byte) (*User, bool) {
	s.usersMux.RLock()
	defer s.usersMux.RUnlock()
	user, ok := s.users[passwordHash]
	return user, ok
}

// HandleConnection handles an incoming Trojan connection
// Returns the request, user, connection, and any buffered data (for fallback)
func (s *Server) HandleConnection(conn net.Conn) (*Request, *User, net.Conn, []byte, error) {
	// Read password hash (56 bytes)
	passwordHashBuf := make([]byte, 56)
	if _, err := io.ReadFull(conn, passwordHashBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read password hash: %w", err)
	}

	var passwordHash [56]byte
	copy(passwordHash[:], passwordHashBuf)

	// Verify user
	user, ok := s.GetUser(passwordHash)
	if !ok {
		// Return buffered data for fallback handling
		return nil, nil, nil, passwordHashBuf, errors.New("user not found")
	}

	// Read CRLF
	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, crlfBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read CRLF: %w", err)
	}
	if crlfBuf[0] != CRLF[0] || crlfBuf[1] != CRLF[1] {
		return nil, nil, nil, nil, errors.New("invalid CRLF after password")
	}

	// Read command (1 byte)
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read command: %w", err)
	}
	cmd := Command(cmdBuf[0])

	// Read address type (1 byte)
	addrTypeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, addrTypeBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read address type: %w", err)
	}
	addrType := AddressType(addrTypeBuf[0])

	// Read address
	var address string
	switch addrType {
	case AddressTypeIPv4:
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeIPv6:
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeDomain:
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLenBuf); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(domainLenBuf[0])

		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read domain: %w", err)
		}
		address = string(domainBuf)

	default:
		return nil, nil, nil, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	// Read port (2 bytes)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Read CRLF
	if _, err := io.ReadFull(conn, crlfBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read final CRLF: %w", err)
	}
	if crlfBuf[0] != CRLF[0] || crlfBuf[1] != CRLF[1] {
		return nil, nil, nil, nil, errors.New("invalid final CRLF")
	}

	req := &Request{
		Password: passwordHash,
		Command:  cmd,
		Address:  address,
		Port:     port,
	}

	// Create Trojan connection
	trojanConn := &Conn{
		Conn:     conn,
		isClient: false,
	}

	return req, user, trojanConn, nil, nil
}

// GetFallback returns the fallback address
func (s *Server) GetFallback() string {
	return s.fallback
}

// Conn represents a Trojan connection
// After the handshake, it's just a raw TCP connection
type Conn struct {
	net.Conn
	isClient bool
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

// UDPPacket represents a Trojan UDP packet
type UDPPacket struct {
	Address string
	Port    uint16
	Length  uint16
	Data    []byte
}

// EncodeUDPPacket encodes a UDP packet for Trojan protocol
func EncodeUDPPacket(address string, port uint16, data []byte) ([]byte, error) {
	var buf []byte

	// Address type and address
	ip := net.ParseIP(address)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, byte(AddressTypeIPv4))
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, byte(AddressTypeIPv6))
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(address) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = append(buf, byte(AddressTypeDomain))
		buf = append(buf, byte(len(address)))
		buf = append(buf, []byte(address)...)
	}

	// Port (2 bytes, big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)

	// Length (2 bytes, big endian)
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(data)))
	buf = append(buf, lengthBytes...)

	// CRLF
	buf = append(buf, CRLF...)

	// Data
	buf = append(buf, data...)

	return buf, nil
}

// DecodeUDPPacket decodes a UDP packet from Trojan protocol
func DecodeUDPPacket(r io.Reader) (*UDPPacket, error) {
	// Read address type (1 byte)
	addrTypeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, addrTypeBuf); err != nil {
		return nil, fmt.Errorf("read address type: %w", err)
	}
	addrType := AddressType(addrTypeBuf[0])

	// Read address
	var address string
	switch addrType {
	case AddressTypeIPv4:
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeIPv6:
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeDomain:
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, domainLenBuf); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(domainLenBuf[0])

		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		address = string(domainBuf)

	default:
		return nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	// Read port (2 bytes)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Read length (2 bytes)
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint16(lengthBuf)

	// Read CRLF
	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlfBuf); err != nil {
		return nil, fmt.Errorf("read CRLF: %w", err)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	return &UDPPacket{
		Address: address,
		Port:    port,
		Length:  length,
		Data:    data,
	}, nil
}

// HashPassword returns the SHA224 hex hash of a password
func HashPassword(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}
