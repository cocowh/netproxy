// Package vless implements the VLESS protocol encoding and decoding.
// VLESS is a lightweight protocol without built-in encryption,
// designed to be used with TLS for security.
package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Version is the VLESS protocol version
const Version byte = 0

// Command represents the VLESS command type
type Command byte

const (
	CommandTCP Command = 1
	CommandUDP Command = 2
	CommandMux Command = 3
)

// AddressType represents the address type
type AddressType byte

const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 2
	AddressTypeIPv6   AddressType = 3
)

// Request represents a VLESS request header
type Request struct {
	Version  byte
	UUID     [16]byte
	Command  Command
	Address  string
	Port     uint16
	Addons   []byte
}

// Response represents a VLESS response header
type Response struct {
	Version byte
	Addons  []byte
}

// User represents a VLESS user
type User struct {
	UUID  [16]byte
	Email string
	Level int
}

// Client represents a VLESS client
type Client struct {
	uuid [16]byte
}

// NewClient creates a new VLESS client
func NewClient(uuid [16]byte) *Client {
	return &Client{
		uuid: uuid,
	}
}

// Dial connects to a VLESS server and returns a connection
func (c *Client) Dial(conn net.Conn, target string, port uint16, cmd Command) (net.Conn, error) {
	// Build and send request header
	header, err := c.buildRequestHeader(target, port, cmd)
	if err != nil {
		return nil, fmt.Errorf("build request header: %w", err)
	}

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("write request header: %w", err)
	}

	// Create VLESS connection
	vlessConn := &Conn{
		Conn:           conn,
		isClient:       true,
		responseRead:   false,
	}

	return vlessConn, nil
}

// buildRequestHeader builds the VLESS request header
func (c *Client) buildRequestHeader(target string, port uint16, cmd Command) ([]byte, error) {
	var buf []byte

	// Version (1 byte)
	buf = append(buf, Version)

	// UUID (16 bytes)
	buf = append(buf, c.uuid[:]...)

	// Addons length (1 byte) - no addons for now
	buf = append(buf, 0)

	// Command (1 byte)
	buf = append(buf, byte(cmd))

	// Port (2 bytes, big endian)
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
		if len(target) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = append(buf, byte(AddressTypeDomain))
		buf = append(buf, byte(len(target)))
		buf = append(buf, []byte(target)...)
	}

	return buf, nil
}

// Server represents a VLESS server
type Server struct {
	users    map[[16]byte]*User
	usersMux sync.RWMutex
}

// NewServer creates a new VLESS server
func NewServer() *Server {
	return &Server{
		users: make(map[[16]byte]*User),
	}
}

// AddUser adds a user to the server
func (s *Server) AddUser(uuid [16]byte, email string, level int) {
	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	s.users[uuid] = &User{
		UUID:  uuid,
		Email: email,
		Level: level,
	}
}

// RemoveUser removes a user from the server
func (s *Server) RemoveUser(uuid [16]byte) {
	s.usersMux.Lock()
	defer s.usersMux.Unlock()
	delete(s.users, uuid)
}

// GetUser gets a user by UUID
func (s *Server) GetUser(uuid [16]byte) (*User, bool) {
	s.usersMux.RLock()
	defer s.usersMux.RUnlock()
	user, ok := s.users[uuid]
	return user, ok
}

// HandleConnection handles an incoming VLESS connection
func (s *Server) HandleConnection(conn net.Conn) (*Request, *User, net.Conn, error) {
	// Read version (1 byte)
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, versionBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read version: %w", err)
	}
	version := versionBuf[0]

	if version != Version {
		return nil, nil, nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read UUID (16 bytes)
	uuidBuf := make([]byte, 16)
	if _, err := io.ReadFull(conn, uuidBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read UUID: %w", err)
	}
	var uuid [16]byte
	copy(uuid[:], uuidBuf)

	// Verify user
	user, ok := s.GetUser(uuid)
	if !ok {
		return nil, nil, nil, errors.New("user not found")
	}

	// Read addons length (1 byte)
	addonsLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, addonsLenBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read addons length: %w", err)
	}
	addonsLen := int(addonsLenBuf[0])

	// Read addons if present
	var addons []byte
	if addonsLen > 0 {
		addons = make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, addons); err != nil {
			return nil, nil, nil, fmt.Errorf("read addons: %w", err)
		}
	}

	// Read command (1 byte)
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read command: %w", err)
	}
	cmd := Command(cmdBuf[0])

	// Read port (2 bytes)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Read address type (1 byte)
	addrTypeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, addrTypeBuf); err != nil {
		return nil, nil, nil, fmt.Errorf("read address type: %w", err)
	}
	addrType := AddressType(addrTypeBuf[0])

	// Read address
	var address string
	switch addrType {
	case AddressTypeIPv4:
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return nil, nil, nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeIPv6:
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return nil, nil, nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		address = net.IP(addrBuf).String()

	case AddressTypeDomain:
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLenBuf); err != nil {
			return nil, nil, nil, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(domainLenBuf[0])

		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return nil, nil, nil, fmt.Errorf("read domain: %w", err)
		}
		address = string(domainBuf)

	default:
		return nil, nil, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	req := &Request{
		Version: version,
		UUID:    uuid,
		Command: cmd,
		Address: address,
		Port:    port,
		Addons:  addons,
	}

	// Create VLESS connection
	vlessConn := &Conn{
		Conn:         conn,
		isClient:     false,
		responseRead: true, // Server doesn't need to read response
	}

	// Send response header
	if err := vlessConn.writeResponseHeader(); err != nil {
		return nil, nil, nil, fmt.Errorf("write response header: %w", err)
	}

	return req, user, vlessConn, nil
}

// Conn represents a VLESS connection
type Conn struct {
	net.Conn
	isClient     bool
	responseRead bool
	readMux      sync.Mutex
	writeMux     sync.Mutex
}

// writeResponseHeader writes the VLESS response header
func (c *Conn) writeResponseHeader() error {
	// Response header: version (1 byte) + addons length (1 byte)
	header := []byte{Version, 0}
	_, err := c.Conn.Write(header)
	return err
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (int, error) {
	c.readMux.Lock()
	defer c.readMux.Unlock()

	// Client needs to read response header first
	if c.isClient && !c.responseRead {
		// Read version (1 byte)
		versionBuf := make([]byte, 1)
		if _, err := io.ReadFull(c.Conn, versionBuf); err != nil {
			return 0, fmt.Errorf("read response version: %w", err)
		}

		// Read addons length (1 byte)
		addonsLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c.Conn, addonsLenBuf); err != nil {
			return 0, fmt.Errorf("read response addons length: %w", err)
		}
		addonsLen := int(addonsLenBuf[0])

		// Skip addons if present
		if addonsLen > 0 {
			addons := make([]byte, addonsLen)
			if _, err := io.ReadFull(c.Conn, addons); err != nil {
				return 0, fmt.Errorf("read response addons: %w", err)
			}
		}

		c.responseRead = true
	}

	return c.Conn.Read(b)
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMux.Lock()
	defer c.writeMux.Unlock()
	return c.Conn.Write(b)
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

// FormatUUID formats UUID bytes as a string
func FormatUUID(uuid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:16])
}
