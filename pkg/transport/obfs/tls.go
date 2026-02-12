// Package obfs implements TLS obfuscation.
// TLS obfuscation disguises traffic as TLS handshake.
package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TLS record types
const (
	tlsRecordTypeChangeCipherSpec = 0x14
	tlsRecordTypeAlert            = 0x15
	tlsRecordTypeHandshake        = 0x16
	tlsRecordTypeApplicationData  = 0x17
)

// TLS handshake types
const (
	tlsHandshakeTypeClientHello = 0x01
	tlsHandshakeTypeServerHello = 0x02
)

// TLS versions
const (
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
)

// TLSObfsConfig configures TLS obfuscation
type TLSObfsConfig struct {
	Host string // SNI host
}

// DefaultTLSObfsConfig returns default configuration
func DefaultTLSObfsConfig() *TLSObfsConfig {
	return &TLSObfsConfig{
		Host: "www.bing.com",
	}
}

// TLSObfsConn wraps a connection with TLS obfuscation
type TLSObfsConn struct {
	net.Conn
	host       string
	isClient   bool
	handshaked bool
	readBuf    bytes.Buffer
	mu         sync.Mutex
}

// NewTLSObfsClient creates a client-side TLS obfuscation wrapper
func NewTLSObfsClient(conn net.Conn, config *TLSObfsConfig) net.Conn {
	if config == nil {
		config = DefaultTLSObfsConfig()
	}
	return &TLSObfsConn{
		Conn:     conn,
		host:     config.Host,
		isClient: true,
	}
}

// NewTLSObfsServer creates a server-side TLS obfuscation wrapper
func NewTLSObfsServer(conn net.Conn) net.Conn {
	return &TLSObfsConn{
		Conn:     conn,
		isClient: false,
	}
}

// Read reads data from the obfuscated connection
func (c *TLSObfsConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return buffered data first
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	if !c.handshaked {
		if c.isClient {
			// Client reads ServerHello
			if err := c.readServerHello(); err != nil {
				return 0, err
			}
		} else {
			// Server reads ClientHello
			payload, err := c.readClientHello()
			if err != nil {
				return 0, err
			}
			if len(payload) > 0 {
				c.readBuf.Write(payload)
			}
		}
		c.handshaked = true

		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(b)
		}
	}

	// Read TLS application data record
	return c.readApplicationData(b)
}

// Write writes data to the obfuscated connection
func (c *TLSObfsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.handshaked {
		if c.isClient {
			// Client sends ClientHello with payload
			if err := c.writeClientHello(b); err != nil {
				return 0, err
			}
		} else {
			// Server sends ServerHello
			if err := c.writeServerHello(); err != nil {
				return 0, err
			}
			// Then send data as application data
			if err := c.writeApplicationData(b); err != nil {
				return 0, err
			}
		}
		c.handshaked = true
		return len(b), nil
	}

	// Write as TLS application data
	return len(b), c.writeApplicationData(b)
}

// writeClientHello writes a fake TLS ClientHello with embedded payload
func (c *TLSObfsConn) writeClientHello(payload []byte) error {
	var buf bytes.Buffer

	// Generate random session ID
	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// Build ClientHello
	var clientHello bytes.Buffer

	// Client version
	binary.Write(&clientHello, binary.BigEndian, uint16(tlsVersion12))

	// Random (32 bytes)
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random, uint32(time.Now().Unix()))
	rand.Read(random[4:])
	clientHello.Write(random)

	// Session ID
	clientHello.WriteByte(byte(len(sessionID)))
	clientHello.Write(sessionID)

	// Cipher suites
	cipherSuites := []uint16{
		0xc02c, 0xc02b, 0xc030, 0xc02f, // ECDHE suites
		0x009f, 0x009e, 0xc024, 0xc023, // DHE suites
		0x00ff, // Renegotiation info
	}
	binary.Write(&clientHello, binary.BigEndian, uint16(len(cipherSuites)*2))
	for _, suite := range cipherSuites {
		binary.Write(&clientHello, binary.BigEndian, suite)
	}

	// Compression methods
	clientHello.WriteByte(1) // Length
	clientHello.WriteByte(0) // null compression

	// Extensions
	var extensions bytes.Buffer

	// SNI extension
	sniExt := buildSNIExtension(c.host)
	extensions.Write(sniExt)

	// Session ticket extension (embed payload here)
	if len(payload) > 0 {
		binary.Write(&extensions, binary.BigEndian, uint16(0x0023)) // Session ticket type
		binary.Write(&extensions, binary.BigEndian, uint16(len(payload)))
		extensions.Write(payload)
	}

	// Supported versions extension
	binary.Write(&extensions, binary.BigEndian, uint16(0x002b))
	binary.Write(&extensions, binary.BigEndian, uint16(3))
	extensions.WriteByte(2)
	binary.Write(&extensions, binary.BigEndian, uint16(tlsVersion12))

	// Write extensions length and data
	binary.Write(&clientHello, binary.BigEndian, uint16(extensions.Len()))
	clientHello.Write(extensions.Bytes())

	// Build handshake message
	var handshake bytes.Buffer
	handshake.WriteByte(tlsHandshakeTypeClientHello)
	// Length (3 bytes)
	length := clientHello.Len()
	handshake.WriteByte(byte(length >> 16))
	handshake.WriteByte(byte(length >> 8))
	handshake.WriteByte(byte(length))
	handshake.Write(clientHello.Bytes())

	// Build TLS record
	buf.WriteByte(tlsRecordTypeHandshake)
	binary.Write(&buf, binary.BigEndian, uint16(tlsVersion10))
	binary.Write(&buf, binary.BigEndian, uint16(handshake.Len()))
	buf.Write(handshake.Bytes())

	_, err := c.Conn.Write(buf.Bytes())
	return err
}

// readClientHello reads and parses a fake TLS ClientHello
func (c *TLSObfsConn) readClientHello() ([]byte, error) {
	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return nil, fmt.Errorf("read TLS header: %w", err)
	}

	if header[0] != tlsRecordTypeHandshake {
		return nil, fmt.Errorf("expected handshake record, got %d", header[0])
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(c.Conn, record); err != nil {
		return nil, fmt.Errorf("read TLS record: %w", err)
	}

	// Parse handshake
	if len(record) < 4 {
		return nil, fmt.Errorf("handshake too short")
	}

	if record[0] != tlsHandshakeTypeClientHello {
		return nil, fmt.Errorf("expected ClientHello, got %d", record[0])
	}

	// Skip to extensions and find session ticket
	pos := 4 // Skip handshake type and length

	// Skip version (2) + random (32) = 34
	pos += 34

	// Skip session ID
	if pos >= len(record) {
		return nil, nil
	}
	sessionIDLen := int(record[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(record) {
		return nil, nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[pos:]))
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(record) {
		return nil, nil
	}
	compressionLen := int(record[pos])
	pos += 1 + compressionLen

	// Parse extensions
	if pos+2 > len(record) {
		return nil, nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(record[pos:]))
	pos += 2

	endPos := pos + extensionsLen
	if endPos > len(record) {
		endPos = len(record)
	}

	// Find session ticket extension
	for pos+4 <= endPos {
		extType := binary.BigEndian.Uint16(record[pos:])
		extLen := int(binary.BigEndian.Uint16(record[pos+2:]))
		pos += 4

		if extType == 0x0023 && extLen > 0 { // Session ticket
			if pos+extLen <= len(record) {
				return record[pos : pos+extLen], nil
			}
		}

		pos += extLen
	}

	return nil, nil
}

// writeServerHello writes a fake TLS ServerHello
func (c *TLSObfsConn) writeServerHello() error {
	var buf bytes.Buffer

	// Build ServerHello
	var serverHello bytes.Buffer

	// Server version
	binary.Write(&serverHello, binary.BigEndian, uint16(tlsVersion12))

	// Random (32 bytes)
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random, uint32(time.Now().Unix()))
	rand.Read(random[4:])
	serverHello.Write(random)

	// Session ID (32 bytes)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	serverHello.WriteByte(byte(len(sessionID)))
	serverHello.Write(sessionID)

	// Cipher suite
	binary.Write(&serverHello, binary.BigEndian, uint16(0xc02f)) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	// Compression method
	serverHello.WriteByte(0) // null

	// Extensions (empty)
	binary.Write(&serverHello, binary.BigEndian, uint16(0))

	// Build handshake message
	var handshake bytes.Buffer
	handshake.WriteByte(tlsHandshakeTypeServerHello)
	length := serverHello.Len()
	handshake.WriteByte(byte(length >> 16))
	handshake.WriteByte(byte(length >> 8))
	handshake.WriteByte(byte(length))
	handshake.Write(serverHello.Bytes())

	// Build TLS record
	buf.WriteByte(tlsRecordTypeHandshake)
	binary.Write(&buf, binary.BigEndian, uint16(tlsVersion12))
	binary.Write(&buf, binary.BigEndian, uint16(handshake.Len()))
	buf.Write(handshake.Bytes())

	// Also send ChangeCipherSpec
	buf.WriteByte(tlsRecordTypeChangeCipherSpec)
	binary.Write(&buf, binary.BigEndian, uint16(tlsVersion12))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	buf.WriteByte(1)

	_, err := c.Conn.Write(buf.Bytes())
	return err
}

// readServerHello reads and validates a fake TLS ServerHello
func (c *TLSObfsConn) readServerHello() error {
	// Read ServerHello record
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return fmt.Errorf("read ServerHello header: %w", err)
	}

	if header[0] != tlsRecordTypeHandshake {
		return fmt.Errorf("expected handshake, got %d", header[0])
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(c.Conn, record); err != nil {
		return fmt.Errorf("read ServerHello: %w", err)
	}

	// Read ChangeCipherSpec
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return fmt.Errorf("read ChangeCipherSpec header: %w", err)
	}

	if header[0] != tlsRecordTypeChangeCipherSpec {
		return fmt.Errorf("expected ChangeCipherSpec, got %d", header[0])
	}

	recordLen = binary.BigEndian.Uint16(header[3:5])
	record = make([]byte, recordLen)
	if _, err := io.ReadFull(c.Conn, record); err != nil {
		return fmt.Errorf("read ChangeCipherSpec: %w", err)
	}

	return nil
}

// writeApplicationData writes data as TLS application data
func (c *TLSObfsConn) writeApplicationData(data []byte) error {
	var buf bytes.Buffer

	buf.WriteByte(tlsRecordTypeApplicationData)
	binary.Write(&buf, binary.BigEndian, uint16(tlsVersion12))
	binary.Write(&buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	_, err := c.Conn.Write(buf.Bytes())
	return err
}

// readApplicationData reads TLS application data
func (c *TLSObfsConn) readApplicationData(b []byte) (int, error) {
	// Read TLS record header
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	if header[0] != tlsRecordTypeApplicationData {
		return 0, fmt.Errorf("expected application data, got %d", header[0])
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])
	if int(recordLen) <= len(b) {
		return io.ReadFull(c.Conn, b[:recordLen])
	}

	// Need to buffer
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(c.Conn, record); err != nil {
		return 0, err
	}

	n := copy(b, record)
	if n < len(record) {
		c.readBuf.Write(record[n:])
	}
	return n, nil
}

// buildSNIExtension builds a Server Name Indication extension
func buildSNIExtension(host string) []byte {
	var buf bytes.Buffer

	// Extension type (SNI = 0x0000)
	binary.Write(&buf, binary.BigEndian, uint16(0x0000))

	// Extension data length
	hostBytes := []byte(host)
	dataLen := 2 + 1 + 2 + len(hostBytes) // list length + type + name length + name
	binary.Write(&buf, binary.BigEndian, uint16(dataLen))

	// Server name list length
	binary.Write(&buf, binary.BigEndian, uint16(dataLen-2))

	// Server name type (hostname = 0)
	buf.WriteByte(0)

	// Server name length and value
	binary.Write(&buf, binary.BigEndian, uint16(len(hostBytes)))
	buf.Write(hostBytes)

	return buf.Bytes()
}
