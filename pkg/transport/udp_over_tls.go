package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// UDPOverTLS provides UDP packet transport over a TLS connection
// Protocol: [2-byte length][payload]
type UDPOverTLS struct {
	tlsConn   net.Conn
	localAddr net.Addr
	mu        sync.Mutex
	closed    bool
}

// NewUDPOverTLS creates a new UDP over TLS transport
func NewUDPOverTLS(tlsConn net.Conn) *UDPOverTLS {
	return &UDPOverTLS{
		tlsConn:   tlsConn,
		localAddr: tlsConn.LocalAddr(),
	}
}

// DialUDPOverTLS establishes a TLS connection and returns a UDP-like interface
func DialUDPOverTLS(ctx context.Context, address string, config *tls.Config) (*UDPOverTLS, error) {
	dialer := &tls.Dialer{
		Config: config,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TLS: %w", err)
	}

	return NewUDPOverTLS(conn), nil
}

// ReadFrom reads a UDP packet from the TLS stream
func (u *UDPOverTLS) ReadFrom(p []byte) (int, net.Addr, error) {
	// Read length header (2 bytes, big-endian)
	header := make([]byte, 2)
	if _, err := io.ReadFull(u.tlsConn, header); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint16(header)
	if length == 0 {
		return 0, u.tlsConn.RemoteAddr(), nil
	}

	// Check if buffer is large enough
	if int(length) > len(p) {
		// Read and discard the packet, then return error
		discard := make([]byte, length)
		io.ReadFull(u.tlsConn, discard)
		return 0, nil, fmt.Errorf("buffer too small: need %d, have %d", length, len(p))
	}

	// Read payload
	n, err := io.ReadFull(u.tlsConn, p[:length])
	if err != nil {
		return n, nil, err
	}

	return n, u.tlsConn.RemoteAddr(), nil
}

// WriteTo writes a UDP packet to the TLS stream
func (u *UDPOverTLS) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("packet too large: max 65535 bytes")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, errors.New("connection closed")
	}

	// Write length header
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(p)))

	if _, err := u.tlsConn.Write(header); err != nil {
		return 0, err
	}

	// Write payload
	n, err := u.tlsConn.Write(p)
	if err != nil {
		return n, err
	}

	return n, nil
}

// Close closes the TLS connection
func (u *UDPOverTLS) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return nil
	}
	u.closed = true
	return u.tlsConn.Close()
}

// LocalAddr returns the local address
func (u *UDPOverTLS) LocalAddr() net.Addr {
	return u.localAddr
}

// SetDeadline sets the read and write deadlines
func (u *UDPOverTLS) SetDeadline(t time.Time) error {
	return u.tlsConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (u *UDPOverTLS) SetReadDeadline(t time.Time) error {
	return u.tlsConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (u *UDPOverTLS) SetWriteDeadline(t time.Time) error {
	return u.tlsConn.SetWriteDeadline(t)
}

// UDPOverTLSListener accepts UDP over TLS connections
type UDPOverTLSListener struct {
	listener net.Listener
	config   *tls.Config
}

// NewUDPOverTLSListener creates a new UDP over TLS listener
func NewUDPOverTLSListener(address string, config *tls.Config) (*UDPOverTLSListener, error) {
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener: %w", err)
	}

	return &UDPOverTLSListener{
		listener: listener,
		config:   config,
	}, nil
}

// Accept accepts a new UDP over TLS connection
func (l *UDPOverTLSListener) Accept() (*UDPOverTLS, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	return NewUDPOverTLS(conn), nil
}

// Close closes the listener
func (l *UDPOverTLSListener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's address
func (l *UDPOverTLSListener) Addr() net.Addr {
	return l.listener.Addr()
}

// UDPOverTLSRelay relays UDP packets between a real UDP socket and TLS connections
type UDPOverTLSRelay struct {
	udpConn    *net.UDPConn
	tlsConns   map[string]*UDPOverTLS
	mu         sync.RWMutex
	bufferSize int
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewUDPOverTLSRelay creates a new UDP over TLS relay
func NewUDPOverTLSRelay(udpAddr string, bufferSize int) (*UDPOverTLSRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &UDPOverTLSRelay{
		udpConn:    conn,
		tlsConns:   make(map[string]*UDPOverTLS),
		bufferSize: bufferSize,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// AddTLSConn adds a TLS connection to the relay
func (r *UDPOverTLSRelay) AddTLSConn(key string, conn *UDPOverTLS) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tlsConns[key] = conn

	// Start reading from this TLS connection
	go r.readFromTLS(key, conn)
}

// RemoveTLSConn removes a TLS connection from the relay
func (r *UDPOverTLSRelay) RemoveTLSConn(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if conn, ok := r.tlsConns[key]; ok {
		conn.Close()
		delete(r.tlsConns, key)
	}
}

// readFromTLS reads packets from a TLS connection and forwards to UDP
func (r *UDPOverTLSRelay) readFromTLS(key string, conn *UDPOverTLS) {
	buf := make([]byte, r.bufferSize)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			r.RemoveTLSConn(key)
			return
		}

		// Parse destination address from packet (first 6 bytes: 4 IP + 2 port)
		if n < 6 {
			continue
		}

		ip := net.IP(buf[:4])
		port := binary.BigEndian.Uint16(buf[4:6])
		destAddr := &net.UDPAddr{IP: ip, Port: int(port)}

		// Forward to UDP
		r.udpConn.WriteToUDP(buf[6:n], destAddr)
	}
}

// Start starts the relay
func (r *UDPOverTLSRelay) Start() {
	go r.readFromUDP()
}

// readFromUDP reads packets from UDP and forwards to TLS connections
func (r *UDPOverTLSRelay) readFromUDP() {
	buf := make([]byte, r.bufferSize)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		n, addr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Prepend source address to packet
		packet := make([]byte, 6+n)
		copy(packet[:4], addr.IP.To4())
		binary.BigEndian.PutUint16(packet[4:6], uint16(addr.Port))
		copy(packet[6:], buf[:n])

		// Forward to all TLS connections
		r.mu.RLock()
		for _, conn := range r.tlsConns {
			conn.WriteTo(packet, nil)
		}
		r.mu.RUnlock()
	}
}

// Close closes the relay
func (r *UDPOverTLSRelay) Close() error {
	r.cancel()

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, conn := range r.tlsConns {
		conn.Close()
	}
	r.tlsConns = nil

	return r.udpConn.Close()
}

// UDPAddr returns the UDP address of the relay
func (r *UDPOverTLSRelay) UDPAddr() net.Addr {
	return r.udpConn.LocalAddr()
}

// AddressedUDPOverTLS extends UDPOverTLS with address information in packets
// Protocol: [2-byte length][4-byte IP][2-byte port][payload]
type AddressedUDPOverTLS struct {
	*UDPOverTLS
}

// NewAddressedUDPOverTLS creates a new addressed UDP over TLS transport
func NewAddressedUDPOverTLS(tlsConn net.Conn) *AddressedUDPOverTLS {
	return &AddressedUDPOverTLS{
		UDPOverTLS: NewUDPOverTLS(tlsConn),
	}
}

// ReadFromWithAddr reads a UDP packet with address information
func (u *AddressedUDPOverTLS) ReadFromWithAddr(p []byte) (int, *net.UDPAddr, error) {
	// Read length header
	header := make([]byte, 2)
	if _, err := io.ReadFull(u.tlsConn, header); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint16(header)
	if length < 6 {
		return 0, nil, errors.New("packet too short for address")
	}

	// Read address (4 bytes IP + 2 bytes port)
	addrBuf := make([]byte, 6)
	if _, err := io.ReadFull(u.tlsConn, addrBuf); err != nil {
		return 0, nil, err
	}

	addr := &net.UDPAddr{
		IP:   net.IP(addrBuf[:4]),
		Port: int(binary.BigEndian.Uint16(addrBuf[4:6])),
	}

	// Read payload
	payloadLen := int(length) - 6
	if payloadLen > len(p) {
		discard := make([]byte, payloadLen)
		io.ReadFull(u.tlsConn, discard)
		return 0, nil, fmt.Errorf("buffer too small: need %d, have %d", payloadLen, len(p))
	}

	n, err := io.ReadFull(u.tlsConn, p[:payloadLen])
	if err != nil {
		return n, nil, err
	}

	return n, addr, nil
}

// WriteToWithAddr writes a UDP packet with address information
func (u *AddressedUDPOverTLS) WriteToWithAddr(p []byte, addr *net.UDPAddr) (int, error) {
	if len(p)+6 > 65535 {
		return 0, errors.New("packet too large")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, errors.New("connection closed")
	}

	// Build packet: [length][IP][port][payload]
	totalLen := 6 + len(p)
	buf := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(buf[:2], uint16(totalLen))

	ip := addr.IP.To4()
	if ip == nil {
		ip = net.IPv4zero
	}
	copy(buf[2:6], ip)
	binary.BigEndian.PutUint16(buf[6:8], uint16(addr.Port))
	copy(buf[8:], p)

	if _, err := u.tlsConn.Write(buf); err != nil {
		return 0, err
	}

	return len(p), nil
}
