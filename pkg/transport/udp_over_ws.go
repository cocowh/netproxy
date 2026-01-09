package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// UDPOverWS provides UDP packet transport over a WebSocket connection
// Each UDP packet is sent as a WebSocket Binary Message
type UDPOverWS struct {
	conn      *websocket.Conn
	localAddr net.Addr
	mu        sync.Mutex
	closed    bool
}

// NewUDPOverWS creates a new UDP over WebSocket transport
func NewUDPOverWS(conn *websocket.Conn) *UDPOverWS {
	return &UDPOverWS{
		conn:      conn,
		localAddr: conn.LocalAddr(),
	}
}

// DialUDPOverWS establishes a WebSocket connection and returns a UDP-like interface
func DialUDPOverWS(ctx context.Context, wsURL string, header http.Header) (*UDPOverWS, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	return NewUDPOverWS(conn), nil
}

// DialUDPOverWSWithProxy establishes a WebSocket connection through a proxy
func DialUDPOverWSWithProxy(ctx context.Context, proxyDialer ProxyDialer, host, path string, header http.Header) (*UDPOverWS, error) {
	// Dial TCP connection through proxy
	conn, err := proxyDialer.Dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial through proxy: %w", err)
	}

	// Perform WebSocket handshake
	u := url.URL{Scheme: "ws", Host: host, Path: path}
	if header == nil {
		header = http.Header{}
	}
	header.Set("Host", host)

	wsConn, _, err := websocket.NewClient(conn, &u, header, 4096, 4096)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket handshake failed: %w", err)
	}

	return NewUDPOverWS(wsConn), nil
}

// ReadFrom reads a UDP packet from the WebSocket connection
func (u *UDPOverWS) ReadFrom(p []byte) (int, net.Addr, error) {
	msgType, data, err := u.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}

	if msgType != websocket.BinaryMessage {
		// Skip non-binary messages
		return u.ReadFrom(p)
	}

	n := copy(p, data)
	return n, u.conn.RemoteAddr(), nil
}

// WriteTo writes a UDP packet to the WebSocket connection
func (u *UDPOverWS) WriteTo(p []byte, addr net.Addr) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, errors.New("connection closed")
	}

	if err := u.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close closes the WebSocket connection
func (u *UDPOverWS) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return nil
	}
	u.closed = true

	// Send close message
	u.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

	return u.conn.Close()
}

// LocalAddr returns the local address
func (u *UDPOverWS) LocalAddr() net.Addr {
	return u.localAddr
}

// SetDeadline sets the read and write deadlines
func (u *UDPOverWS) SetDeadline(t time.Time) error {
	if err := u.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return u.conn.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline
func (u *UDPOverWS) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (u *UDPOverWS) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
}

// UDPOverWSServer handles UDP over WebSocket connections on the server side
type UDPOverWSServer struct {
	upgrader websocket.Upgrader
	handler  func(*UDPOverWS)
}

// NewUDPOverWSServer creates a new UDP over WebSocket server
func NewUDPOverWSServer(handler func(*UDPOverWS)) *UDPOverWSServer {
	return &UDPOverWSServer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  65536,
			WriteBufferSize: 65536,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins
			},
		},
		handler: handler,
	}
}

// ServeHTTP implements http.Handler
func (s *UDPOverWSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	udpWS := NewUDPOverWS(conn)
	s.handler(udpWS)
}

// UDPOverWSRelay relays UDP packets between a real UDP socket and WebSocket connections
type UDPOverWSRelay struct {
	udpConn    *net.UDPConn
	wsConns    map[string]*UDPOverWS
	mu         sync.RWMutex
	bufferSize int
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewUDPOverWSRelay creates a new UDP over WebSocket relay
func NewUDPOverWSRelay(udpAddr string, bufferSize int) (*UDPOverWSRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &UDPOverWSRelay{
		udpConn:    conn,
		wsConns:    make(map[string]*UDPOverWS),
		bufferSize: bufferSize,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// AddWSConn adds a WebSocket connection to the relay
func (r *UDPOverWSRelay) AddWSConn(key string, conn *UDPOverWS) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wsConns[key] = conn

	// Start reading from this WebSocket connection
	go r.readFromWS(key, conn)
}

// RemoveWSConn removes a WebSocket connection from the relay
func (r *UDPOverWSRelay) RemoveWSConn(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if conn, ok := r.wsConns[key]; ok {
		conn.Close()
		delete(r.wsConns, key)
	}
}

// readFromWS reads packets from a WebSocket connection and forwards to UDP
func (r *UDPOverWSRelay) readFromWS(key string, conn *UDPOverWS) {
	buf := make([]byte, r.bufferSize)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			r.RemoveWSConn(key)
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
func (r *UDPOverWSRelay) Start() {
	go r.readFromUDP()
}

// readFromUDP reads packets from UDP and forwards to WebSocket connections
func (r *UDPOverWSRelay) readFromUDP() {
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

		// Forward to all WebSocket connections
		r.mu.RLock()
		for _, conn := range r.wsConns {
			conn.WriteTo(packet, nil)
		}
		r.mu.RUnlock()
	}
}

// Close closes the relay
func (r *UDPOverWSRelay) Close() error {
	r.cancel()

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, conn := range r.wsConns {
		conn.Close()
	}
	r.wsConns = nil

	return r.udpConn.Close()
}

// UDPAddr returns the UDP address of the relay
func (r *UDPOverWSRelay) UDPAddr() net.Addr {
	return r.udpConn.LocalAddr()
}

// AddressedUDPOverWS extends UDPOverWS with address information in packets
// Protocol: [4-byte IP][2-byte port][payload]
type AddressedUDPOverWS struct {
	*UDPOverWS
}

// NewAddressedUDPOverWS creates a new addressed UDP over WebSocket transport
func NewAddressedUDPOverWS(conn *websocket.Conn) *AddressedUDPOverWS {
	return &AddressedUDPOverWS{
		UDPOverWS: NewUDPOverWS(conn),
	}
}

// ReadFromWithAddr reads a UDP packet with address information
func (u *AddressedUDPOverWS) ReadFromWithAddr(p []byte) (int, *net.UDPAddr, error) {
	msgType, data, err := u.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}

	if msgType != websocket.BinaryMessage {
		return u.ReadFromWithAddr(p)
	}

	if len(data) < 6 {
		return 0, nil, errors.New("packet too short for address")
	}

	addr := &net.UDPAddr{
		IP:   net.IP(data[:4]),
		Port: int(binary.BigEndian.Uint16(data[4:6])),
	}

	n := copy(p, data[6:])
	return n, addr, nil
}

// WriteToWithAddr writes a UDP packet with address information
func (u *AddressedUDPOverWS) WriteToWithAddr(p []byte, addr *net.UDPAddr) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, errors.New("connection closed")
	}

	// Build packet: [IP][port][payload]
	packet := make([]byte, 6+len(p))
	ip := addr.IP.To4()
	if ip == nil {
		ip = net.IPv4zero
	}
	copy(packet[:4], ip)
	binary.BigEndian.PutUint16(packet[4:6], uint16(addr.Port))
	copy(packet[6:], p)

	if err := u.conn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		return 0, err
	}

	return len(p), nil
}

// WSPacketConnAdapter adapts UDPOverWS to net.PacketConn interface
type WSPacketConnAdapter struct {
	udpWS *UDPOverWS
}

// NewWSPacketConnAdapter creates a new adapter
func NewWSPacketConnAdapter(udpWS *UDPOverWS) net.PacketConn {
	return &WSPacketConnAdapter{udpWS: udpWS}
}

func (a *WSPacketConnAdapter) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return a.udpWS.ReadFrom(p)
}

func (a *WSPacketConnAdapter) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return a.udpWS.WriteTo(p, addr)
}

func (a *WSPacketConnAdapter) Close() error {
	return a.udpWS.Close()
}

func (a *WSPacketConnAdapter) LocalAddr() net.Addr {
	return a.udpWS.LocalAddr()
}

func (a *WSPacketConnAdapter) SetDeadline(t time.Time) error {
	return a.udpWS.SetDeadline(t)
}

func (a *WSPacketConnAdapter) SetReadDeadline(t time.Time) error {
	return a.udpWS.SetReadDeadline(t)
}

func (a *WSPacketConnAdapter) SetWriteDeadline(t time.Time) error {
	return a.udpWS.SetWriteDeadline(t)
}

// StreamToPacketBridge bridges a stream connection to UDP packets
// This is useful for protocols that need to convert between stream and packet modes
type StreamToPacketBridge struct {
	streamConn net.Conn
	udpConn    *net.UDPConn
	bufferSize int
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewStreamToPacketBridge creates a new bridge
func NewStreamToPacketBridge(streamConn net.Conn, udpAddr string, bufferSize int) (*StreamToPacketBridge, error) {
	addr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &StreamToPacketBridge{
		streamConn: streamConn,
		udpConn:    udpConn,
		bufferSize: bufferSize,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start starts the bridge
func (b *StreamToPacketBridge) Start() {
	go b.streamToUDP()
	go b.udpToStream()
}

// streamToUDP reads from stream and writes to UDP
func (b *StreamToPacketBridge) streamToUDP() {
	buf := make([]byte, b.bufferSize)
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		// Read length header
		header := make([]byte, 2)
		if _, err := io.ReadFull(b.streamConn, header); err != nil {
			return
		}

		length := binary.BigEndian.Uint16(header)
		if int(length) > b.bufferSize {
			// Skip oversized packet
			io.CopyN(io.Discard, b.streamConn, int64(length))
			continue
		}

		// Read packet
		if _, err := io.ReadFull(b.streamConn, buf[:length]); err != nil {
			return
		}

		// Parse destination and forward
		if length < 6 {
			continue
		}

		ip := net.IP(buf[:4])
		port := binary.BigEndian.Uint16(buf[4:6])
		destAddr := &net.UDPAddr{IP: ip, Port: int(port)}

		b.udpConn.WriteToUDP(buf[6:length], destAddr)
	}
}

// udpToStream reads from UDP and writes to stream
func (b *StreamToPacketBridge) udpToStream() {
	buf := make([]byte, b.bufferSize)
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		n, addr, err := b.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Build packet with address
		packet := make([]byte, 2+6+n)
		binary.BigEndian.PutUint16(packet[:2], uint16(6+n))
		copy(packet[2:6], addr.IP.To4())
		binary.BigEndian.PutUint16(packet[6:8], uint16(addr.Port))
		copy(packet[8:], buf[:n])

		if _, err := b.streamConn.Write(packet); err != nil {
			return
		}
	}
}

// Close closes the bridge
func (b *StreamToPacketBridge) Close() error {
	b.cancel()
	b.streamConn.Close()
	return b.udpConn.Close()
}

// UDPAddr returns the UDP address of the bridge
func (b *StreamToPacketBridge) UDPAddr() net.Addr {
	return b.udpConn.LocalAddr()
}
