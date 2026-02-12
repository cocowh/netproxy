package kcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/xtaci/kcp-go/v5"
)

// Transport implements the KCP transport layer.
// It provides both client (Dial) and server (Listen) capabilities.
type Transport struct {
	config *Config
	block  kcp.BlockCrypt
	mu     sync.RWMutex
}

// NewTransport creates a new KCP transport with the given configuration.
func NewTransport(config *Config) (*Transport, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	block, err := config.GetBlockCrypt()
	if err != nil {
		return nil, fmt.Errorf("failed to create block cipher: %w", err)
	}

	return &Transport{
		config: config,
		block:  block,
	}, nil
}

// Dial establishes a KCP connection to the specified address.
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.RLock()
	config := t.config
	block := t.block
	t.mu.RUnlock()

	// Create KCP session with FEC if configured
	var sess *kcp.UDPSession
	var err error

	if config.DataShard > 0 && config.ParityShard > 0 {
		sess, err = kcp.DialWithOptions(addr, block, config.DataShard, config.ParityShard)
	} else {
		sess, err = kcp.DialWithOptions(addr, block, 0, 0)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial KCP: %w", err)
	}

	// Apply configuration
	if err := t.configureSession(sess); err != nil {
		sess.Close()
		return nil, err
	}

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		if ctx.Err() != nil {
			sess.Close()
		}
	}()

	conn := &Conn{
		UDPSession: sess,
		config:     config,
	}

	// Wrap with compression if enabled
	if config.Compression {
		return newCompressedConn(conn), nil
	}

	return conn, nil
}

// DialPacket is not supported for KCP as it provides stream-oriented connections.
func (t *Transport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("KCP does not support packet connections, use Dial instead")
}

// Listen creates a KCP listener on the specified address.
func (t *Transport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	t.mu.RLock()
	config := t.config
	block := t.block
	t.mu.RUnlock()

	var listener *kcp.Listener
	var err error

	if config.DataShard > 0 && config.ParityShard > 0 {
		listener, err = kcp.ListenWithOptions(addr, block, config.DataShard, config.ParityShard)
	} else {
		listener, err = kcp.ListenWithOptions(addr, block, 0, 0)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to listen KCP: %w", err)
	}

	// Set socket buffer sizes
	if err := listener.SetReadBuffer(config.ReadBuffer); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set read buffer: %w", err)
	}
	if err := listener.SetWriteBuffer(config.WriteBuffer); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set write buffer: %w", err)
	}

	// Set DSCP
	if config.DSCP > 0 {
		if err := listener.SetDSCP(config.DSCP); err != nil {
			listener.Close()
			return nil, fmt.Errorf("failed to set DSCP: %w", err)
		}
	}

	return &Listener{
		Listener: listener,
		config:   config,
	}, nil
}

// ListenPacket is not supported for KCP.
func (t *Transport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("KCP does not support ListenPacket, use Listen instead")
}

// configureSession applies configuration to a KCP session.
func (t *Transport) configureSession(sess *kcp.UDPSession) error {
	config := t.config

	// Set MTU
	sess.SetMtu(config.MTU)

	// Set window sizes
	sess.SetWindowSize(config.SndWnd, config.RcvWnd)

	// Set nodelay parameters
	sess.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NC)

	// Set socket buffer sizes
	if err := sess.SetReadBuffer(config.ReadBuffer); err != nil {
		return fmt.Errorf("failed to set read buffer: %w", err)
	}
	if err := sess.SetWriteBuffer(config.WriteBuffer); err != nil {
		return fmt.Errorf("failed to set write buffer: %w", err)
	}

	// Set DSCP
	if config.DSCP > 0 {
		if err := sess.SetDSCP(config.DSCP); err != nil {
			return fmt.Errorf("failed to set DSCP: %w", err)
		}
	}

	// Set ACK no delay
	sess.SetACKNoDelay(config.AckNoDelay)

	// Set stream mode
	sess.SetStreamMode(config.StreamMode)

	return nil
}

// UpdateConfig updates the transport configuration.
// Note: This only affects new connections, not existing ones.
func (t *Transport) UpdateConfig(config *Config) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	block, err := config.GetBlockCrypt()
	if err != nil {
		return fmt.Errorf("failed to create block cipher: %w", err)
	}

	t.mu.Lock()
	t.config = config
	t.block = block
	t.mu.Unlock()

	return nil
}

// Listener wraps kcp.Listener with additional functionality.
type Listener struct {
	*kcp.Listener
	config *Config
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	sess, err := l.Listener.AcceptKCP()
	if err != nil {
		return nil, err
	}

	// Apply configuration to accepted session
	sess.SetMtu(l.config.MTU)
	sess.SetWindowSize(l.config.SndWnd, l.config.RcvWnd)
	sess.SetNoDelay(l.config.NoDelay, l.config.Interval, l.config.Resend, l.config.NC)
	sess.SetACKNoDelay(l.config.AckNoDelay)
	sess.SetStreamMode(l.config.StreamMode)

	conn := &Conn{
		UDPSession: sess,
		config:     l.config,
	}

	// Wrap with compression if enabled
	if l.config.Compression {
		return newCompressedConn(conn), nil
	}

	return conn, nil
}

// Conn wraps kcp.UDPSession with additional functionality.
type Conn struct {
	*kcp.UDPSession
	config *Config
}

// GetConfig returns the configuration used for this connection.
func (c *Conn) GetConfig() *Config {
	return c.config
}

// compressedConn wraps a connection with Snappy compression.
type compressedConn struct {
	net.Conn
	reader *snappy.Reader
	writer *snappy.Writer
}

func newCompressedConn(conn net.Conn) net.Conn {
	return &compressedConn{
		Conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
	}
}

func (c *compressedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *compressedConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if err != nil {
		return n, err
	}
	return n, c.writer.Flush()
}

func (c *compressedConn) Close() error {
	return c.Conn.Close()
}

// Dialer provides a simple interface for dialing KCP connections.
type Dialer struct {
	transport *Transport
	timeout   time.Duration
}

// NewDialer creates a new KCP dialer with the given configuration.
func NewDialer(config *Config, timeout time.Duration) (*Dialer, error) {
	transport, err := NewTransport(config)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		transport: transport,
		timeout:   timeout,
	}, nil
}

// Dial establishes a KCP connection to the specified address.
func (d *Dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	return d.transport.Dial(ctx, addr)
}

// DialPacket is not supported for KCP.
func (d *Dialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("KCP does not support packet connections")
}

// Server provides a simple interface for accepting KCP connections.
type Server struct {
	listener net.Listener
	config   *Config
}

// NewServer creates a new KCP server listening on the specified address.
func NewServer(addr string, config *Config) (*Server, error) {
	transport, err := NewTransport(config)
	if err != nil {
		return nil, err
	}

	listener, err := transport.Listen(context.Background(), addr)
	if err != nil {
		return nil, err
	}

	return &Server{
		listener: listener,
		config:   config,
	}, nil
}

// Accept waits for and returns the next connection.
func (s *Server) Accept() (net.Conn, error) {
	return s.listener.Accept()
}

// Close closes the server.
func (s *Server) Close() error {
	return s.listener.Close()
}

// Addr returns the listener's network address.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// NewKCPTransport creates a new KCP transport with FEC parameters.
// This is a convenience function for backward compatibility.
// The salt parameter is combined with key for encryption.
func NewKCPTransport(dataShards, parityShards int, key, salt string) *Transport {
	config := DefaultConfig()
	config.DataShard = dataShards
	config.ParityShard = parityShards
	// Combine key and salt for the encryption key
	if salt != "" {
		config.Key = key + salt
	} else {
		config.Key = key
	}

	transport, err := NewTransport(config)
	if err != nil {
		// Return a transport with default config if there's an error
		transport, _ = NewTransport(DefaultConfig())
	}
	return transport
}
