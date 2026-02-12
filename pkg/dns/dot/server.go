// Package dot provides DNS-over-TLS server implementation.
package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config represents DoT server configuration.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":853")
	ListenAddr string `json:"listen_addr" yaml:"listen_addr"`

	// Upstream is the upstream DNS server address
	Upstream string `json:"upstream" yaml:"upstream"`

	// TLSCertFile is the path to the TLS certificate file
	TLSCertFile string `json:"tls_cert_file" yaml:"tls_cert_file"`

	// TLSKeyFile is the path to the TLS key file
	TLSKeyFile string `json:"tls_key_file" yaml:"tls_key_file"`

	// Timeout is the query timeout
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// MaxConnections is the maximum number of concurrent connections
	MaxConnections int `json:"max_connections" yaml:"max_connections"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:     ":853",
		Upstream:       "8.8.8.8:53",
		Timeout:        5 * time.Second,
		MaxConnections: 1000,
	}
}

// Server implements a DNS-over-TLS server.
type Server struct {
	config    Config
	listener  net.Listener
	dnsClient *dns.Client
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	connCount int
	connMu    sync.Mutex
}

// NewServer creates a new DoT server.
func NewServer(cfg Config) *Server {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 1000
	}

	return &Server{
		config: cfg,
		dnsClient: &dns.Client{
			Net:     "udp",
			Timeout: cfg.Timeout,
		},
	}
}

// Start starts the DoT server.
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", s.config.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}
	s.listener = listener

	// Accept connections
	go s.acceptLoop()

	// Wait for context cancellation
	<-s.ctx.Done()
	return s.Stop()
}

// Stop stops the DoT server.
func (s *Server) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// acceptLoop accepts incoming connections.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		// Check connection limit
		s.connMu.Lock()
		if s.connCount >= s.config.MaxConnections {
			s.connMu.Unlock()
			conn.Close()
			continue
		}
		s.connCount++
		s.connMu.Unlock()

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single DoT connection.
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		s.connMu.Lock()
		s.connCount--
		s.connMu.Unlock()
		s.wg.Done()
	}()

	// DNS over TCP uses length-prefixed messages
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(s.config.Timeout))

		// Read DNS message
		msg, err := s.readDNSMessage(conn)
		if err != nil {
			return
		}

		// Forward query to upstream
		response, err := s.forwardQuery(msg)
		if err != nil {
			// Send SERVFAIL response
			response = new(dns.Msg)
			response.SetRcode(msg, dns.RcodeServerFailure)
		}

		// Write response
		conn.SetWriteDeadline(time.Now().Add(s.config.Timeout))
		if err := s.writeDNSMessage(conn, response); err != nil {
			return
		}
	}
}

// readDNSMessage reads a length-prefixed DNS message from the connection.
func (s *Server) readDNSMessage(conn net.Conn) (*dns.Msg, error) {
	// Read 2-byte length prefix
	lengthBuf := make([]byte, 2)
	if _, err := conn.Read(lengthBuf); err != nil {
		return nil, err
	}

	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if length > 65535 {
		return nil, fmt.Errorf("message too large: %d", length)
	}

	// Read message
	msgBuf := make([]byte, length)
	if _, err := conn.Read(msgBuf); err != nil {
		return nil, err
	}

	// Unpack DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		return nil, err
	}

	return msg, nil
}

// writeDNSMessage writes a length-prefixed DNS message to the connection.
func (s *Server) writeDNSMessage(conn net.Conn, msg *dns.Msg) error {
	// Pack message
	msgBuf, err := msg.Pack()
	if err != nil {
		return err
	}

	// Write length prefix
	length := len(msgBuf)
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if _, err := conn.Write(lengthBuf); err != nil {
		return err
	}

	// Write message
	if _, err := conn.Write(msgBuf); err != nil {
		return err
	}

	return nil
}

// forwardQuery forwards a DNS query to the upstream server.
func (s *Server) forwardQuery(query *dns.Msg) (*dns.Msg, error) {
	response, _, err := s.dnsClient.Exchange(query, s.config.Upstream)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Resolver implements a DoT client for resolving DNS queries.
type Resolver struct {
	serverAddr string
	tlsConfig  *tls.Config
	timeout    time.Duration
}

// NewResolver creates a new DoT resolver.
func NewResolver(serverAddr string, serverName string) *Resolver {
	return &Resolver{
		serverAddr: serverAddr,
		tlsConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
		timeout: 10 * time.Second,
	}
}

// NewResolverWithConfig creates a new DoT resolver with custom TLS config.
func NewResolverWithConfig(serverAddr string, tlsConfig *tls.Config) *Resolver {
	return &Resolver{
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		timeout:    10 * time.Second,
	}
}

// Resolve resolves a DNS query using DoT.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) ([]net.IP, error) {
	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	// Connect to server
	dialer := &tls.Dialer{
		Config: r.tlsConfig,
	}

	conn, err := dialer.DialContext(ctx, "tcp", r.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(r.timeout)
	}
	conn.SetDeadline(deadline)

	// Pack query
	queryBuf, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack query: %w", err)
	}

	// Write length prefix
	length := len(queryBuf)
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if _, err := conn.Write(lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to write length: %w", err)
	}

	// Write query
	if _, err := conn.Write(queryBuf); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	// Read response length
	respLengthBuf := make([]byte, 2)
	if _, err := conn.Read(respLengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	respLength := int(respLengthBuf[0])<<8 | int(respLengthBuf[1])
	if respLength > 65535 {
		return nil, fmt.Errorf("response too large: %d", respLength)
	}

	// Read response
	respBuf := make([]byte, respLength)
	if _, err := conn.Read(respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack response
	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	// Extract IPs
	var ips []net.IP
	for _, rr := range response.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}

	return ips, nil
}

// LookupIP resolves a hostname to IP addresses.
func (r *Resolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	// Try A records first
	ips, err := r.Resolve(ctx, name, dns.TypeA)
	if err != nil {
		return nil, err
	}

	// Also try AAAA records
	ipv6, err := r.Resolve(ctx, name, dns.TypeAAAA)
	if err == nil {
		ips = append(ips, ipv6...)
	}

	return ips, nil
}
