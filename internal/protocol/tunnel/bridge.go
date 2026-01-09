package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/hashicorp/yamux"
)

// TLSConfig holds TLS configuration for tunnel encryption
type TLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	SkipVerify bool
}

// Bridge acts as the public server that accepts control connections from inner clients
type Bridge struct {
	controlAddr string
	dataAddr    string            // Deprecated: used only if tunnels map is empty
	tunnels     map[string]string // port -> clientID
	token       string            // Authentication token
	tlsConfig   *TLSConfig        // TLS configuration
	logger      logger.Logger
	registry    sync.Map // map[string]*ClientSession (ClientID -> Session)
	listeners   []net.Listener
}

type ClientSession struct {
	ID       string
	Control  *yamux.Session
	LastSeen time.Time
}

func NewBridge(controlAddr, dataAddr string, tunnels map[string]string, token string, l logger.Logger) *Bridge {
	return &Bridge{
		controlAddr: controlAddr,
		dataAddr:    dataAddr,
		tunnels:     tunnels,
		token:       token,
		logger:      l,
	}
}

// NewBridgeWithTLS creates a new Bridge with TLS support
func NewBridgeWithTLS(controlAddr, dataAddr string, tunnels map[string]string, token string, tlsCfg *TLSConfig, l logger.Logger) *Bridge {
	return &Bridge{
		controlAddr: controlAddr,
		dataAddr:    dataAddr,
		tunnels:     tunnels,
		token:       token,
		tlsConfig:   tlsCfg,
		logger:      l,
	}
}

// loadTLSConfig loads TLS configuration and returns a tls.Config for server
func (b *Bridge) loadTLSConfig() (*tls.Config, error) {
	if b.tlsConfig == nil || !b.tlsConfig.Enabled {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(b.tlsConfig.CertFile, b.tlsConfig.KeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Load CA certificate for client verification if provided
	if b.tlsConfig.CAFile != "" {
		caCert, err := os.ReadFile(b.tlsConfig.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

func (b *Bridge) Start(ctx context.Context) error {
	// Start Control Listener
	go b.serveControl(ctx)

	// Start Data Listeners
	if len(b.tunnels) > 0 {
		for port, clientID := range b.tunnels {
			go b.serveDataPort(ctx, port, clientID)
		}
	} else if b.dataAddr != "" {
		// Fallback for backward compatibility
		go b.serveData(ctx)
	}

	return nil
}

func (b *Bridge) serveControl(ctx context.Context) {
	var ln net.Listener
	var err error

	// Check if TLS is enabled
	tlsConfig, tlsErr := b.loadTLSConfig()
	if tlsErr != nil {
		b.logger.Fatal("Failed to load TLS config", logger.Any("error", tlsErr))
		return
	}

	if tlsConfig != nil {
		// Use TLS listener for encrypted control channel
		ln, err = tls.Listen("tcp", b.controlAddr, tlsConfig)
		if err != nil {
			b.logger.Fatal("Failed to listen on control port with TLS", logger.Any("error", err))
			return
		}
		b.logger.Info("Bridge Control listening with TLS", logger.Any("addr", b.controlAddr))
	} else {
		// Use plain TCP listener
		ln, err = net.Listen("tcp", b.controlAddr)
		if err != nil {
			b.logger.Fatal("Failed to listen on control port", logger.Any("error", err))
			return
		}
		b.logger.Info("Bridge Control listening", logger.Any("addr", b.controlAddr))
	}

	b.listeners = append(b.listeners, ln)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if closed?
			b.logger.Error("Accept error", logger.Any("error", err))
			continue
		}
		go b.handleControlConn(conn)
	}
}

func (b *Bridge) handleControlConn(conn net.Conn) {
	// 1. Handshake to identify client (Simple implementation: Client sends ID first line)
	// In production, use stronger authentication.
	// We use yamux to multiplex over this single TCP connection.

	session, err := yamux.Server(conn, nil)
	if err != nil {
		b.logger.Error("Yamux server init failed", logger.Any("error", err))
		conn.Close()
		return
	}

	// Accept initial stream for handshake
	stream, err := session.Accept()
	if err != nil {
		b.logger.Error("Yamux accept handshake failed", logger.Any("error", err))
		session.Close()
		return
	}

	// Read Handshake (ID|Token)
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		stream.Close()
		session.Close()
		return
	}
	handshake := string(buf[:n])
	
	// Parse Handshake
	// Format: ClientID or ClientID|Token
	var clientID, token string
	parts := []string{handshake}
	for i, c := range handshake {
		if c == '|' {
			parts = []string{handshake[:i], handshake[i+1:]}
			break
		}
	}
	
	if len(parts) == 2 {
		clientID = parts[0]
		token = parts[1]
	} else {
		clientID = parts[0]
	}

	// Verify Token
	if b.token != "" && token != b.token {
		b.logger.Error("Client authentication failed", logger.Any("id", clientID))
		stream.Write([]byte("AUTH_FAILED"))
		stream.Close()
		session.Close()
		return
	}
	
	// Send Ack
	stream.Write([]byte("OK"))

	b.logger.Info("Client registered", logger.Any("id", clientID))

	clientSession := &ClientSession{
		ID:       clientID,
		Control:  session,
		LastSeen: time.Now(),
	}
	b.registry.Store(clientID, clientSession)

	// Keep-alive loop or wait for session close
	<-session.CloseChan()
	b.registry.Delete(clientID)
	b.logger.Info("Client disconnected", logger.Any("id", clientID))
}

func (b *Bridge) serveData(ctx context.Context) {
	ln, err := net.Listen("tcp", b.dataAddr)
	if err != nil {
		b.logger.Fatal("Failed to listen on data port", logger.Any("error", err))
		return
	}
	b.listeners = append(b.listeners, ln)
	b.logger.Info("Bridge Data listening", logger.Any("addr", b.dataAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		// Fallback: random routing
		go b.routeConnection(conn, "")
	}
}

func (b *Bridge) serveDataPort(ctx context.Context, addr string, targetClientID string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.logger.Error("Failed to listen on tunnel port", logger.Any("addr", addr), logger.Any("error", err))
		return
	}
	b.listeners = append(b.listeners, ln)
	b.logger.Info("Bridge Tunnel listening", logger.Any("addr", addr), logger.Any("target", targetClientID))

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go b.routeConnection(conn, targetClientID)
	}
}

func (b *Bridge) routeConnection(userConn net.Conn, targetClientID string) {
	var targetSession *ClientSession

	if targetClientID != "" {
		if val, ok := b.registry.Load(targetClientID); ok {
			targetSession = val.(*ClientSession)
		}
	} else {
		// Random fallback
		b.registry.Range(func(key, value interface{}) bool {
			targetSession = value.(*ClientSession)
			return false // stop after first
		})
	}

	if targetSession == nil {
		b.logger.Error("Client not connected", logger.Any("target", targetClientID))
		userConn.Close()
		return
	}

	// Open a new stream on the control connection to the client
	// This signals the client to connect to its local target
	stream, err := targetSession.Control.Open()
	if err != nil {
		b.logger.Error("Failed to open stream to client", logger.Any("error", err))
		userConn.Close()
		return
	}

	// Relay
	go func() {
		defer userConn.Close()
		defer stream.Close()
		
		// Bidirectional copy
		errChan := make(chan error, 2)
		go func() {
			_, err := io.Copy(userConn, stream)
			errChan <- err
		}()
		go func() {
			_, err := io.Copy(stream, userConn)
			errChan <- err
		}()
		<-errChan
	}()
}
