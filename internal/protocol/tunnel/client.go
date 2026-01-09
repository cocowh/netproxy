package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/hashicorp/yamux"
)

type Client struct {
	serverAddr string
	targetAddr string // Local service to expose
	clientID   string
	token      string     // Authentication Token
	tlsConfig  *TLSConfig // TLS configuration
	logger     logger.Logger
}

func NewClient(serverAddr, targetAddr, clientID, token string, l logger.Logger) *Client {
	return &Client{
		serverAddr: serverAddr,
		targetAddr: targetAddr,
		clientID:   clientID,
		token:      token,
		logger:     l,
	}
}

// NewClientWithTLS creates a new Client with TLS support
func NewClientWithTLS(serverAddr, targetAddr, clientID, token string, tlsCfg *TLSConfig, l logger.Logger) *Client {
	return &Client{
		serverAddr: serverAddr,
		targetAddr: targetAddr,
		clientID:   clientID,
		token:      token,
		tlsConfig:  tlsCfg,
		logger:     l,
	}
}

// loadTLSConfig loads TLS configuration and returns a tls.Config for client
func (c *Client) loadTLSConfig() (*tls.Config, error) {
	if c.tlsConfig == nil || !c.tlsConfig.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.tlsConfig.SkipVerify,
	}

	// Set server name for SNI
	if c.tlsConfig.ServerName != "" {
		tlsConfig.ServerName = c.tlsConfig.ServerName
	}

	// Load CA certificate if provided
	if c.tlsConfig.CAFile != "" {
		caCert, err := os.ReadFile(c.tlsConfig.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if provided (for mutual TLS)
	if c.tlsConfig.CertFile != "" && c.tlsConfig.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.tlsConfig.CertFile, c.tlsConfig.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func (c *Client) Start(ctx context.Context) error {
	for {
		err := c.connectAndServe(ctx)
		if err != nil {
			c.logger.Error("Tunnel client disconnected, retrying...", logger.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
			continue
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	var conn net.Conn
	var err error

	// Check if TLS is enabled
	tlsConfig, tlsErr := c.loadTLSConfig()
	if tlsErr != nil {
		return fmt.Errorf("failed to load TLS config: %w", tlsErr)
	}

	if tlsConfig != nil {
		// Use TLS connection for encrypted control channel
		conn, err = tls.Dial("tcp", c.serverAddr, tlsConfig)
		if err != nil {
			return err
		}
		c.logger.Debug("Connected to server with TLS", logger.Any("addr", c.serverAddr))
	} else {
		// Use plain TCP connection
		conn, err = net.Dial("tcp", c.serverAddr)
		if err != nil {
			return err
		}
	}
	defer conn.Close()

	// Initialize Yamux Client
	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	// Open identifying stream
	stream, err := session.Open()
	if err != nil {
		return err
	}
	// Send Handshake
	handshake := c.clientID
	if c.token != "" {
		handshake += "|" + c.token
	}
	_, err = stream.Write([]byte(handshake))
	if err != nil {
		return err
	}

	// Read Ack
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		return err
	}
	resp := string(buf[:n])
	if resp != "OK" {
		conn.Close()
		return fmt.Errorf("server handshake failed: %s", resp)
	}
	
	// Accept incoming streams from Server (which represent user connections)
	for {
		serverStream, err := session.Accept()
		if err != nil {
			return err
		}

		// When server opens a stream, it means a user connected to the public port.
		// We should connect to the local target.
		go c.handleServerStream(serverStream)
	}
}

func (c *Client) handleServerStream(remote io.ReadWriteCloser) {
	defer remote.Close()

	local, err := net.Dial("tcp", c.targetAddr)
	if err != nil {
		c.logger.Error("Failed to dial local target", logger.Any("error", err))
		return
	}
	defer local.Close()

	// Bidirectional Copy
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(local, remote)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(remote, local)
		errChan <- err
	}()

	<-errChan
}
