package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"

	"github.com/cocowh/netproxy/pkg/transport"
)

type tlsTransport struct {
	config *tls.Config
}

// NewTLSTransport creates a new TLS transporter
func NewTLSTransport(certFile, keyFile, caFile string, insecure bool) (transport.Transporter, error) {
	var certs []tls.Certificate
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	var rootCAs *x509.CertPool
	if caFile != "" {
		caData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		rootCAs = x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caData)
	}

	config := &tls.Config{
		Certificates:       certs,
		RootCAs:            rootCAs,
		InsecureSkipVerify: insecure,
	}

	return &tlsTransport{
		config: config,
	}, nil
}

func (t *tlsTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	// We need to clone the config to set ServerName per connection
	config := t.config.Clone()
	
	// Split host from addr
	host, _, _ := net.SplitHostPort(addr)
	if config.ServerName == "" {
		config.ServerName = host
	}

	return tls.DialWithDialer(dialer, "tcp", addr, config)
}

func (t *tlsTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, t.config), nil
}

func (t *tlsTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// TLS does not support PacketConn directly (DTLS exists but is different)
	return nil, net.UnknownNetworkError("tls does not support ListenPacket")
}

func (t *tlsTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("tls does not support DialPacket")
}
