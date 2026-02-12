// Package doh provides DNS-over-HTTPS server implementation.
package doh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config represents DoH server configuration.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":443")
	ListenAddr string `json:"listen_addr" yaml:"listen_addr"`

	// Path is the URL path for DoH queries (default: "/dns-query")
	Path string `json:"path" yaml:"path"`

	// Upstream is the upstream DNS server address
	Upstream string `json:"upstream" yaml:"upstream"`

	// TLSCertFile is the path to the TLS certificate file
	TLSCertFile string `json:"tls_cert_file" yaml:"tls_cert_file"`

	// TLSKeyFile is the path to the TLS key file
	TLSKeyFile string `json:"tls_key_file" yaml:"tls_key_file"`

	// Timeout is the query timeout
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// MaxBodySize is the maximum request body size
	MaxBodySize int64 `json:"max_body_size" yaml:"max_body_size"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:  ":443",
		Path:        "/dns-query",
		Upstream:    "8.8.8.8:53",
		Timeout:     5 * time.Second,
		MaxBodySize: 65535,
	}
}

// Server implements a DNS-over-HTTPS server.
type Server struct {
	config     Config
	httpServer *http.Server
	dnsClient  *dns.Client
}

// NewServer creates a new DoH server.
func NewServer(cfg Config) *Server {
	if cfg.Path == "" {
		cfg.Path = "/dns-query"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 65535
	}

	return &Server{
		config: cfg,
		dnsClient: &dns.Client{
			Net:     "udp",
			Timeout: cfg.Timeout,
		},
	}
}

// Start starts the DoH server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.config.Path, s.handleDNSQuery)

	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  s.config.Timeout,
		WriteTimeout: s.config.Timeout,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			err = s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

// Stop stops the DoH server.
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleDNSQuery handles DNS-over-HTTPS queries.
func (s *Server) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	// Check content type
	contentType := r.Header.Get("Content-Type")

	var dnsMsg *dns.Msg
	var err error

	switch r.Method {
	case http.MethodGet:
		// GET method: DNS query in URL parameter
		dnsMsg, err = s.parseDNSFromGET(r)
	case http.MethodPost:
		// POST method: DNS query in body
		if contentType != "application/dns-message" {
			http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		dnsMsg, err = s.parseDNSFromPOST(r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse DNS query: %v", err), http.StatusBadRequest)
		return
	}

	// Forward query to upstream
	response, err := s.forwardQuery(dnsMsg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to forward query: %v", err), http.StatusBadGateway)
		return
	}

	// Pack response
	responseBytes, err := response.Pack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to pack response: %v", err), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", s.getTTL(response)))
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

// parseDNSFromGET parses DNS query from GET request.
func (s *Server) parseDNSFromGET(r *http.Request) (*dns.Msg, error) {
	// Get dns parameter
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing dns parameter")
	}

	// Decode base64url
	// Add padding if necessary
	if m := len(dnsParam) % 4; m != 0 {
		dnsParam += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.URLEncoding.DecodeString(dnsParam)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, fmt.Errorf("failed to decode dns parameter: %w", err)
		}
	}

	// Unpack DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(decoded); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return msg, nil
}

// parseDNSFromPOST parses DNS query from POST request.
func (s *Server) parseDNSFromPOST(r *http.Request) (*dns.Msg, error) {
	// Read body with size limit
	body, err := io.ReadAll(io.LimitReader(r.Body, s.config.MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unpack DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return msg, nil
}

// forwardQuery forwards a DNS query to the upstream server.
func (s *Server) forwardQuery(query *dns.Msg) (*dns.Msg, error) {
	response, _, err := s.dnsClient.Exchange(query, s.config.Upstream)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// getTTL returns the minimum TTL from the response.
func (s *Server) getTTL(response *dns.Msg) int {
	minTTL := 300 // Default 5 minutes

	for _, rr := range response.Answer {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, rr := range response.Ns {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, rr := range response.Extra {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	if minTTL < 0 {
		minTTL = 0
	}

	return minTTL
}

// Resolver implements a DoH client for resolving DNS queries.
type Resolver struct {
	serverURL  string
	httpClient *http.Client
}

// NewResolver creates a new DoH resolver.
func NewResolver(serverURL string) *Resolver {
	return &Resolver{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Resolve resolves a DNS query using DoH.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) ([]net.IP, error) {
	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	// Pack query
	queryBytes, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack query: %w", err)
	}

	// Encode as base64url
	encoded := base64.RawURLEncoding.EncodeToString(queryBytes)

	// Build URL
	url := fmt.Sprintf("%s?dns=%s", r.serverURL, encoded)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack response
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
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
