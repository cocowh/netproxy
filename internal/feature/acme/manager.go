// Package acme provides automatic TLS certificate management using ACME protocol.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Config represents ACME configuration.
type Config struct {
	// Email is the account email for ACME registration
	Email string `json:"email" yaml:"email"`

	// Domains is the list of domains to obtain certificates for
	Domains []string `json:"domains" yaml:"domains"`

	// CacheDir is the directory to cache certificates and account keys
	CacheDir string `json:"cache_dir" yaml:"cache_dir"`

	// DirectoryURL is the ACME directory URL
	// Default: Let's Encrypt production
	DirectoryURL string `json:"directory_url" yaml:"directory_url"`

	// RenewBefore is how long before expiry to renew certificates
	RenewBefore time.Duration `json:"renew_before" yaml:"renew_before"`

	// HTTPChallenge enables HTTP-01 challenge
	HTTPChallenge bool `json:"http_challenge" yaml:"http_challenge"`

	// HTTPChallengePort is the port for HTTP-01 challenge (default: 80)
	HTTPChallengePort int `json:"http_challenge_port" yaml:"http_challenge_port"`

	// TLSChallenge enables TLS-ALPN-01 challenge
	TLSChallenge bool `json:"tls_challenge" yaml:"tls_challenge"`

	// TLSChallengePort is the port for TLS-ALPN-01 challenge (default: 443)
	TLSChallengePort int `json:"tls_challenge_port" yaml:"tls_challenge_port"`

	// DNSChallenge enables DNS-01 challenge
	DNSChallenge bool `json:"dns_challenge" yaml:"dns_challenge"`

	// DNSProvider is the DNS provider for DNS-01 challenge
	DNSProvider string `json:"dns_provider" yaml:"dns_provider"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		CacheDir:          "./data/acme",
		DirectoryURL:      "https://acme-v02.api.letsencrypt.org/directory",
		RenewBefore:       30 * 24 * time.Hour, // 30 days
		HTTPChallenge:     true,
		HTTPChallengePort: 80,
		TLSChallengePort:  443,
	}
}

// LetsEncryptStagingURL is the Let's Encrypt staging directory URL.
const LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Manager manages ACME certificates.
type Manager struct {
	config     Config
	client     *acme.Client
	accountKey crypto.Signer
	cache      *certCache
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// certCache caches certificates.
type certCache struct {
	certs map[string]*tls.Certificate
	mu    sync.RWMutex
}

// NewManager creates a new ACME manager.
func NewManager(cfg Config) (*Manager, error) {
	// Create cache directory
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	m := &Manager{
		config: cfg,
		cache: &certCache{
			certs: make(map[string]*tls.Certificate),
		},
	}

	// Load or create account key
	accountKey, err := m.loadOrCreateAccountKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load account key: %w", err)
	}
	m.accountKey = accountKey

	// Create ACME client
	m.client = &acme.Client{
		Key:          accountKey,
		DirectoryURL: cfg.DirectoryURL,
	}

	return m, nil
}

// loadOrCreateAccountKey loads or creates the account private key.
func (m *Manager) loadOrCreateAccountKey() (crypto.Signer, error) {
	keyPath := filepath.Join(m.config.CacheDir, "account.key")

	// Try to load existing key
	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "EC PRIVATE KEY" {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	// Generate new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Save key
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}

	return key, nil
}

// Start starts the certificate manager.
func (m *Manager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Register account if needed
	if err := m.registerAccount(); err != nil {
		return fmt.Errorf("failed to register account: %w", err)
	}

	// Load cached certificates
	m.loadCachedCerts()

	// Obtain certificates for configured domains
	for _, domain := range m.config.Domains {
		if _, err := m.GetCertificate(domain); err != nil {
			return fmt.Errorf("failed to obtain certificate for %s: %w", domain, err)
		}
	}

	// Start renewal loop
	go m.renewalLoop()

	return nil
}

// Stop stops the certificate manager.
func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// registerAccount registers the ACME account.
func (m *Manager) registerAccount() error {
	// Check if account is already registered
	accountPath := filepath.Join(m.config.CacheDir, "account.json")
	if _, err := os.Stat(accountPath); err == nil {
		return nil // Already registered
	}

	// Register new account
	account := &acme.Account{
		Contact: []string{"mailto:" + m.config.Email},
	}

	_, err := m.client.Register(m.ctx, account, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return err
	}

	// Save account info
	data, _ := json.Marshal(account)
	return os.WriteFile(accountPath, data, 0600)
}

// GetCertificate returns a certificate for the given domain.
func (m *Manager) GetCertificate(domain string) (*tls.Certificate, error) {
	// Check cache
	m.cache.mu.RLock()
	cert, ok := m.cache.certs[domain]
	m.cache.mu.RUnlock()

	if ok && !m.needsRenewal(cert) {
		return cert, nil
	}

	// Obtain new certificate
	return m.obtainCertificate(domain)
}

// GetCertificateFunc returns a function suitable for tls.Config.GetCertificate.
func (m *Manager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.GetCertificate(hello.ServerName)
	}
}

// obtainCertificate obtains a new certificate for the domain.
func (m *Manager) obtainCertificate(domain string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check cache
	m.cache.mu.RLock()
	cert, ok := m.cache.certs[domain]
	m.cache.mu.RUnlock()

	if ok && !m.needsRenewal(cert) {
		return cert, nil
	}

	// Try to load from disk
	cert, err := m.loadCertFromDisk(domain)
	if err == nil && !m.needsRenewal(cert) {
		m.cache.mu.Lock()
		m.cache.certs[domain] = cert
		m.cache.mu.Unlock()
		return cert, nil
	}

	// Create new order
	order, err := m.client.AuthorizeOrder(m.ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}

	// Complete challenges
	for _, authzURL := range order.AuthzURLs {
		authz, err := m.client.GetAuthorization(m.ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get authorization: %w", err)
		}

		if authz.Status == acme.StatusValid {
			continue
		}

		// Find and complete challenge
		if err := m.completeChallenge(authz); err != nil {
			return nil, fmt.Errorf("failed to complete challenge: %w", err)
		}
	}

	// Wait for order to be ready
	order, err = m.client.WaitOrder(m.ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for order: %w", err)
	}

	// Generate certificate key
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Finalize order
	der, _, err := m.client.CreateOrderCert(m.ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize order: %w", err)
	}

	// Parse certificate
	var certPEM []byte
	for _, b := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		})...)
	}

	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// Save to disk
	if err := m.saveCertToDisk(domain, certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Update cache
	m.cache.mu.Lock()
	m.cache.certs[domain] = &tlsCert
	m.cache.mu.Unlock()

	return &tlsCert, nil
}

// completeChallenge completes an ACME challenge.
func (m *Manager) completeChallenge(authz *acme.Authorization) error {
	var challenge *acme.Challenge

	// Find supported challenge
	for _, c := range authz.Challenges {
		switch c.Type {
		case "http-01":
			if m.config.HTTPChallenge {
				challenge = c
			}
		case "tls-alpn-01":
			if m.config.TLSChallenge {
				challenge = c
			}
		case "dns-01":
			if m.config.DNSChallenge {
				challenge = c
			}
		}
		if challenge != nil {
			break
		}
	}

	if challenge == nil {
		return errors.New("no supported challenge found")
	}

	// Accept challenge
	_, err := m.client.Accept(m.ctx, challenge)
	if err != nil {
		return fmt.Errorf("failed to accept challenge: %w", err)
	}

	// Wait for authorization
	_, err = m.client.WaitAuthorization(m.ctx, authz.URI)
	return err
}

// needsRenewal checks if a certificate needs renewal.
func (m *Manager) needsRenewal(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return true
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}

	return time.Until(x509Cert.NotAfter) < m.config.RenewBefore
}

// loadCertFromDisk loads a certificate from disk.
func (m *Manager) loadCertFromDisk(domain string) (*tls.Certificate, error) {
	certPath := filepath.Join(m.config.CacheDir, domain+".crt")
	keyPath := filepath.Join(m.config.CacheDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// saveCertToDisk saves a certificate to disk.
func (m *Manager) saveCertToDisk(domain string, certPEM, keyPEM []byte) error {
	certPath := filepath.Join(m.config.CacheDir, domain+".crt")
	keyPath := filepath.Join(m.config.CacheDir, domain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	return os.WriteFile(keyPath, keyPEM, 0600)
}

// loadCachedCerts loads all cached certificates.
func (m *Manager) loadCachedCerts() {
	for _, domain := range m.config.Domains {
		cert, err := m.loadCertFromDisk(domain)
		if err == nil {
			m.cache.mu.Lock()
			m.cache.certs[domain] = cert
			m.cache.mu.Unlock()
		}
	}
}

// renewalLoop periodically checks and renews certificates.
func (m *Manager) renewalLoop() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.renewCertificates()
		}
	}
}

// renewCertificates renews certificates that need renewal.
func (m *Manager) renewCertificates() {
	m.cache.mu.RLock()
	domains := make([]string, 0, len(m.cache.certs))
	for domain, cert := range m.cache.certs {
		if m.needsRenewal(cert) {
			domains = append(domains, domain)
		}
	}
	m.cache.mu.RUnlock()

	for _, domain := range domains {
		if _, err := m.obtainCertificate(domain); err != nil {
			// Log error but continue with other domains
			continue
		}
	}
}

// GetTLSConfig returns a TLS config that uses ACME certificates.
func (m *Manager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
	}
}
