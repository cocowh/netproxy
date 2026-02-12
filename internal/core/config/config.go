package config

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config holds the global configuration
type Config struct {
	Listeners    []ListenerConfig       `mapstructure:"listeners"`
	Log          LogConfig              `mapstructure:"log"`
	Auth         AuthConfig             `mapstructure:"auth"`
	DNS          DNSConfig              `mapstructure:"dns"`
	Modules      map[string]interface{} `mapstructure:"modules"`
	Tunnel       TunnelConfig           `mapstructure:"tunnel"`
	Routing      RoutingConfig          `mapstructure:"routing"`
	Admin        AdminConfig            `mapstructure:"admin"`
	Users        UsersConfig            `mapstructure:"users"`
	TUN          TUNConfig              `mapstructure:"tun"`
	TPROXY       TPROXYConfig           `mapstructure:"tproxy"`
	FakeDNS      FakeDNSConfig          `mapstructure:"fakedns"`
	ACME         ACMEConfig             `mapstructure:"acme"`
	Health       HealthConfig           `mapstructure:"health"`
	Metrics      MetricsConfig          `mapstructure:"metrics"`
	Subscription SubscriptionConfig     `mapstructure:"subscription"`
}

// UsersConfig holds user management configuration
type UsersConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	StoreType   string `mapstructure:"store_type"`   // "memory" or "sqlite"
	SQLitePath  string `mapstructure:"sqlite_path"`  // Path to SQLite database
	DefaultQuota int64 `mapstructure:"default_quota"` // Default traffic quota in bytes
}

// TUNConfig holds TUN device configuration
type TUNConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Name    string   `mapstructure:"name"`    // Device name (e.g., "tun0" or "utun0")
	MTU     int      `mapstructure:"mtu"`     // MTU size
	Address string   `mapstructure:"address"` // IP address (e.g., "10.0.0.1/24")
	Gateway string   `mapstructure:"gateway"` // Gateway address
	Routes  []string `mapstructure:"routes"`  // Routes to add
}

// TPROXYConfig holds transparent proxy configuration
type TPROXYConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Addr    string `mapstructure:"addr"`     // Listen address
	Mark    int    `mapstructure:"mark"`     // Firewall mark for routing
	Table   int    `mapstructure:"table"`    // Routing table number
}

// FakeDNSConfig holds FakeDNS configuration
type FakeDNSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	IPRange  string `mapstructure:"ip_range"`  // IP range for fake IPs (e.g., "198.18.0.0/16")
	PoolSize int    `mapstructure:"pool_size"` // Size of IP pool
}

// ACMEConfig holds ACME certificate configuration
type ACMEConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	Email             string        `mapstructure:"email"`
	Domains           []string      `mapstructure:"domains"`
	CacheDir          string        `mapstructure:"cache_dir"`
	DirectoryURL      string        `mapstructure:"directory_url"`
	RenewBefore       time.Duration `mapstructure:"renew_before"`
	HTTPChallenge     bool          `mapstructure:"http_challenge"`
	HTTPChallengePort int           `mapstructure:"http_challenge_port"`
	TLSChallenge      bool          `mapstructure:"tls_challenge"`
	TLSChallengePort  int           `mapstructure:"tls_challenge_port"`
}

// HealthConfig holds health check configuration
type HealthConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Interval       time.Duration `mapstructure:"interval"`
	DefaultTimeout time.Duration `mapstructure:"default_timeout"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Addr    string `mapstructure:"addr"` // Prometheus metrics endpoint address
}

// SubscriptionConfig holds subscription update configuration
type SubscriptionConfig struct {
	Enabled bool                     `mapstructure:"enabled"`
	Sources []SubscriptionSourceConfig `mapstructure:"sources"`
}

// SubscriptionSourceConfig holds a single subscription source configuration
type SubscriptionSourceConfig struct {
	Name           string        `mapstructure:"name"`
	Type           string        `mapstructure:"type"`            // "geoip", "geosite", "rules"
	URL            string        `mapstructure:"url"`
	LocalPath      string        `mapstructure:"local_path"`
	UpdateInterval time.Duration `mapstructure:"update_interval"`
	Enabled        bool          `mapstructure:"enabled"`
}

type AdminConfig struct {
	Addr  string    `mapstructure:"addr"`
	Token string    `mapstructure:"token"`
	TLS   TLSConfig `mapstructure:"tls"` // TLS configuration for HTTPS
}

type DNSConfig struct {
	Enabled  bool              `mapstructure:"enabled"`
	Addr     string            `mapstructure:"addr"`
	Upstream string            `mapstructure:"upstream"`
	Rules    map[string]string `mapstructure:"rules"` // domain -> upstream
}

type RoutingConfig struct {
	GeoIP     string   `mapstructure:"geoip"`
	Rules     []string `mapstructure:"rules"`
	Upstreams []string `mapstructure:"upstreams"`
	RemoteDNS string   `mapstructure:"remote_dns"`
}

type TunnelConfig struct {
	Mode        string            `mapstructure:"mode"` // "bridge", "client", or empty
	ControlAddr string            `mapstructure:"control_addr"`
	DataAddr    string            `mapstructure:"data_addr"` // Deprecated
	Tunnels     map[string]string `mapstructure:"tunnels"`   // port -> client_id mapping
	ServerAddr  string            `mapstructure:"server_addr"`
	TargetAddr  string            `mapstructure:"target_addr"`
	ClientID    string            `mapstructure:"client_id"`
	Token       string            `mapstructure:"token"`
	TLS         TLSConfig         `mapstructure:"tls"` // TLS configuration for encrypted tunnel
}

// TLSConfig holds TLS configuration for secure connections
type TLSConfig struct {
	Enabled    bool   `mapstructure:"enabled"`     // Enable TLS encryption
	CertFile   string `mapstructure:"cert_file"`   // Path to certificate file (for server/bridge)
	KeyFile    string `mapstructure:"key_file"`    // Path to private key file (for server/bridge)
	CAFile     string `mapstructure:"ca_file"`     // Path to CA certificate file (for client verification)
	ServerName string `mapstructure:"server_name"` // Server name for client verification (SNI)
	SkipVerify bool   `mapstructure:"skip_verify"` // Skip certificate verification (not recommended for production)
}

type ListenerConfig struct {
	Protocol  string                 `mapstructure:"protocol"`
	Transport string                 `mapstructure:"transport"`
	Addr      string                 `mapstructure:"addr"`
	Announce  string                 `mapstructure:"announce"`
	RateLimit RateLimitConfig        `mapstructure:"rate_limit"`
	Options   map[string]interface{} `mapstructure:"options"`
}

type RateLimitConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Limit   int  `mapstructure:"limit"` // events per second
	Burst   int  `mapstructure:"burst"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
	Path  string `mapstructure:"path"`
}

type AuthConfig struct {
	Type   string            `mapstructure:"type"`
	Params map[string]string `mapstructure:"params"`
}

// Manager defines the configuration manager interface
type Manager interface {
	Load() error
	GetConfig() *Config
	Watch(onChange func(newConfig *Config))
	Save() error
}

type viperManager struct {
	v      *viper.Viper
	config *Config
	mu     sync.RWMutex
}

// NewManager creates a new configuration manager
func NewManager(configPath string) Manager {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetEnvPrefix("NETPROXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults
	v.SetDefault("listeners", []map[string]interface{}{
		{"protocol": "socks5", "transport": "tcp", "addr": ":1080"},
		{"protocol": "http", "transport": "tcp", "addr": ":8080"},
	})
	v.SetDefault("log.level", "info")
	v.SetDefault("log.path", "")

	return &viperManager{
		v:      v,
		config: &Config{},
	}
}

func (m *viperManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.v.ReadInConfig(); err != nil {
		// If config file not found, we can proceed with defaults/env
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	if err := m.v.Unmarshal(m.config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func (m *viperManager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *viperManager) Watch(onChange func(newConfig *Config)) {
	m.v.OnConfigChange(func(e fsnotify.Event) {
		m.mu.Lock()
		// Reload config
		if err := m.v.Unmarshal(m.config); err == nil {
			// Notify listener
			if onChange != nil {
				// Execute callback in a separate goroutine to avoid blocking
				go onChange(m.config)
			}
		}
		m.mu.Unlock()
	})
	m.v.WatchConfig()
}

func (m *viperManager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.v.WriteConfig()
}
