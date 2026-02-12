// Package subscription provides rule subscription update functionality.
package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RuleType represents the type of rule file.
type RuleType string

const (
	// RuleTypeGeoIP represents GeoIP rule files
	RuleTypeGeoIP RuleType = "geoip"

	// RuleTypeGeoSite represents GeoSite rule files
	RuleTypeGeoSite RuleType = "geosite"

	// RuleTypeCustom represents custom rule files
	RuleTypeCustom RuleType = "custom"
)

// RuleSource represents a rule subscription source.
type RuleSource struct {
	// Name is the name of the rule source
	Name string `json:"name" yaml:"name"`

	// Type is the type of rule
	Type RuleType `json:"type" yaml:"type"`

	// URL is the download URL
	URL string `json:"url" yaml:"url"`

	// LocalPath is the local file path
	LocalPath string `json:"local_path" yaml:"local_path"`

	// UpdateInterval is the update interval
	UpdateInterval time.Duration `json:"update_interval" yaml:"update_interval"`

	// Checksum is the expected checksum (optional)
	Checksum string `json:"checksum" yaml:"checksum"`

	// Enabled indicates if the source is enabled
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// UpdateResult represents the result of an update operation.
type UpdateResult struct {
	Source    *RuleSource
	Success   bool
	Error     error
	UpdatedAt time.Time
	OldHash   string
	NewHash   string
	Changed   bool
}

// UpdateCallback is called when a rule is updated.
type UpdateCallback func(result *UpdateResult)

// Updater manages rule subscription updates.
type Updater struct {
	sources    []*RuleSource
	httpClient *http.Client
	dataDir    string
	callbacks  []UpdateCallback
	lastUpdate map[string]time.Time
	hashes     map[string]string
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// Config represents updater configuration.
type Config struct {
	// DataDir is the directory to store rule files
	DataDir string `json:"data_dir" yaml:"data_dir"`

	// Sources is the list of rule sources
	Sources []*RuleSource `json:"sources" yaml:"sources"`

	// HTTPTimeout is the HTTP request timeout
	HTTPTimeout time.Duration `json:"http_timeout" yaml:"http_timeout"`

	// UserAgent is the User-Agent header for HTTP requests
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		DataDir:     "./data/rules",
		HTTPTimeout: 30 * time.Second,
		UserAgent:   "NetProxy/1.0",
	}
}

// NewUpdater creates a new rule updater.
func NewUpdater(cfg Config) (*Updater, error) {
	// Create data directory if not exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}

	if cfg.UserAgent != "" {
		httpClient.Transport = &userAgentTransport{
			base:      http.DefaultTransport,
			userAgent: cfg.UserAgent,
		}
	}

	return &Updater{
		sources:    cfg.Sources,
		httpClient: httpClient,
		dataDir:    cfg.DataDir,
		lastUpdate: make(map[string]time.Time),
		hashes:     make(map[string]string),
	}, nil
}

// userAgentTransport adds User-Agent header to requests.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}

// AddSource adds a rule source.
func (u *Updater) AddSource(source *RuleSource) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sources = append(u.sources, source)
}

// RemoveSource removes a rule source by name.
func (u *Updater) RemoveSource(name string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	for i, s := range u.sources {
		if s.Name == name {
			u.sources = append(u.sources[:i], u.sources[i+1:]...)
			return
		}
	}
}

// GetSources returns all rule sources.
func (u *Updater) GetSources() []*RuleSource {
	u.mu.RLock()
	defer u.mu.RUnlock()

	sources := make([]*RuleSource, len(u.sources))
	copy(sources, u.sources)
	return sources
}

// OnUpdate registers a callback for update events.
func (u *Updater) OnUpdate(callback UpdateCallback) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.callbacks = append(u.callbacks, callback)
}

// Start starts the automatic update loop.
func (u *Updater) Start(ctx context.Context) error {
	u.ctx, u.cancel = context.WithCancel(ctx)

	// Load existing hashes
	u.loadHashes()

	// Initial update
	u.UpdateAll()

	// Start update loops for each source
	u.mu.RLock()
	for _, source := range u.sources {
		if source.Enabled && source.UpdateInterval > 0 {
			u.wg.Add(1)
			go u.updateLoop(source)
		}
	}
	u.mu.RUnlock()

	return nil
}

// Stop stops the automatic update loop.
func (u *Updater) Stop() error {
	if u.cancel != nil {
		u.cancel()
	}
	u.wg.Wait()
	return nil
}

// updateLoop runs the update loop for a single source.
func (u *Updater) updateLoop(source *RuleSource) {
	defer u.wg.Done()

	ticker := time.NewTicker(source.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			u.Update(source)
		}
	}
}

// UpdateAll updates all enabled sources.
func (u *Updater) UpdateAll() []*UpdateResult {
	u.mu.RLock()
	sources := make([]*RuleSource, len(u.sources))
	copy(sources, u.sources)
	u.mu.RUnlock()

	var results []*UpdateResult
	for _, source := range sources {
		if source.Enabled {
			result := u.Update(source)
			results = append(results, result)
		}
	}
	return results
}

// Update updates a single source.
func (u *Updater) Update(source *RuleSource) *UpdateResult {
	result := &UpdateResult{
		Source:    source,
		UpdatedAt: time.Now(),
	}

	// Get old hash
	u.mu.RLock()
	result.OldHash = u.hashes[source.Name]
	u.mu.RUnlock()

	// Download file
	data, err := u.download(source.URL)
	if err != nil {
		result.Error = fmt.Errorf("failed to download: %w", err)
		u.notifyCallbacks(result)
		return result
	}

	// Calculate hash
	hash := sha256.Sum256(data)
	result.NewHash = hex.EncodeToString(hash[:])

	// Check if changed
	result.Changed = result.OldHash != result.NewHash

	// Verify checksum if provided
	if source.Checksum != "" && result.NewHash != source.Checksum {
		result.Error = fmt.Errorf("checksum mismatch: expected %s, got %s", source.Checksum, result.NewHash)
		u.notifyCallbacks(result)
		return result
	}

	// Determine local path
	localPath := source.LocalPath
	if localPath == "" {
		localPath = filepath.Join(u.dataDir, source.Name)
	}

	// Write file
	if err := u.writeFile(localPath, data); err != nil {
		result.Error = fmt.Errorf("failed to write file: %w", err)
		u.notifyCallbacks(result)
		return result
	}

	// Update state
	u.mu.Lock()
	u.hashes[source.Name] = result.NewHash
	u.lastUpdate[source.Name] = result.UpdatedAt
	u.mu.Unlock()

	result.Success = true
	u.notifyCallbacks(result)
	return result
}

// download downloads a file from URL.
func (u *Updater) download(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(u.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Limit download size to 100MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	if err != nil {
		return nil, err
	}

	return data, nil
}

// writeFile writes data to a file atomically.
func (u *Updater) writeFile(path string, data []byte) error {
	// Create directory if not exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write to temp file first
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return err
	}

	// Rename to final path
	return os.Rename(tempPath, path)
}

// loadHashes loads existing file hashes.
func (u *Updater) loadHashes() {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, source := range u.sources {
		localPath := source.LocalPath
		if localPath == "" {
			localPath = filepath.Join(u.dataDir, source.Name)
		}

		data, err := os.ReadFile(localPath)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(data)
		u.hashes[source.Name] = hex.EncodeToString(hash[:])
	}
}

// notifyCallbacks notifies all registered callbacks.
func (u *Updater) notifyCallbacks(result *UpdateResult) {
	u.mu.RLock()
	callbacks := make([]UpdateCallback, len(u.callbacks))
	copy(callbacks, u.callbacks)
	u.mu.RUnlock()

	for _, callback := range callbacks {
		callback(result)
	}
}

// GetLastUpdate returns the last update time for a source.
func (u *Updater) GetLastUpdate(name string) (time.Time, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	t, ok := u.lastUpdate[name]
	return t, ok
}

// GetHash returns the current hash for a source.
func (u *Updater) GetHash(name string) (string, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	h, ok := u.hashes[name]
	return h, ok
}

// ForceUpdate forces an immediate update of a source by name.
func (u *Updater) ForceUpdate(name string) *UpdateResult {
	u.mu.RLock()
	var source *RuleSource
	for _, s := range u.sources {
		if s.Name == name {
			source = s
			break
		}
	}
	u.mu.RUnlock()

	if source == nil {
		return &UpdateResult{
			Error: fmt.Errorf("source not found: %s", name),
		}
	}

	return u.Update(source)
}

// DefaultSources returns a list of default rule sources.
func DefaultSources() []*RuleSource {
	return []*RuleSource{
		{
			Name:           "geoip.dat",
			Type:           RuleTypeGeoIP,
			URL:            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
			UpdateInterval: 24 * time.Hour,
			Enabled:        true,
		},
		{
			Name:           "geosite.dat",
			Type:           RuleTypeGeoSite,
			URL:            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
			UpdateInterval: 24 * time.Hour,
			Enabled:        true,
		},
	}
}
