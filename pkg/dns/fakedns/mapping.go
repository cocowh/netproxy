// Package fakedns implements IP-domain mapping for FakeDNS.
package fakedns

import (
	"container/list"
	"net"
	"sync"
	"time"
)

// Entry represents a mapping entry
type Entry struct {
	Domain    string
	IP        net.IP
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Mapping manages the bidirectional mapping between IPs and domains
type Mapping struct {
	ipToDomain   map[string]*Entry // IP string -> Entry
	domainToIP   map[string]*Entry // Domain -> Entry
	lru          *list.List        // LRU list for eviction
	lruMap       map[string]*list.Element
	pool         *Pool
	ipv6Pool     *IPv6Pool
	maxSize      int
	ttl          time.Duration
	mu           sync.RWMutex
}

// MappingConfig configures the mapping behavior
type MappingConfig struct {
	IPv4CIDR string        // IPv4 pool CIDR, e.g., "198.18.0.0/16"
	IPv6CIDR string        // IPv6 pool CIDR, e.g., "fc00::/64" (optional)
	MaxSize  int           // Maximum number of entries
	TTL      time.Duration // Time-to-live for entries
}

// DefaultMappingConfig returns the default configuration
func DefaultMappingConfig() *MappingConfig {
	return &MappingConfig{
		IPv4CIDR: "198.18.0.0/16",
		IPv6CIDR: "",
		MaxSize:  65535,
		TTL:      time.Hour,
	}
}

// NewMapping creates a new mapping with the given configuration
func NewMapping(config *MappingConfig) (*Mapping, error) {
	if config == nil {
		config = DefaultMappingConfig()
	}

	pool, err := NewPool(config.IPv4CIDR)
	if err != nil {
		return nil, err
	}

	var ipv6Pool *IPv6Pool
	if config.IPv6CIDR != "" {
		ipv6Pool, err = NewIPv6Pool(config.IPv6CIDR)
		if err != nil {
			return nil, err
		}
	}

	return &Mapping{
		ipToDomain: make(map[string]*Entry),
		domainToIP: make(map[string]*Entry),
		lru:        list.New(),
		lruMap:     make(map[string]*list.Element),
		pool:       pool,
		ipv6Pool:   ipv6Pool,
		maxSize:    config.MaxSize,
		ttl:        config.TTL,
	}, nil
}

// GetOrCreate returns the fake IP for a domain, creating one if it doesn't exist
func (m *Mapping) GetOrCreate(domain string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if domain already has a mapping
	if entry, ok := m.domainToIP[domain]; ok {
		// Update LRU
		if elem, ok := m.lruMap[domain]; ok {
			m.lru.MoveToFront(elem)
		}
		// Refresh expiration
		entry.ExpiresAt = time.Now().Add(m.ttl)
		return entry.IP, nil
	}

	// Evict if at capacity
	if len(m.domainToIP) >= m.maxSize {
		m.evictOldest()
	}

	// Allocate new IP
	ip, err := m.pool.Allocate()
	if err != nil {
		return nil, err
	}

	// Create entry
	now := time.Now()
	entry := &Entry{
		Domain:    domain,
		IP:        ip,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}

	// Store mappings
	ipStr := ip.String()
	m.ipToDomain[ipStr] = entry
	m.domainToIP[domain] = entry

	// Add to LRU
	elem := m.lru.PushFront(domain)
	m.lruMap[domain] = elem

	return ip, nil
}

// GetOrCreateIPv6 returns the fake IPv6 for a domain
func (m *Mapping) GetOrCreateIPv6(domain string) (net.IP, error) {
	if m.ipv6Pool == nil {
		return nil, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if domain already has an IPv6 mapping
	key := domain + ":v6"
	if entry, ok := m.domainToIP[key]; ok {
		entry.ExpiresAt = time.Now().Add(m.ttl)
		return entry.IP, nil
	}

	// Allocate new IPv6
	ip, err := m.ipv6Pool.Allocate()
	if err != nil {
		return nil, err
	}

	// Create entry
	now := time.Now()
	entry := &Entry{
		Domain:    domain,
		IP:        ip,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}

	// Store mappings
	ipStr := ip.String()
	m.ipToDomain[ipStr] = entry
	m.domainToIP[key] = entry

	return ip, nil
}

// Lookup returns the domain for a fake IP
func (m *Mapping) Lookup(ip net.IP) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.ipToDomain[ip.String()]
	if !ok {
		return "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.Domain, true
}

// LookupIP returns the fake IP for a domain
func (m *Mapping) LookupIP(domain string) (net.IP, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.domainToIP[domain]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.IP, true
}

// IsFakeIP checks if an IP is a fake IP from the pool
func (m *Mapping) IsFakeIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return m.pool.Contains(ip4)
	}
	if m.ipv6Pool != nil {
		return m.ipv6Pool.Contains(ip)
	}
	return false
}

// Remove removes a mapping by domain
func (m *Mapping) Remove(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.domainToIP[domain]
	if !ok {
		return
	}

	delete(m.domainToIP, domain)
	delete(m.ipToDomain, entry.IP.String())

	if elem, ok := m.lruMap[domain]; ok {
		m.lru.Remove(elem)
		delete(m.lruMap, domain)
	}
}

// Clear removes all mappings
func (m *Mapping) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ipToDomain = make(map[string]*Entry)
	m.domainToIP = make(map[string]*Entry)
	m.lru = list.New()
	m.lruMap = make(map[string]*list.Element)
}

// Size returns the current number of mappings
func (m *Mapping) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domainToIP)
}

// Cleanup removes expired entries
func (m *Mapping) Cleanup() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	for domain, entry := range m.domainToIP {
		if now.After(entry.ExpiresAt) {
			delete(m.domainToIP, domain)
			delete(m.ipToDomain, entry.IP.String())
			if elem, ok := m.lruMap[domain]; ok {
				m.lru.Remove(elem)
				delete(m.lruMap, domain)
			}
			removed++
		}
	}

	return removed
}

// evictOldest removes the oldest entry (must be called with lock held)
func (m *Mapping) evictOldest() {
	elem := m.lru.Back()
	if elem == nil {
		return
	}

	domain := elem.Value.(string)
	entry, ok := m.domainToIP[domain]
	if ok {
		delete(m.domainToIP, domain)
		delete(m.ipToDomain, entry.IP.String())
	}

	m.lru.Remove(elem)
	delete(m.lruMap, domain)
}

// GetPool returns the IPv4 pool
func (m *Mapping) GetPool() *Pool {
	return m.pool
}

// GetIPv6Pool returns the IPv6 pool
func (m *Mapping) GetIPv6Pool() *IPv6Pool {
	return m.ipv6Pool
}

// Stats returns statistics about the mapping
type Stats struct {
	TotalEntries   int
	IPv4Entries    int
	IPv6Entries    int
	ExpiredEntries int
}

// GetStats returns current statistics
func (m *Mapping) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{
		TotalEntries: len(m.domainToIP),
	}

	now := time.Now()
	for _, entry := range m.domainToIP {
		if entry.IP.To4() != nil {
			stats.IPv4Entries++
		} else {
			stats.IPv6Entries++
		}
		if now.After(entry.ExpiresAt) {
			stats.ExpiredEntries++
		}
	}

	return stats
}
