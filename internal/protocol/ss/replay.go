// Package ss implements replay attack protection for Shadowsocks.
// It uses a Bloom filter to efficiently detect and reject replayed packets.
package ss

import (
	"hash"
	"hash/fnv"
	"sync"
	"time"
)

// Filter is a time-based Bloom filter for replay attack detection
type Filter struct {
	current    *bloomFilter
	previous   *bloomFilter
	interval   time.Duration
	lastRotate time.Time
	mu         sync.RWMutex
}

// FilterConfig configures the replay filter
type FilterConfig struct {
	// Size is the number of bits in the Bloom filter
	Size uint32
	// HashCount is the number of hash functions
	HashCount uint32
	// Interval is the rotation interval
	Interval time.Duration
}

// DefaultFilterConfig returns the default configuration
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		Size:      1 << 20, // 1M bits = 128KB
		HashCount: 4,
		Interval:  time.Minute * 2,
	}
}

// NewFilter creates a new replay filter
func NewFilter(config *FilterConfig) *Filter {
	if config == nil {
		config = DefaultFilterConfig()
	}

	return &Filter{
		current:    newBloomFilter(config.Size, config.HashCount),
		previous:   newBloomFilter(config.Size, config.HashCount),
		interval:   config.Interval,
		lastRotate: time.Now(),
	}
}

// Check checks if the data has been seen before and adds it to the filter
// Returns true if this is a replay (data was seen before)
func (f *Filter) Check(data []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Rotate filters if needed
	f.maybeRotate()

	// Check if seen in current or previous filter
	if f.current.Contains(data) || f.previous.Contains(data) {
		return true // Replay detected
	}

	// Add to current filter
	f.current.Add(data)
	return false
}

// maybeRotate rotates the filters if the interval has passed
// Must be called with lock held
func (f *Filter) maybeRotate() {
	now := time.Now()
	if now.Sub(f.lastRotate) >= f.interval {
		// Rotate: current becomes previous, create new current
		f.previous = f.current
		f.current = newBloomFilter(f.current.size, f.current.hashCount)
		f.lastRotate = now
	}
}

// Reset clears both filters
func (f *Filter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.current.Reset()
	f.previous.Reset()
	f.lastRotate = time.Now()
}

// Stats returns statistics about the filter
type Stats struct {
	CurrentCount  uint64
	PreviousCount uint64
	Size          uint32
	HashCount     uint32
	LastRotate    time.Time
}

// GetStats returns current statistics
func (f *Filter) GetStats() Stats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return Stats{
		CurrentCount:  f.current.count,
		PreviousCount: f.previous.count,
		Size:          f.current.size,
		HashCount:     f.current.hashCount,
		LastRotate:    f.lastRotate,
	}
}

// bloomFilter is a simple Bloom filter implementation
type bloomFilter struct {
	bits      []uint64
	size      uint32
	hashCount uint32
	count     uint64
	hasher    hash.Hash64
}

// newBloomFilter creates a new Bloom filter
func newBloomFilter(size, hashCount uint32) *bloomFilter {
	// Round up to multiple of 64
	numWords := (size + 63) / 64
	return &bloomFilter{
		bits:      make([]uint64, numWords),
		size:      numWords * 64,
		hashCount: hashCount,
		hasher:    fnv.New64a(),
	}
}

// Add adds data to the filter
func (bf *bloomFilter) Add(data []byte) {
	h1, h2 := bf.hash(data)
	for i := uint32(0); i < bf.hashCount; i++ {
		pos := (h1 + i*h2) % bf.size
		bf.setBit(pos)
	}
	bf.count++
}

// Contains checks if data might be in the filter
func (bf *bloomFilter) Contains(data []byte) bool {
	h1, h2 := bf.hash(data)
	for i := uint32(0); i < bf.hashCount; i++ {
		pos := (h1 + i*h2) % bf.size
		if !bf.getBit(pos) {
			return false
		}
	}
	return true
}

// Reset clears the filter
func (bf *bloomFilter) Reset() {
	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

// hash computes two hash values for double hashing
func (bf *bloomFilter) hash(data []byte) (uint32, uint32) {
	bf.hasher.Reset()
	bf.hasher.Write(data)
	h := bf.hasher.Sum64()
	return uint32(h), uint32(h >> 32)
}

// setBit sets a bit at the given position
func (bf *bloomFilter) setBit(pos uint32) {
	word := pos / 64
	bit := pos % 64
	bf.bits[word] |= 1 << bit
}

// getBit gets a bit at the given position
func (bf *bloomFilter) getBit(pos uint32) bool {
	word := pos / 64
	bit := pos % 64
	return (bf.bits[word] & (1 << bit)) != 0
}

// SaltFilter is a replay filter that uses salt + IV for detection
type SaltFilter struct {
	filter *Filter
}

// NewSaltFilter creates a new salt-based replay filter
func NewSaltFilter(config *FilterConfig) *SaltFilter {
	return &SaltFilter{
		filter: NewFilter(config),
	}
}

// Check checks if the salt+IV combination has been seen
func (sf *SaltFilter) Check(salt, iv []byte) bool {
	// Combine salt and IV for checking
	combined := make([]byte, len(salt)+len(iv))
	copy(combined, salt)
	copy(combined[len(salt):], iv)
	return sf.filter.Check(combined)
}

// Reset clears the filter
func (sf *SaltFilter) Reset() {
	sf.filter.Reset()
}

// GetStats returns statistics
func (sf *SaltFilter) GetStats() Stats {
	return sf.filter.GetStats()
}

// NonceFilter is a replay filter specifically for AEAD nonces
type NonceFilter struct {
	seen map[string]time.Time
	ttl  time.Duration
	mu   sync.RWMutex
}

// NewNonceFilter creates a new nonce-based replay filter
func NewNonceFilter(ttl time.Duration) *NonceFilter {
	if ttl == 0 {
		ttl = time.Minute * 5
	}
	nf := &NonceFilter{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
	go nf.cleanup()
	return nf
}

// Check checks if the nonce has been seen
func (nf *NonceFilter) Check(nonce []byte) bool {
	key := string(nonce)

	nf.mu.Lock()
	defer nf.mu.Unlock()

	if _, exists := nf.seen[key]; exists {
		return true // Replay
	}

	nf.seen[key] = time.Now()
	return false
}

// cleanup periodically removes expired entries
func (nf *NonceFilter) cleanup() {
	ticker := time.NewTicker(nf.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		nf.mu.Lock()
		now := time.Now()
		for key, t := range nf.seen {
			if now.Sub(t) > nf.ttl {
				delete(nf.seen, key)
			}
		}
		nf.mu.Unlock()
	}
}

// Size returns the number of stored nonces
func (nf *NonceFilter) Size() int {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return len(nf.seen)
}

// Reset clears all stored nonces
func (nf *NonceFilter) Reset() {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.seen = make(map[string]time.Time)
}
