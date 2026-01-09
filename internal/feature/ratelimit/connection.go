package ratelimit

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ErrConnectionLimitExceeded is returned when the connection limit is exceeded
var ErrConnectionLimitExceeded = errors.New("connection limit exceeded")

// ConnectionLimiter limits the number of concurrent connections
type ConnectionLimiter struct {
	mu       sync.Mutex
	counts   map[string]int64
	maxConns int64
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(maxConns int64) *ConnectionLimiter {
	return &ConnectionLimiter{
		counts:   make(map[string]int64),
		maxConns: maxConns,
	}
}

// Allow checks if a new connection is allowed for the given key
func (l *ConnectionLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[key] >= l.maxConns {
		return false
	}
	l.counts[key]++
	return true
}

// Release releases a connection for the given key
func (l *ConnectionLimiter) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[key] > 0 {
		l.counts[key]--
	}
	// Clean up zero counts to prevent memory leak
	if l.counts[key] == 0 {
		delete(l.counts, key)
	}
}

// GetCount returns the current connection count for a key
func (l *ConnectionLimiter) GetCount(key string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[key]
}

// GetTotalCount returns the total connection count across all keys
func (l *ConnectionLimiter) GetTotalCount() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	var total int64
	for _, count := range l.counts {
		total += count
	}
	return total
}

// GetAllCounts returns all connection counts
func (l *ConnectionLimiter) GetAllCounts() map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := make(map[string]int64, len(l.counts))
	for k, v := range l.counts {
		result[k] = v
	}
	return result
}

// SetMaxConns updates the maximum connections limit
func (l *ConnectionLimiter) SetMaxConns(maxConns int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxConns = maxConns
}

// GetMaxConns returns the maximum connections limit
func (l *ConnectionLimiter) GetMaxConns() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxConns
}

// MultiKeyConnectionLimiter supports multiple limiting dimensions
type MultiKeyConnectionLimiter struct {
	mu       sync.Mutex
	// Global limit
	globalLimit int64
	globalCount int64
	// Per-key limits (e.g., per IP, per user)
	keyLimits map[string]int64 // key -> max connections
	keyCounts map[string]int64 // key -> current count
	// Default per-key limit
	defaultKeyLimit int64
}

// NewMultiKeyConnectionLimiter creates a new multi-key connection limiter
func NewMultiKeyConnectionLimiter(globalLimit, defaultKeyLimit int64) *MultiKeyConnectionLimiter {
	return &MultiKeyConnectionLimiter{
		globalLimit:     globalLimit,
		defaultKeyLimit: defaultKeyLimit,
		keyLimits:       make(map[string]int64),
		keyCounts:       make(map[string]int64),
	}
}

// SetKeyLimit sets a custom limit for a specific key
func (l *MultiKeyConnectionLimiter) SetKeyLimit(key string, limit int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keyLimits[key] = limit
}

// Allow checks if a new connection is allowed
func (l *MultiKeyConnectionLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check global limit
	if l.globalLimit > 0 && l.globalCount >= l.globalLimit {
		return false
	}

	// Check per-key limit
	keyLimit := l.defaultKeyLimit
	if customLimit, ok := l.keyLimits[key]; ok {
		keyLimit = customLimit
	}

	if keyLimit > 0 && l.keyCounts[key] >= keyLimit {
		return false
	}

	// Increment counts
	l.globalCount++
	l.keyCounts[key]++
	return true
}

// Release releases a connection
func (l *MultiKeyConnectionLimiter) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.globalCount > 0 {
		l.globalCount--
	}

	if l.keyCounts[key] > 0 {
		l.keyCounts[key]--
	}

	// Clean up zero counts
	if l.keyCounts[key] == 0 {
		delete(l.keyCounts, key)
	}
}

// GetGlobalCount returns the global connection count
func (l *MultiKeyConnectionLimiter) GetGlobalCount() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalCount
}

// GetKeyCount returns the connection count for a specific key
func (l *MultiKeyConnectionLimiter) GetKeyCount(key string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyCounts[key]
}

// RateLimitedConn wraps a net.Conn with bandwidth rate limiting
type RateLimitedConn struct {
	net.Conn
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
	ctx          context.Context
}

// NewRateLimitedConn creates a new rate-limited connection
// readBytesPerSec: read bandwidth limit in bytes per second (0 = unlimited)
// writeBytesPerSec: write bandwidth limit in bytes per second (0 = unlimited)
func NewRateLimitedConn(conn net.Conn, readBytesPerSec, writeBytesPerSec int) *RateLimitedConn {
	return NewRateLimitedConnWithContext(context.Background(), conn, readBytesPerSec, writeBytesPerSec)
}

// NewRateLimitedConnWithContext creates a new rate-limited connection with context
func NewRateLimitedConnWithContext(ctx context.Context, conn net.Conn, readBytesPerSec, writeBytesPerSec int) *RateLimitedConn {
	c := &RateLimitedConn{
		Conn: conn,
		ctx:  ctx,
	}

	if readBytesPerSec > 0 {
		// Allow burst of up to 64KB or 1 second worth of data, whichever is larger
		burst := readBytesPerSec
		if burst < 65536 {
			burst = 65536
		}
		c.readLimiter = rate.NewLimiter(rate.Limit(readBytesPerSec), burst)
	}

	if writeBytesPerSec > 0 {
		burst := writeBytesPerSec
		if burst < 65536 {
			burst = 65536
		}
		c.writeLimiter = rate.NewLimiter(rate.Limit(writeBytesPerSec), burst)
	}

	return c
}

// Read reads data from the connection with rate limiting
func (c *RateLimitedConn) Read(b []byte) (int, error) {
	if c.readLimiter == nil {
		return c.Conn.Read(b)
	}

	// Limit the read size to avoid waiting too long
	maxRead := len(b)
	if maxRead > c.readLimiter.Burst() {
		maxRead = c.readLimiter.Burst()
	}

	// Wait for permission to read
	if err := c.readLimiter.WaitN(c.ctx, maxRead); err != nil {
		return 0, err
	}

	return c.Conn.Read(b[:maxRead])
}

// Write writes data to the connection with rate limiting
func (c *RateLimitedConn) Write(b []byte) (int, error) {
	if c.writeLimiter == nil {
		return c.Conn.Write(b)
	}

	written := 0
	for written < len(b) {
		// Calculate how much we can write in this iteration
		toWrite := len(b) - written
		if toWrite > c.writeLimiter.Burst() {
			toWrite = c.writeLimiter.Burst()
		}

		// Wait for permission to write
		if err := c.writeLimiter.WaitN(c.ctx, toWrite); err != nil {
			return written, err
		}

		n, err := c.Conn.Write(b[written : written+toWrite])
		written += n
		if err != nil {
			return written, err
		}
	}

	return written, nil
}

// SetReadLimit updates the read rate limit
func (c *RateLimitedConn) SetReadLimit(bytesPerSec int) {
	if bytesPerSec <= 0 {
		c.readLimiter = nil
		return
	}

	burst := bytesPerSec
	if burst < 65536 {
		burst = 65536
	}
	c.readLimiter = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}

// SetWriteLimit updates the write rate limit
func (c *RateLimitedConn) SetWriteLimit(bytesPerSec int) {
	if bytesPerSec <= 0 {
		c.writeLimiter = nil
		return
	}

	burst := bytesPerSec
	if burst < 65536 {
		burst = 65536
	}
	c.writeLimiter = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}

// LimitedConnWrapper wraps a connection with both connection counting and rate limiting
type LimitedConnWrapper struct {
	*RateLimitedConn
	limiter *ConnectionLimiter
	key     string
	closed  bool
	mu      sync.Mutex
}

// NewLimitedConnWrapper creates a new limited connection wrapper
func NewLimitedConnWrapper(conn net.Conn, limiter *ConnectionLimiter, key string, readBytesPerSec, writeBytesPerSec int) *LimitedConnWrapper {
	return &LimitedConnWrapper{
		RateLimitedConn: NewRateLimitedConn(conn, readBytesPerSec, writeBytesPerSec),
		limiter:         limiter,
		key:             key,
	}
}

// Close closes the connection and releases the connection count
func (c *LimitedConnWrapper) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	if c.limiter != nil {
		c.limiter.Release(c.key)
	}
	return c.Conn.Close()
}

// BandwidthLimiter manages bandwidth limits for multiple connections
type BandwidthLimiter struct {
	mu sync.RWMutex
	// Global bandwidth limits
	globalReadLimit  int // bytes per second
	globalWriteLimit int // bytes per second
	// Per-key bandwidth limits
	keyReadLimits  map[string]int
	keyWriteLimits map[string]int
	// Default per-key limits
	defaultReadLimit  int
	defaultWriteLimit int
}

// NewBandwidthLimiter creates a new bandwidth limiter
func NewBandwidthLimiter(globalReadLimit, globalWriteLimit int) *BandwidthLimiter {
	return &BandwidthLimiter{
		globalReadLimit:  globalReadLimit,
		globalWriteLimit: globalWriteLimit,
		keyReadLimits:    make(map[string]int),
		keyWriteLimits:   make(map[string]int),
	}
}

// SetDefaultLimits sets the default per-key bandwidth limits
func (l *BandwidthLimiter) SetDefaultLimits(readLimit, writeLimit int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.defaultReadLimit = readLimit
	l.defaultWriteLimit = writeLimit
}

// SetKeyLimits sets custom bandwidth limits for a specific key
func (l *BandwidthLimiter) SetKeyLimits(key string, readLimit, writeLimit int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keyReadLimits[key] = readLimit
	l.keyWriteLimits[key] = writeLimit
}

// GetLimits returns the bandwidth limits for a key
func (l *BandwidthLimiter) GetLimits(key string) (readLimit, writeLimit int) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	readLimit = l.defaultReadLimit
	if customLimit, ok := l.keyReadLimits[key]; ok {
		readLimit = customLimit
	}

	writeLimit = l.defaultWriteLimit
	if customLimit, ok := l.keyWriteLimits[key]; ok {
		writeLimit = customLimit
	}

	return
}

// WrapConn wraps a connection with the appropriate bandwidth limits
func (l *BandwidthLimiter) WrapConn(conn net.Conn, key string) net.Conn {
	readLimit, writeLimit := l.GetLimits(key)
	if readLimit == 0 && writeLimit == 0 {
		return conn
	}
	return NewRateLimitedConn(conn, readLimit, writeLimit)
}

// IdleTimeoutConn wraps a connection with idle timeout
type IdleTimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
}

// NewIdleTimeoutConn creates a new connection with idle timeout
func NewIdleTimeoutConn(conn net.Conn, idleTimeout time.Duration) *IdleTimeoutConn {
	return &IdleTimeoutConn{
		Conn:        conn,
		idleTimeout: idleTimeout,
	}
}

// Read reads data and resets the idle timeout
func (c *IdleTimeoutConn) Read(b []byte) (int, error) {
	if c.idleTimeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Read(b)
}

// Write writes data and resets the idle timeout
func (c *IdleTimeoutConn) Write(b []byte) (int, error) {
	if c.idleTimeout > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Write(b)
}
