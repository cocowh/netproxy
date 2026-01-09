package loadbalancer

import (
	"context"
	"hash/fnv"
	"math/rand"
	"sync"
	"sync/atomic"
)

// Context keys for load balancer
type ctxKey string

const (
	// CtxKeyClientIP is the context key for client IP (used by HashBalancer)
	CtxKeyClientIP ctxKey = "lb_client_ip"
	// CtxKeyTargetHost is the context key for target host (used by HashBalancer)
	CtxKeyTargetHost ctxKey = "lb_target_host"
)

// WithClientIP adds client IP to context for hash-based load balancing
func WithClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, CtxKeyClientIP, clientIP)
}

// WithTargetHost adds target host to context for hash-based load balancing
func WithTargetHost(ctx context.Context, targetHost string) context.Context {
	return context.WithValue(ctx, CtxKeyTargetHost, targetHost)
}

// GetClientIP retrieves client IP from context
func GetClientIP(ctx context.Context) string {
	if v := ctx.Value(CtxKeyClientIP); v != nil {
		return v.(string)
	}
	return ""
}

// GetTargetHost retrieves target host from context
func GetTargetHost(ctx context.Context) string {
	if v := ctx.Value(CtxKeyTargetHost); v != nil {
		return v.(string)
	}
	return ""
}

// Balancer defines the interface for load balancing
type Balancer interface {
	Next(ctx context.Context, peers []string) string
}

// ConnTracker defines the interface for tracking connections (used by LeastConnBalancer)
type ConnTracker interface {
	// IncrConn increments the connection count for a peer
	IncrConn(peer string)
	// DecrConn decrements the connection count for a peer
	DecrConn(peer string)
}

// RoundRobinBalancer implements round-robin strategy
type RoundRobinBalancer struct {
	counter uint64
}

func NewRoundRobinBalancer() Balancer {
	return &RoundRobinBalancer{}
}

func (b *RoundRobinBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}
	n := atomic.AddUint64(&b.counter, 1)
	return peers[(n-1)%uint64(len(peers))]
}

// RandomBalancer implements random strategy
type RandomBalancer struct{}

func NewRandomBalancer() Balancer {
	return &RandomBalancer{}
}

func (b *RandomBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}
	return peers[rand.Intn(len(peers))]
}

// HashMode defines the hash key source
type HashMode int

const (
	// HashByClientIP uses client IP as hash key (session persistence by client)
	HashByClientIP HashMode = iota
	// HashByTargetHost uses target host as hash key (same destination goes to same peer)
	HashByTargetHost
	// HashByBoth uses both client IP and target host as hash key
	HashByBoth
)

// HashBalancer implements consistent hash-based load balancing
// It ensures the same client/target always routes to the same peer (session persistence)
type HashBalancer struct {
	mode HashMode
}

// NewHashBalancer creates a new hash-based balancer
// mode determines what to use as the hash key:
// - HashByClientIP: same client always goes to same peer
// - HashByTargetHost: same destination always goes to same peer
// - HashByBoth: combination of client and destination
func NewHashBalancer(mode HashMode) Balancer {
	return &HashBalancer{mode: mode}
}

func (b *HashBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}

	// Build hash key based on mode
	var key string
	switch b.mode {
	case HashByClientIP:
		key = GetClientIP(ctx)
	case HashByTargetHost:
		key = GetTargetHost(ctx)
	case HashByBoth:
		key = GetClientIP(ctx) + ":" + GetTargetHost(ctx)
	}

	// If no key available, fallback to random
	if key == "" {
		return peers[rand.Intn(len(peers))]
	}

	// Use FNV-1a hash for good distribution
	h := fnv.New32a()
	h.Write([]byte(key))
	idx := h.Sum32() % uint32(len(peers))

	return peers[idx]
}

// LeastConnBalancer implements least-connections load balancing
// It selects the peer with the fewest active connections
type LeastConnBalancer struct {
	mu       sync.RWMutex
	connCount map[string]int64
}

// NewLeastConnBalancer creates a new least-connections balancer
func NewLeastConnBalancer() *LeastConnBalancer {
	return &LeastConnBalancer{
		connCount: make(map[string]int64),
	}
}

func (b *LeastConnBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Find peer with minimum connections
	minConn := int64(-1)
	var selected string
	var candidates []string

	for _, peer := range peers {
		conn := b.connCount[peer] // defaults to 0 if not found
		if minConn < 0 || conn < minConn {
			minConn = conn
			selected = peer
			candidates = []string{peer}
		} else if conn == minConn {
			// Multiple peers with same connection count
			candidates = append(candidates, peer)
		}
	}

	// If multiple peers have the same minimum, pick randomly among them
	if len(candidates) > 1 {
		return candidates[rand.Intn(len(candidates))]
	}

	return selected
}

// IncrConn increments the connection count for a peer
func (b *LeastConnBalancer) IncrConn(peer string) {
	b.mu.Lock()
	b.connCount[peer]++
	b.mu.Unlock()
}

// DecrConn decrements the connection count for a peer
func (b *LeastConnBalancer) DecrConn(peer string) {
	b.mu.Lock()
	if b.connCount[peer] > 0 {
		b.connCount[peer]--
	}
	b.mu.Unlock()
}

// GetConnCount returns the current connection count for a peer (for monitoring)
func (b *LeastConnBalancer) GetConnCount(peer string) int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connCount[peer]
}

// GetAllConnCounts returns all connection counts (for monitoring)
func (b *LeastConnBalancer) GetAllConnCounts() map[string]int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]int64, len(b.connCount))
	for k, v := range b.connCount {
		result[k] = v
	}
	return result
}
