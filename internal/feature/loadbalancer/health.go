package loadbalancer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
)

// HealthStatus represents the health status of a peer
type HealthStatus struct {
	Healthy     bool
	LastCheck   time.Time
	LastError   error
	Latency     time.Duration
	FailCount   int
	SuccessCount int
}

// HealthChecker performs periodic health checks on upstream peers
type HealthChecker struct {
	mu       sync.RWMutex
	peers    []string
	status   map[string]*HealthStatus
	interval time.Duration
	timeout  time.Duration
	// Number of consecutive failures before marking unhealthy
	failThreshold int
	// Number of consecutive successes before marking healthy again
	successThreshold int
	// Callback when health status changes
	onStatusChange func(peer string, healthy bool)
	// Logger
	logger logger.Logger
	// Cancel function for stopping the checker
	cancel context.CancelFunc
}

// HealthCheckerOption is a functional option for HealthChecker
type HealthCheckerOption func(*HealthChecker)

// WithInterval sets the health check interval
func WithInterval(d time.Duration) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.interval = d
	}
}

// WithTimeout sets the health check timeout
func WithTimeout(d time.Duration) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.timeout = d
	}
}

// WithFailThreshold sets the number of consecutive failures before marking unhealthy
func WithFailThreshold(n int) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.failThreshold = n
	}
}

// WithSuccessThreshold sets the number of consecutive successes before marking healthy
func WithSuccessThreshold(n int) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.successThreshold = n
	}
}

// WithStatusChangeCallback sets the callback for health status changes
func WithStatusChangeCallback(fn func(peer string, healthy bool)) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.onStatusChange = fn
	}
}

// WithLogger sets the logger for health checker
func WithLogger(l logger.Logger) HealthCheckerOption {
	return func(h *HealthChecker) {
		h.logger = l
	}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(peers []string, opts ...HealthCheckerOption) *HealthChecker {
	h := &HealthChecker{
		peers:            peers,
		status:           make(map[string]*HealthStatus),
		interval:         10 * time.Second, // default 10s
		timeout:          3 * time.Second,  // default 3s
		failThreshold:    3,                // default 3 consecutive failures
		successThreshold: 2,                // default 2 consecutive successes
	}

	for _, opt := range opts {
		opt(h)
	}

	// Initialize status for all peers (assume healthy initially)
	for _, peer := range peers {
		h.status[peer] = &HealthStatus{
			Healthy:   true,
			LastCheck: time.Time{},
		}
	}

	return h
}

// Start begins the health check loop
func (h *HealthChecker) Start(ctx context.Context) {
	ctx, h.cancel = context.WithCancel(ctx)
	
	// Perform initial check immediately
	h.checkAllPeers()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkAllPeers()
		}
	}
}

// Stop stops the health checker
func (h *HealthChecker) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
}

// checkAllPeers checks all peers concurrently
func (h *HealthChecker) checkAllPeers() {
	var wg sync.WaitGroup
	for _, peer := range h.peers {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			h.checkPeer(p)
		}(peer)
	}
	wg.Wait()
}

// checkPeer performs a health check on a single peer
func (h *HealthChecker) checkPeer(peer string) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", peer, h.timeout)
	latency := time.Since(start)

	h.mu.Lock()
	defer h.mu.Unlock()

	status, ok := h.status[peer]
	if !ok {
		status = &HealthStatus{}
		h.status[peer] = status
	}

	status.LastCheck = time.Now()
	status.Latency = latency

	wasHealthy := status.Healthy

	if err != nil {
		status.LastError = err
		status.FailCount++
		status.SuccessCount = 0

		// Mark unhealthy after consecutive failures
		if status.FailCount >= h.failThreshold {
			status.Healthy = false
		}

		if h.logger != nil {
			h.logger.Debug("health check failed",
				logger.Any("peer", peer),
				logger.Any("error", err),
				logger.Any("fail_count", status.FailCount),
				logger.Any("healthy", status.Healthy),
			)
		}
	} else {
		conn.Close()
		status.LastError = nil
		status.SuccessCount++
		status.FailCount = 0

		// Mark healthy after consecutive successes
		if status.SuccessCount >= h.successThreshold {
			status.Healthy = true
		}

		if h.logger != nil {
			h.logger.Debug("health check succeeded",
				logger.Any("peer", peer),
				logger.Any("latency", latency),
				logger.Any("success_count", status.SuccessCount),
				logger.Any("healthy", status.Healthy),
			)
		}
	}

	// Notify status change
	if wasHealthy != status.Healthy && h.onStatusChange != nil {
		go h.onStatusChange(peer, status.Healthy)
	}
}

// IsHealthy returns whether a peer is healthy
func (h *HealthChecker) IsHealthy(peer string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if status, ok := h.status[peer]; ok {
		return status.Healthy
	}
	// Unknown peer is considered healthy
	return true
}

// GetHealthyPeers returns a list of healthy peers
func (h *HealthChecker) GetHealthyPeers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var healthy []string
	for _, peer := range h.peers {
		if status, ok := h.status[peer]; ok && status.Healthy {
			healthy = append(healthy, peer)
		}
	}
	return healthy
}

// GetStatus returns the health status of a peer
func (h *HealthChecker) GetStatus(peer string) *HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if status, ok := h.status[peer]; ok {
		// Return a copy to avoid race conditions
		return &HealthStatus{
			Healthy:      status.Healthy,
			LastCheck:    status.LastCheck,
			LastError:    status.LastError,
			Latency:      status.Latency,
			FailCount:    status.FailCount,
			SuccessCount: status.SuccessCount,
		}
	}
	return nil
}

// GetAllStatus returns the health status of all peers
func (h *HealthChecker) GetAllStatus() map[string]*HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make(map[string]*HealthStatus, len(h.status))
	for peer, status := range h.status {
		result[peer] = &HealthStatus{
			Healthy:      status.Healthy,
			LastCheck:    status.LastCheck,
			LastError:    status.LastError,
			Latency:      status.Latency,
			FailCount:    status.FailCount,
			SuccessCount: status.SuccessCount,
		}
	}
	return result
}

// UpdatePeers updates the list of peers to check
func (h *HealthChecker) UpdatePeers(peers []string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create a set of new peers
	newPeers := make(map[string]bool)
	for _, p := range peers {
		newPeers[p] = true
	}

	// Remove status for peers that are no longer in the list
	for peer := range h.status {
		if !newPeers[peer] {
			delete(h.status, peer)
		}
	}

	// Add status for new peers
	for _, peer := range peers {
		if _, ok := h.status[peer]; !ok {
			h.status[peer] = &HealthStatus{
				Healthy:   true, // Assume healthy initially
				LastCheck: time.Time{},
			}
		}
	}

	h.peers = peers
}

// GetLatency returns the last measured latency for a peer
func (h *HealthChecker) GetLatency(peer string) time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if status, ok := h.status[peer]; ok {
		return status.Latency
	}
	return 0
}

// HealthAwareBalancer wraps a Balancer and filters out unhealthy peers
type HealthAwareBalancer struct {
	balancer Balancer
	checker  *HealthChecker
}

// NewHealthAwareBalancer creates a new health-aware balancer
func NewHealthAwareBalancer(balancer Balancer, checker *HealthChecker) *HealthAwareBalancer {
	return &HealthAwareBalancer{
		balancer: balancer,
		checker:  checker,
	}
}

// Next selects the next peer, filtering out unhealthy ones
func (b *HealthAwareBalancer) Next(ctx context.Context, peers []string) string {
	// Filter to only healthy peers
	healthyPeers := make([]string, 0, len(peers))
	for _, peer := range peers {
		if b.checker.IsHealthy(peer) {
			healthyPeers = append(healthyPeers, peer)
		}
	}

	// If no healthy peers, fall back to all peers (better than nothing)
	if len(healthyPeers) == 0 {
		return b.balancer.Next(ctx, peers)
	}

	return b.balancer.Next(ctx, healthyPeers)
}

// LatencyBalancer implements latency-based load balancing
// It selects the peer with the lowest latency
type LatencyBalancer struct {
	checker *HealthChecker
}

// NewLatencyBalancer creates a new latency-based balancer
func NewLatencyBalancer(checker *HealthChecker) *LatencyBalancer {
	return &LatencyBalancer{
		checker: checker,
	}
}

// Next selects the peer with the lowest latency
func (b *LatencyBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}

	var bestPeer string
	var bestLatency time.Duration = -1

	for _, peer := range peers {
		// Skip unhealthy peers
		if !b.checker.IsHealthy(peer) {
			continue
		}

		latency := b.checker.GetLatency(peer)
		if bestLatency < 0 || (latency > 0 && latency < bestLatency) {
			bestLatency = latency
			bestPeer = peer
		}
	}

	// If no peer selected (all unhealthy or no latency data), pick first available
	if bestPeer == "" && len(peers) > 0 {
		return peers[0]
	}

	return bestPeer
}

// WeightedBalancer implements weighted load balancing
type WeightedBalancer struct {
	mu      sync.RWMutex
	weights map[string]int
	// Current weight state for smooth weighted round-robin
	currentWeights map[string]int
}

// NewWeightedBalancer creates a new weighted balancer
func NewWeightedBalancer(weights map[string]int) *WeightedBalancer {
	b := &WeightedBalancer{
		weights:        make(map[string]int),
		currentWeights: make(map[string]int),
	}
	for peer, weight := range weights {
		b.weights[peer] = weight
		b.currentWeights[peer] = 0
	}
	return b
}

// SetWeight sets the weight for a peer
func (b *WeightedBalancer) SetWeight(peer string, weight int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.weights[peer] = weight
	if _, ok := b.currentWeights[peer]; !ok {
		b.currentWeights[peer] = 0
	}
}

// GetWeight returns the weight for a peer
func (b *WeightedBalancer) GetWeight(peer string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.weights[peer]
}

// Next selects the next peer using smooth weighted round-robin algorithm
func (b *WeightedBalancer) Next(ctx context.Context, peers []string) string {
	if len(peers) == 0 {
		return ""
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Calculate total weight
	totalWeight := 0
	for _, peer := range peers {
		weight := b.weights[peer]
		if weight <= 0 {
			weight = 1 // Default weight
		}
		totalWeight += weight
	}

	// Smooth weighted round-robin
	var bestPeer string
	var maxWeight int = -1

	for _, peer := range peers {
		weight := b.weights[peer]
		if weight <= 0 {
			weight = 1
		}

		// Add weight to current weight
		b.currentWeights[peer] += weight

		// Select peer with highest current weight
		if b.currentWeights[peer] > maxWeight {
			maxWeight = b.currentWeights[peer]
			bestPeer = peer
		}
	}

	// Subtract total weight from selected peer
	if bestPeer != "" {
		b.currentWeights[bestPeer] -= totalWeight
	}

	return bestPeer
}
