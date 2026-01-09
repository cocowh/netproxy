package stats

import (
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// UserStats holds statistics for a single user
type UserStats struct {
	Username     string
	Ingress      int64 // Total ingress bytes
	Egress       int64 // Total egress bytes
	Connections  int64 // Current active connections
	TotalConns   int64 // Total connections (historical)
	LastActivity time.Time
}

// UserStatsCollector collects per-user statistics
type UserStatsCollector struct {
	mu    sync.RWMutex
	users map[string]*UserStats
}

// NewUserStatsCollector creates a new user stats collector
func NewUserStatsCollector() *UserStatsCollector {
	return &UserStatsCollector{
		users: make(map[string]*UserStats),
	}
}

// getOrCreateUser gets or creates user stats (must be called with lock held)
func (c *UserStatsCollector) getOrCreateUser(username string) *UserStats {
	if stats, ok := c.users[username]; ok {
		return stats
	}
	stats := &UserStats{
		Username: username,
	}
	c.users[username] = stats
	return stats
}

// AddConnection increments the connection count for a user
func (c *UserStatsCollector) AddConnection(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.getOrCreateUser(username)
	atomic.AddInt64(&stats.Connections, 1)
	atomic.AddInt64(&stats.TotalConns, 1)
	stats.LastActivity = time.Now()
}

// RemoveConnection decrements the connection count for a user
func (c *UserStatsCollector) RemoveConnection(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stats, ok := c.users[username]; ok {
		if atomic.LoadInt64(&stats.Connections) > 0 {
			atomic.AddInt64(&stats.Connections, -1)
		}
		stats.LastActivity = time.Now()
	}
}

// AddTraffic adds traffic statistics for a user
func (c *UserStatsCollector) AddTraffic(username string, ingress, egress int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.getOrCreateUser(username)
	if ingress > 0 {
		atomic.AddInt64(&stats.Ingress, ingress)
	}
	if egress > 0 {
		atomic.AddInt64(&stats.Egress, egress)
	}
	stats.LastActivity = time.Now()
}

// GetUserStats returns statistics for a specific user
func (c *UserStatsCollector) GetUserStats(username string) *UserStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if stats, ok := c.users[username]; ok {
		return &UserStats{
			Username:     stats.Username,
			Ingress:      atomic.LoadInt64(&stats.Ingress),
			Egress:       atomic.LoadInt64(&stats.Egress),
			Connections:  atomic.LoadInt64(&stats.Connections),
			TotalConns:   atomic.LoadInt64(&stats.TotalConns),
			LastActivity: stats.LastActivity,
		}
	}
	return nil
}

// GetAllUserStats returns statistics for all users
func (c *UserStatsCollector) GetAllUserStats() []*UserStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*UserStats, 0, len(c.users))
	for _, stats := range c.users {
		result = append(result, &UserStats{
			Username:     stats.Username,
			Ingress:      atomic.LoadInt64(&stats.Ingress),
			Egress:       atomic.LoadInt64(&stats.Egress),
			Connections:  atomic.LoadInt64(&stats.Connections),
			TotalConns:   atomic.LoadInt64(&stats.TotalConns),
			LastActivity: stats.LastActivity,
		})
	}

	// Sort by username for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].Username < result[j].Username
	})

	return result
}

// Reset resets all user statistics
func (c *UserStatsCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users = make(map[string]*UserStats)
}

// ResetUser resets statistics for a specific user
func (c *UserStatsCollector) ResetUser(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.users, username)
}

// ProxyStats holds statistics for a single proxy/upstream
type ProxyStats struct {
	Address     string
	Ingress     int64
	Egress      int64
	Connections int64
	TotalConns  int64
	Errors      int64
	AvgLatency  time.Duration
}

// ProxyStatsCollector collects per-proxy statistics
type ProxyStatsCollector struct {
	mu      sync.RWMutex
	proxies map[string]*ProxyStats
}

// NewProxyStatsCollector creates a new proxy stats collector
func NewProxyStatsCollector() *ProxyStatsCollector {
	return &ProxyStatsCollector{
		proxies: make(map[string]*ProxyStats),
	}
}

// getOrCreateProxy gets or creates proxy stats (must be called with lock held)
func (c *ProxyStatsCollector) getOrCreateProxy(address string) *ProxyStats {
	if stats, ok := c.proxies[address]; ok {
		return stats
	}
	stats := &ProxyStats{
		Address: address,
	}
	c.proxies[address] = stats
	return stats
}

// AddConnection increments the connection count for a proxy
func (c *ProxyStatsCollector) AddConnection(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.getOrCreateProxy(address)
	atomic.AddInt64(&stats.Connections, 1)
	atomic.AddInt64(&stats.TotalConns, 1)
}

// RemoveConnection decrements the connection count for a proxy
func (c *ProxyStatsCollector) RemoveConnection(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stats, ok := c.proxies[address]; ok {
		if atomic.LoadInt64(&stats.Connections) > 0 {
			atomic.AddInt64(&stats.Connections, -1)
		}
	}
}

// AddTraffic adds traffic statistics for a proxy
func (c *ProxyStatsCollector) AddTraffic(address string, ingress, egress int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.getOrCreateProxy(address)
	if ingress > 0 {
		atomic.AddInt64(&stats.Ingress, ingress)
	}
	if egress > 0 {
		atomic.AddInt64(&stats.Egress, egress)
	}
}

// AddError increments the error count for a proxy
func (c *ProxyStatsCollector) AddError(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.getOrCreateProxy(address)
	atomic.AddInt64(&stats.Errors, 1)
}

// GetProxyStats returns statistics for a specific proxy
func (c *ProxyStatsCollector) GetProxyStats(address string) *ProxyStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if stats, ok := c.proxies[address]; ok {
		return &ProxyStats{
			Address:     stats.Address,
			Ingress:     atomic.LoadInt64(&stats.Ingress),
			Egress:      atomic.LoadInt64(&stats.Egress),
			Connections: atomic.LoadInt64(&stats.Connections),
			TotalConns:  atomic.LoadInt64(&stats.TotalConns),
			Errors:      atomic.LoadInt64(&stats.Errors),
			AvgLatency:  stats.AvgLatency,
		}
	}
	return nil
}

// GetAllProxyStats returns statistics for all proxies
func (c *ProxyStatsCollector) GetAllProxyStats() []*ProxyStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*ProxyStats, 0, len(c.proxies))
	for _, stats := range c.proxies {
		result = append(result, &ProxyStats{
			Address:     stats.Address,
			Ingress:     atomic.LoadInt64(&stats.Ingress),
			Egress:      atomic.LoadInt64(&stats.Egress),
			Connections: atomic.LoadInt64(&stats.Connections),
			TotalConns:  atomic.LoadInt64(&stats.TotalConns),
			Errors:      atomic.LoadInt64(&stats.Errors),
			AvgLatency:  stats.AvgLatency,
		})
	}

	// Sort by address for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].Address < result[j].Address
	})

	return result
}

// UserStatsConn wraps a net.Conn to collect per-user stats
type UserStatsConn struct {
	net.Conn
	collector *UserStatsCollector
	username  string
	closed    bool
	mu        sync.Mutex
}

// NewUserStatsConn creates a new user stats connection wrapper
func NewUserStatsConn(conn net.Conn, collector *UserStatsCollector, username string) *UserStatsConn {
	collector.AddConnection(username)
	return &UserStatsConn{
		Conn:      conn,
		collector: collector,
		username:  username,
	}
}

// Read reads data and records ingress traffic
func (c *UserStatsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.collector.AddTraffic(c.username, int64(n), 0)
	}
	return n, err
}

// Write writes data and records egress traffic
func (c *UserStatsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.collector.AddTraffic(c.username, 0, int64(n))
	}
	return n, err
}

// Close closes the connection and decrements the connection count
func (c *UserStatsConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	c.collector.RemoveConnection(c.username)
	return c.Conn.Close()
}

// PrometheusExporter exports metrics in Prometheus format
type PrometheusExporter struct {
	globalCollector *SimpleCollector
	userCollector   *UserStatsCollector
	proxyCollector  *ProxyStatsCollector
	namespace       string
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(namespace string) *PrometheusExporter {
	return &PrometheusExporter{
		namespace: namespace,
	}
}

// SetGlobalCollector sets the global stats collector
func (e *PrometheusExporter) SetGlobalCollector(c *SimpleCollector) {
	e.globalCollector = c
}

// SetUserCollector sets the user stats collector
func (e *PrometheusExporter) SetUserCollector(c *UserStatsCollector) {
	e.userCollector = c
}

// SetProxyCollector sets the proxy stats collector
func (e *PrometheusExporter) SetProxyCollector(c *ProxyStatsCollector) {
	e.proxyCollector = c
}

// WriteMetrics writes metrics in Prometheus format
func (e *PrometheusExporter) WriteMetrics(w io.Writer) {
	ns := e.namespace
	if ns == "" {
		ns = "netproxy"
	}

	// Global metrics
	if e.globalCollector != nil {
		snapshot := e.globalCollector.GetStats()

		fmt.Fprintf(w, "# HELP %s_connections_active Current number of active connections\n", ns)
		fmt.Fprintf(w, "# TYPE %s_connections_active gauge\n", ns)
		fmt.Fprintf(w, "%s_connections_active %d\n", ns, snapshot.ActiveConnections)

		fmt.Fprintf(w, "# HELP %s_connections_total Total number of connections\n", ns)
		fmt.Fprintf(w, "# TYPE %s_connections_total counter\n", ns)
		fmt.Fprintf(w, "%s_connections_total %d\n", ns, snapshot.TotalConnections)

		fmt.Fprintf(w, "# HELP %s_traffic_bytes_total Total traffic in bytes\n", ns)
		fmt.Fprintf(w, "# TYPE %s_traffic_bytes_total counter\n", ns)
		fmt.Fprintf(w, "%s_traffic_bytes_total{direction=\"ingress\"} %d\n", ns, snapshot.IngressBytes)
		fmt.Fprintf(w, "%s_traffic_bytes_total{direction=\"egress\"} %d\n", ns, snapshot.EgressBytes)
	}

	// Per-user metrics
	if e.userCollector != nil {
		userStats := e.userCollector.GetAllUserStats()

		if len(userStats) > 0 {
			fmt.Fprintf(w, "# HELP %s_user_connections_active Current number of active connections per user\n", ns)
			fmt.Fprintf(w, "# TYPE %s_user_connections_active gauge\n", ns)
			for _, stats := range userStats {
				fmt.Fprintf(w, "%s_user_connections_active{user=\"%s\"} %d\n", ns, stats.Username, stats.Connections)
			}

			fmt.Fprintf(w, "# HELP %s_user_connections_total Total number of connections per user\n", ns)
			fmt.Fprintf(w, "# TYPE %s_user_connections_total counter\n", ns)
			for _, stats := range userStats {
				fmt.Fprintf(w, "%s_user_connections_total{user=\"%s\"} %d\n", ns, stats.Username, stats.TotalConns)
			}

			fmt.Fprintf(w, "# HELP %s_user_traffic_bytes_total Total traffic in bytes per user\n", ns)
			fmt.Fprintf(w, "# TYPE %s_user_traffic_bytes_total counter\n", ns)
			for _, stats := range userStats {
				fmt.Fprintf(w, "%s_user_traffic_bytes_total{user=\"%s\",direction=\"ingress\"} %d\n", ns, stats.Username, stats.Ingress)
				fmt.Fprintf(w, "%s_user_traffic_bytes_total{user=\"%s\",direction=\"egress\"} %d\n", ns, stats.Username, stats.Egress)
			}
		}
	}

	// Per-proxy metrics
	if e.proxyCollector != nil {
		proxyStats := e.proxyCollector.GetAllProxyStats()

		if len(proxyStats) > 0 {
			fmt.Fprintf(w, "# HELP %s_proxy_connections_active Current number of active connections per proxy\n", ns)
			fmt.Fprintf(w, "# TYPE %s_proxy_connections_active gauge\n", ns)
			for _, stats := range proxyStats {
				fmt.Fprintf(w, "%s_proxy_connections_active{proxy=\"%s\"} %d\n", ns, stats.Address, stats.Connections)
			}

			fmt.Fprintf(w, "# HELP %s_proxy_connections_total Total number of connections per proxy\n", ns)
			fmt.Fprintf(w, "# TYPE %s_proxy_connections_total counter\n", ns)
			for _, stats := range proxyStats {
				fmt.Fprintf(w, "%s_proxy_connections_total{proxy=\"%s\"} %d\n", ns, stats.Address, stats.TotalConns)
			}

			fmt.Fprintf(w, "# HELP %s_proxy_traffic_bytes_total Total traffic in bytes per proxy\n", ns)
			fmt.Fprintf(w, "# TYPE %s_proxy_traffic_bytes_total counter\n", ns)
			for _, stats := range proxyStats {
				fmt.Fprintf(w, "%s_proxy_traffic_bytes_total{proxy=\"%s\",direction=\"ingress\"} %d\n", ns, stats.Address, stats.Ingress)
				fmt.Fprintf(w, "%s_proxy_traffic_bytes_total{proxy=\"%s\",direction=\"egress\"} %d\n", ns, stats.Address, stats.Egress)
			}

			fmt.Fprintf(w, "# HELP %s_proxy_errors_total Total number of errors per proxy\n", ns)
			fmt.Fprintf(w, "# TYPE %s_proxy_errors_total counter\n", ns)
			for _, stats := range proxyStats {
				fmt.Fprintf(w, "%s_proxy_errors_total{proxy=\"%s\"} %d\n", ns, stats.Address, stats.Errors)
			}
		}
	}
}

// MetricsString returns metrics as a string
func (e *PrometheusExporter) MetricsString() string {
	var buf []byte
	w := &bytesWriter{buf: &buf}
	e.WriteMetrics(w)
	return string(buf)
}

// bytesWriter is a simple io.Writer that writes to a byte slice
type bytesWriter struct {
	buf *[]byte
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// CombinedStatsCollector combines multiple collectors
type CombinedStatsCollector struct {
	global *SimpleCollector
	user   *UserStatsCollector
	proxy  *ProxyStatsCollector
}

// NewCombinedStatsCollector creates a new combined stats collector
func NewCombinedStatsCollector() *CombinedStatsCollector {
	return &CombinedStatsCollector{
		global: NewSimpleCollector().(*SimpleCollector),
		user:   NewUserStatsCollector(),
		proxy:  NewProxyStatsCollector(),
	}
}

// Global returns the global stats collector
func (c *CombinedStatsCollector) Global() *SimpleCollector {
	return c.global
}

// User returns the user stats collector
func (c *CombinedStatsCollector) User() *UserStatsCollector {
	return c.user
}

// Proxy returns the proxy stats collector
func (c *CombinedStatsCollector) Proxy() *ProxyStatsCollector {
	return c.proxy
}

// WrapConn wraps a connection with stats collection
func (c *CombinedStatsCollector) WrapConn(conn net.Conn, username, proxyAddr string) net.Conn {
	// Wrap with global stats
	wrapped := NewStatsConn(conn, c.global)

	// Wrap with user stats if username is provided
	if username != "" {
		wrapped = NewUserStatsConn(wrapped, c.user, username)
	}

	// Track proxy connection if proxy address is provided
	if proxyAddr != "" {
		c.proxy.AddConnection(proxyAddr)
	}

	return wrapped
}
