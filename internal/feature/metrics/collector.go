// Package metrics provides metrics collection for the NetProxy service.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/cocowh/netproxy/pkg/metrics"
)

// Collector collects and manages metrics for the proxy service
type Collector struct {
	registry *metrics.Registry

	// Connection metrics
	connectionsTotal  map[string]*metrics.Counter
	connectionsActive map[string]*metrics.Gauge

	// Traffic metrics
	trafficBytesTotal map[string]*metrics.Counter

	// User metrics
	userTrafficBytes map[string]*metrics.Counter

	// Latency metrics
	upstreamLatency map[string]*metrics.Histogram

	// Error metrics
	errorsTotal map[string]*metrics.Counter

	mu sync.RWMutex
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		registry:          metrics.NewRegistry(),
		connectionsTotal:  make(map[string]*metrics.Counter),
		connectionsActive: make(map[string]*metrics.Gauge),
		trafficBytesTotal: make(map[string]*metrics.Counter),
		userTrafficBytes:  make(map[string]*metrics.Counter),
		upstreamLatency:   make(map[string]*metrics.Histogram),
		errorsTotal:       make(map[string]*metrics.Counter),
	}
}

// DefaultCollector is the default global collector
var DefaultCollector = NewCollector()

// IncConnectionsTotal increments the total connections counter for a protocol
func (c *Collector) IncConnectionsTotal(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := protocol
	counter, ok := c.connectionsTotal[key]
	if !ok {
		counter = c.registry.GetCounter(
			"netproxy_connections_total",
			"Total number of connections",
			map[string]string{"protocol": protocol},
		)
		c.connectionsTotal[key] = counter
	}
	counter.Inc()
}

// IncActiveConnections increments the active connections gauge
func (c *Collector) IncActiveConnections(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := protocol
	gauge, ok := c.connectionsActive[key]
	if !ok {
		gauge = c.registry.GetGauge(
			"netproxy_connections_active",
			"Number of active connections",
			map[string]string{"protocol": protocol},
		)
		c.connectionsActive[key] = gauge
	}
	gauge.Inc()
}

// DecActiveConnections decrements the active connections gauge
func (c *Collector) DecActiveConnections(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := protocol
	gauge, ok := c.connectionsActive[key]
	if !ok {
		return
	}
	gauge.Dec()
}

// AddTrafficBytes adds traffic bytes for a direction
func (c *Collector) AddTrafficBytes(direction string, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := direction
	counter, ok := c.trafficBytesTotal[key]
	if !ok {
		counter = c.registry.GetCounter(
			"netproxy_traffic_bytes_total",
			"Total traffic bytes",
			map[string]string{"direction": direction},
		)
		c.trafficBytesTotal[key] = counter
	}
	counter.Add(bytes)
}

// AddUserTrafficBytes adds traffic bytes for a specific user
func (c *Collector) AddUserTrafficBytes(user, direction string, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := user + "_" + direction
	counter, ok := c.userTrafficBytes[key]
	if !ok {
		counter = c.registry.GetCounter(
			"netproxy_user_traffic_bytes",
			"User traffic bytes",
			map[string]string{"user": user, "direction": direction},
		)
		c.userTrafficBytes[key] = counter
	}
	counter.Add(bytes)
}

// ObserveUpstreamLatency records upstream latency
func (c *Collector) ObserveUpstreamLatency(upstream string, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := upstream
	histogram, ok := c.upstreamLatency[key]
	if !ok {
		histogram = c.registry.GetHistogram(
			"netproxy_upstream_latency_seconds",
			"Upstream connection latency in seconds",
			map[string]string{"upstream": upstream},
			metrics.DefaultBuckets(),
		)
		c.upstreamLatency[key] = histogram
	}
	histogram.Observe(latency.Seconds())
}

// IncErrors increments the error counter
func (c *Collector) IncErrors(errorType string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := errorType
	counter, ok := c.errorsTotal[key]
	if !ok {
		counter = c.registry.GetCounter(
			"netproxy_errors_total",
			"Total number of errors",
			map[string]string{"type": errorType},
		)
		c.errorsTotal[key] = counter
	}
	counter.Inc()
}

// Handler returns the HTTP handler for metrics endpoint
func (c *Collector) Handler() http.Handler {
	return c.registry.Handler()
}

// Gather returns all metrics in Prometheus format
func (c *Collector) Gather() string {
	return c.registry.Gather()
}

// GetTotalConnections returns the total number of connections across all protocols
func (c *Collector) GetTotalConnections() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var total int64
	for _, counter := range c.connectionsTotal {
		total += int64(counter.Value())
	}
	return total
}

// GetActiveConnections returns the number of active connections across all protocols
func (c *Collector) GetActiveConnections() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var total int64
	for _, gauge := range c.connectionsActive {
		total += int64(gauge.Value())
	}
	return total
}

// GetAcceptedConnections returns the number of accepted connections (same as total for now)
func (c *Collector) GetAcceptedConnections() int64 {
	return c.GetTotalConnections()
}

// GetRejectedConnections returns the number of rejected connections
func (c *Collector) GetRejectedConnections() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	counter, ok := c.errorsTotal["connection_rejected"]
	if !ok {
		return 0
	}
	return int64(counter.Value())
}

// GetTotalBytes returns total upload and download bytes
func (c *Collector) GetTotalBytes() (int64, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var upload, download int64
	if counter, ok := c.trafficBytesTotal["upload"]; ok {
		upload = int64(counter.Value())
	}
	if counter, ok := c.trafficBytesTotal["download"]; ok {
		download = int64(counter.Value())
	}
	return upload, download
}

// GetTotalPackets returns total upload and download packets (estimated from bytes)
func (c *Collector) GetTotalPackets() (int64, int64) {
	// Estimate packets based on average packet size of 1400 bytes
	upload, download := c.GetTotalBytes()
	return upload / 1400, download / 1400
}

// GetProtocolConnections returns the number of connections for a specific protocol
func (c *Collector) GetProtocolConnections(protocol string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if counter, ok := c.connectionsTotal[protocol]; ok {
		return int64(counter.Value())
	}
	return 0
}

// GetProtocolBytes returns upload and download bytes for a specific protocol
func (c *Collector) GetProtocolBytes(protocol string) (int64, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var upload, download int64
	if counter, ok := c.trafficBytesTotal[protocol+"_upload"]; ok {
		upload = int64(counter.Value())
	}
	if counter, ok := c.trafficBytesTotal[protocol+"_download"]; ok {
		download = int64(counter.Value())
	}
	return upload, download
}

// Convenience functions using DefaultCollector

// IncConnectionsTotal increments total connections
func IncConnectionsTotal(protocol string) {
	DefaultCollector.IncConnectionsTotal(protocol)
}

// IncActiveConnections increments active connections
func IncActiveConnections(protocol string) {
	DefaultCollector.IncActiveConnections(protocol)
}

// DecActiveConnections decrements active connections
func DecActiveConnections(protocol string) {
	DefaultCollector.DecActiveConnections(protocol)
}

// AddTrafficBytes adds traffic bytes
func AddTrafficBytes(direction string, bytes uint64) {
	DefaultCollector.AddTrafficBytes(direction, bytes)
}

// AddUserTrafficBytes adds user traffic bytes
func AddUserTrafficBytes(user, direction string, bytes uint64) {
	DefaultCollector.AddUserTrafficBytes(user, direction, bytes)
}

// ObserveUpstreamLatency records upstream latency
func ObserveUpstreamLatency(upstream string, latency time.Duration) {
	DefaultCollector.ObserveUpstreamLatency(upstream, latency)
}

// IncErrors increments errors
func IncErrors(errorType string) {
	DefaultCollector.IncErrors(errorType)
}

// Handler returns the default collector's HTTP handler
func Handler() http.Handler {
	return DefaultCollector.Handler()
}

// ConnectionTracker tracks connection lifecycle for metrics
type ConnectionTracker struct {
	protocol  string
	startTime time.Time
	collector *Collector
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker(protocol string) *ConnectionTracker {
	ct := &ConnectionTracker{
		protocol:  protocol,
		startTime: time.Now(),
		collector: DefaultCollector,
	}
	ct.collector.IncConnectionsTotal(protocol)
	ct.collector.IncActiveConnections(protocol)
	return ct
}

// Close marks the connection as closed
func (ct *ConnectionTracker) Close() {
	ct.collector.DecActiveConnections(ct.protocol)
}

// AddUploadBytes adds upload bytes
func (ct *ConnectionTracker) AddUploadBytes(bytes uint64) {
	ct.collector.AddTrafficBytes("upload", bytes)
}

// AddDownloadBytes adds download bytes
func (ct *ConnectionTracker) AddDownloadBytes(bytes uint64) {
	ct.collector.AddTrafficBytes("download", bytes)
}

// Duration returns the connection duration
func (ct *ConnectionTracker) Duration() time.Duration {
	return time.Since(ct.startTime)
}
