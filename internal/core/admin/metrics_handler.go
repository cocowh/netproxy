// Package admin provides HTTP API handlers for administration.
package admin

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/cocowh/netproxy/internal/feature/metrics"
)

// MetricsHandler handles metrics-related API requests.
type MetricsHandler struct {
	collector *metrics.Collector
	startTime time.Time
}

// NewMetricsHandler creates a new metrics handler.
func NewMetricsHandler(collector *metrics.Collector) *MetricsHandler {
	return &MetricsHandler{
		collector: collector,
		startTime: time.Now(),
	}
}

// RegisterRoutes registers the metrics API routes.
func (h *MetricsHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/metrics", h.handleMetrics)
	mux.HandleFunc("/api/v1/metrics/connections", h.handleConnections)
	mux.HandleFunc("/api/v1/metrics/traffic", h.handleTraffic)
	mux.HandleFunc("/api/v1/metrics/system", h.handleSystem)
}

// MetricsResponse represents the overall metrics response.
type MetricsResponse struct {
	Uptime      time.Duration            `json:"uptime"`
	Connections ConnectionMetrics        `json:"connections"`
	Traffic     TrafficMetrics           `json:"traffic"`
	System      SystemMetrics            `json:"system"`
	Protocols   map[string]ProtocolStats `json:"protocols,omitempty"`
}

// ConnectionMetrics represents connection-related metrics.
type ConnectionMetrics struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Accepted int64 `json:"accepted"`
	Rejected int64 `json:"rejected"`
}

// TrafficMetrics represents traffic-related metrics.
type TrafficMetrics struct {
	BytesIn    int64 `json:"bytes_in"`
	BytesOut   int64 `json:"bytes_out"`
	PacketsIn  int64 `json:"packets_in"`
	PacketsOut int64 `json:"packets_out"`
}

// SystemMetrics represents system-related metrics.
type SystemMetrics struct {
	Goroutines   int     `json:"goroutines"`
	HeapAlloc    uint64  `json:"heap_alloc"`
	HeapSys      uint64  `json:"heap_sys"`
	HeapInuse    uint64  `json:"heap_inuse"`
	StackInuse   uint64  `json:"stack_inuse"`
	NumGC        uint32  `json:"num_gc"`
	GCPauseTotal uint64  `json:"gc_pause_total_ns"`
	CPUUsage     float64 `json:"cpu_usage,omitempty"`
}

// ProtocolStats represents per-protocol statistics.
type ProtocolStats struct {
	Connections int64 `json:"connections"`
	BytesIn     int64 `json:"bytes_in"`
	BytesOut    int64 `json:"bytes_out"`
}

// handleMetrics handles GET /api/v1/metrics
func (h *MetricsHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := MetricsResponse{
		Uptime:      time.Since(h.startTime),
		Connections: h.getConnectionMetrics(),
		Traffic:     h.getTrafficMetrics(),
		System:      h.getSystemMetrics(),
	}

	if h.collector != nil {
		response.Protocols = h.getProtocolStats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleConnections handles GET /api/v1/metrics/connections
func (h *MetricsHandler) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := h.getConnectionMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleTraffic handles GET /api/v1/metrics/traffic
func (h *MetricsHandler) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := h.getTrafficMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleSystem handles GET /api/v1/metrics/system
func (h *MetricsHandler) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := h.getSystemMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getConnectionMetrics returns connection metrics.
func (h *MetricsHandler) getConnectionMetrics() ConnectionMetrics {
	if h.collector == nil {
		return ConnectionMetrics{}
	}

	return ConnectionMetrics{
		Total:    h.collector.GetTotalConnections(),
		Active:   h.collector.GetActiveConnections(),
		Accepted: h.collector.GetAcceptedConnections(),
		Rejected: h.collector.GetRejectedConnections(),
	}
}

// getTrafficMetrics returns traffic metrics.
func (h *MetricsHandler) getTrafficMetrics() TrafficMetrics {
	if h.collector == nil {
		return TrafficMetrics{}
	}

	bytesIn, bytesOut := h.collector.GetTotalBytes()
	packetsIn, packetsOut := h.collector.GetTotalPackets()

	return TrafficMetrics{
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		PacketsIn:  packetsIn,
		PacketsOut: packetsOut,
	}
}

// getSystemMetrics returns system metrics.
func (h *MetricsHandler) getSystemMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemMetrics{
		Goroutines:   runtime.NumGoroutine(),
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapInuse:    m.HeapInuse,
		StackInuse:   m.StackInuse,
		NumGC:        m.NumGC,
		GCPauseTotal: m.PauseTotalNs,
	}
}

// getProtocolStats returns per-protocol statistics.
func (h *MetricsHandler) getProtocolStats() map[string]ProtocolStats {
	if h.collector == nil {
		return nil
	}

	stats := make(map[string]ProtocolStats)

	protocols := []string{"http", "socks5", "ss", "vmess", "vless", "trojan", "wireguard"}
	for _, proto := range protocols {
		conns := h.collector.GetProtocolConnections(proto)
		bytesIn, bytesOut := h.collector.GetProtocolBytes(proto)

		if conns > 0 || bytesIn > 0 || bytesOut > 0 {
			stats[proto] = ProtocolStats{
				Connections: conns,
				BytesIn:     bytesIn,
				BytesOut:    bytesOut,
			}
		}
	}

	return stats
}
