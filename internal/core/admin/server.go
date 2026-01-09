package admin

import (
	"encoding/json"
	"net/http"

	"github.com/cocowh/netproxy/internal/feature/stats"
)

// TLSConfig holds TLS configuration for HTTPS
type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// Server represents the admin server
type Server struct {
	addr               string
	token              string
	tlsConfig          *TLSConfig
	statsCollector     stats.StatsCollector
	prometheusExporter *stats.PrometheusExporter
	userStatsCollector *stats.UserStatsCollector
	proxyStatsCollector *stats.ProxyStatsCollector
}

// NewServer creates a new admin server
func NewServer(addr string, token string, collector stats.StatsCollector) *Server {
	return &Server{
		addr:           addr,
		token:          token,
		statsCollector: collector,
	}
}

// NewServerWithTLS creates a new admin server with TLS support
func NewServerWithTLS(addr string, token string, tlsCfg *TLSConfig, collector stats.StatsCollector) *Server {
	return &Server{
		addr:           addr,
		token:          token,
		tlsConfig:      tlsCfg,
		statsCollector: collector,
	}
}

// SetPrometheusExporter sets the Prometheus exporter for /metrics endpoint
func (s *Server) SetPrometheusExporter(exporter *stats.PrometheusExporter) {
	s.prometheusExporter = exporter
}

// SetUserStatsCollector sets the user stats collector
func (s *Server) SetUserStatsCollector(collector *stats.UserStatsCollector) {
	s.userStatsCollector = collector
}

// SetProxyStatsCollector sets the proxy stats collector
func (s *Server) SetProxyStatsCollector(collector *stats.ProxyStatsCollector) {
	s.proxyStatsCollector = collector
}

// Start starts the admin server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/conns", s.authMiddleware(s.handleConns))
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/stats/users", s.authMiddleware(s.handleUserStats))
	mux.HandleFunc("/stats/proxies", s.authMiddleware(s.handleProxyStats))

	// Check if TLS is enabled
	if s.tlsConfig != nil && s.tlsConfig.Enabled {
		return http.ListenAndServeTLS(s.addr, s.tlsConfig.CertFile, s.tlsConfig.KeyFile, mux)
	}

	return http.ListenAndServe(s.addr, mux)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			token := r.Header.Get("X-Admin-Token")
			if token != s.token {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	snapshot := s.statsCollector.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleConns(w http.ResponseWriter, r *http.Request) {
	conns := s.statsCollector.GetActiveConnections()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleMetrics returns metrics in Prometheus format
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if s.prometheusExporter != nil {
		s.prometheusExporter.WriteMetrics(w)
		return
	}

	// Fallback: generate basic metrics from statsCollector
	if s.statsCollector != nil {
		snapshot := s.statsCollector.GetStats()
		w.Write([]byte("# HELP netproxy_connections_active Current number of active connections\n"))
		w.Write([]byte("# TYPE netproxy_connections_active gauge\n"))
		w.Write([]byte("netproxy_connections_active " + formatInt64(snapshot.ActiveConnections) + "\n"))
		w.Write([]byte("# HELP netproxy_connections_total Total number of connections\n"))
		w.Write([]byte("# TYPE netproxy_connections_total counter\n"))
		w.Write([]byte("netproxy_connections_total " + formatInt64(snapshot.TotalConnections) + "\n"))
		w.Write([]byte("# HELP netproxy_traffic_bytes_total Total traffic in bytes\n"))
		w.Write([]byte("# TYPE netproxy_traffic_bytes_total counter\n"))
		w.Write([]byte("netproxy_traffic_bytes_total{direction=\"ingress\"} " + formatInt64(snapshot.IngressBytes) + "\n"))
		w.Write([]byte("netproxy_traffic_bytes_total{direction=\"egress\"} " + formatInt64(snapshot.EgressBytes) + "\n"))
	}
}

// handleUserStats returns per-user statistics
func (s *Server) handleUserStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.userStatsCollector == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	userStats := s.userStatsCollector.GetAllUserStats()
	json.NewEncoder(w).Encode(userStats)
}

// handleProxyStats returns per-proxy statistics
func (s *Server) handleProxyStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.proxyStatsCollector == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	proxyStats := s.proxyStatsCollector.GetAllProxyStats()
	json.NewEncoder(w).Encode(proxyStats)
}

// formatInt64 converts int64 to string
func formatInt64(n int64) string {
	return string(appendInt64(nil, n))
}

// appendInt64 appends int64 to byte slice
func appendInt64(b []byte, n int64) []byte {
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	if n == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}
