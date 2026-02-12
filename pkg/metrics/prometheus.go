// Package metrics provides Prometheus metrics collection and export.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing counter
type Counter struct {
	value uint64
	name  string
	help  string
	labels map[string]string
}

// NewCounter creates a new counter
func NewCounter(name, help string, labels map[string]string) *Counter {
	return &Counter{
		name:   name,
		help:   help,
		labels: labels,
	}
}

// Inc increments the counter by 1
func (c *Counter) Inc() {
	atomic.AddUint64(&c.value, 1)
}

// Add adds the given value to the counter
func (c *Counter) Add(delta uint64) {
	atomic.AddUint64(&c.value, delta)
}

// Value returns the current value
func (c *Counter) Value() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Gauge is a metric that can go up and down
type Gauge struct {
	value  int64
	name   string
	help   string
	labels map[string]string
}

// NewGauge creates a new gauge
func NewGauge(name, help string, labels map[string]string) *Gauge {
	return &Gauge{
		name:   name,
		help:   help,
		labels: labels,
	}
}

// Set sets the gauge to the given value
func (g *Gauge) Set(value int64) {
	atomic.StoreInt64(&g.value, value)
}

// Inc increments the gauge by 1
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Add adds the given value to the gauge
func (g *Gauge) Add(delta int64) {
	atomic.AddInt64(&g.value, delta)
}

// Value returns the current value
func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

// Histogram tracks the distribution of values
type Histogram struct {
	name    string
	help    string
	labels  map[string]string
	buckets []float64
	counts  []uint64
	sum     uint64
	count   uint64
	mu      sync.Mutex
}

// NewHistogram creates a new histogram with the given buckets
func NewHistogram(name, help string, labels map[string]string, buckets []float64) *Histogram {
	// Sort buckets
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)

	return &Histogram{
		name:    name,
		help:    help,
		labels:  labels,
		buckets: sorted,
		counts:  make([]uint64, len(sorted)),
	}
}

// DefaultBuckets returns default histogram buckets
func DefaultBuckets() []float64 {
	return []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
}

// Observe records a value
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update buckets
	for i, bound := range h.buckets {
		if value <= bound {
			h.counts[i]++
		}
	}

	// Update sum and count
	h.sum += uint64(value * 1000) // Store as milliseconds for precision
	h.count++
}

// Registry holds all registered metrics
type Registry struct {
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	mu         sync.RWMutex
}

// NewRegistry creates a new metrics registry
func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

// DefaultRegistry is the default global registry
var DefaultRegistry = NewRegistry()

// RegisterCounter registers a counter
func (r *Registry) RegisterCounter(c *Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := metricKey(c.name, c.labels)
	r.counters[key] = c
}

// RegisterGauge registers a gauge
func (r *Registry) RegisterGauge(g *Gauge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := metricKey(g.name, g.labels)
	r.gauges[key] = g
}

// RegisterHistogram registers a histogram
func (r *Registry) RegisterHistogram(h *Histogram) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := metricKey(h.name, h.labels)
	r.histograms[key] = h
}

// GetCounter gets or creates a counter
func (r *Registry) GetCounter(name, help string, labels map[string]string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := metricKey(name, labels)
	if c, ok := r.counters[key]; ok {
		return c
	}

	c := NewCounter(name, help, labels)
	r.counters[key] = c
	return c
}

// GetGauge gets or creates a gauge
func (r *Registry) GetGauge(name, help string, labels map[string]string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := metricKey(name, labels)
	if g, ok := r.gauges[key]; ok {
		return g
	}

	g := NewGauge(name, help, labels)
	r.gauges[key] = g
	return g
}

// GetHistogram gets or creates a histogram
func (r *Registry) GetHistogram(name, help string, labels map[string]string, buckets []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := metricKey(name, labels)
	if h, ok := r.histograms[key]; ok {
		return h
	}

	h := NewHistogram(name, help, labels, buckets)
	r.histograms[key] = h
	return h
}

// Gather collects all metrics in Prometheus text format
func (r *Registry) Gather() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var sb strings.Builder

	// Group metrics by name for HELP and TYPE
	countersByName := make(map[string][]*Counter)
	for _, c := range r.counters {
		countersByName[c.name] = append(countersByName[c.name], c)
	}

	gaugesByName := make(map[string][]*Gauge)
	for _, g := range r.gauges {
		gaugesByName[g.name] = append(gaugesByName[g.name], g)
	}

	histogramsByName := make(map[string][]*Histogram)
	for _, h := range r.histograms {
		histogramsByName[h.name] = append(histogramsByName[h.name], h)
	}

	// Output counters
	for name, counters := range countersByName {
		if len(counters) > 0 {
			sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, counters[0].help))
			sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", name))
			for _, c := range counters {
				sb.WriteString(fmt.Sprintf("%s%s %d\n", c.name, formatLabels(c.labels), c.Value()))
			}
		}
	}

	// Output gauges
	for name, gauges := range gaugesByName {
		if len(gauges) > 0 {
			sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, gauges[0].help))
			sb.WriteString(fmt.Sprintf("# TYPE %s gauge\n", name))
			for _, g := range gauges {
				sb.WriteString(fmt.Sprintf("%s%s %d\n", g.name, formatLabels(g.labels), g.Value()))
			}
		}
	}

	// Output histograms
	for name, histograms := range histogramsByName {
		if len(histograms) > 0 {
			sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, histograms[0].help))
			sb.WriteString(fmt.Sprintf("# TYPE %s histogram\n", name))
			for _, h := range histograms {
				h.mu.Lock()
				// Output bucket counts
				for i, bound := range h.buckets {
					labels := copyLabels(h.labels)
					labels["le"] = fmt.Sprintf("%g", bound)
					sb.WriteString(fmt.Sprintf("%s_bucket%s %d\n", h.name, formatLabels(labels), h.counts[i]))
				}
				// +Inf bucket
				labels := copyLabels(h.labels)
				labels["le"] = "+Inf"
				sb.WriteString(fmt.Sprintf("%s_bucket%s %d\n", h.name, formatLabels(labels), h.count))
				// Sum and count
				sb.WriteString(fmt.Sprintf("%s_sum%s %f\n", h.name, formatLabels(h.labels), float64(h.sum)/1000))
				sb.WriteString(fmt.Sprintf("%s_count%s %d\n", h.name, formatLabels(h.labels), h.count))
				h.mu.Unlock()
			}
		}
	}

	return sb.String()
}

// Handler returns an HTTP handler for the metrics endpoint
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write([]byte(r.Gather()))
	})
}

// Helper functions

func metricKey(name string, labels map[string]string) string {
	return name + formatLabels(labels)
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, labels[k]))
	}

	return "{" + strings.Join(parts, ",") + "}"
}

func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// Convenience functions using DefaultRegistry

// GetDefaultCounter returns a counter from the default registry
func GetDefaultCounter(name, help string, labels map[string]string) *Counter {
	return DefaultRegistry.GetCounter(name, help, labels)
}

// GetDefaultGauge returns a gauge from the default registry
func GetDefaultGauge(name, help string, labels map[string]string) *Gauge {
	return DefaultRegistry.GetGauge(name, help, labels)
}

// GetDefaultHistogram returns a histogram from the default registry
func GetDefaultHistogram(name, help string, labels map[string]string, buckets []float64) *Histogram {
	return DefaultRegistry.GetHistogram(name, help, labels, buckets)
}

// Handler returns the default registry's HTTP handler
func Handler() http.Handler {
	return DefaultRegistry.Handler()
}

// Timer is a helper for timing operations
type Timer struct {
	histogram *Histogram
	start     time.Time
}

// NewTimer creates a new timer that will observe to the given histogram
func NewTimer(h *Histogram) *Timer {
	return &Timer{
		histogram: h,
		start:     time.Now(),
	}
}

// ObserveDuration records the duration since the timer was created
func (t *Timer) ObserveDuration() {
	t.histogram.Observe(time.Since(t.start).Seconds())
}
