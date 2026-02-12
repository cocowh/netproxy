// Package health provides enhanced health check functionality.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	// StatusHealthy indicates the component is healthy
	StatusHealthy Status = "healthy"

	// StatusUnhealthy indicates the component is unhealthy
	StatusUnhealthy Status = "unhealthy"

	// StatusDegraded indicates the component is degraded but functional
	StatusDegraded Status = "degraded"

	// StatusUnknown indicates the health status is unknown
	StatusUnknown Status = "unknown"
)

// CheckResult represents the result of a health check.
type CheckResult struct {
	Status    Status                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Check is a health check function.
type Check func(ctx context.Context) *CheckResult

// Component represents a health-checkable component.
type Component struct {
	Name     string
	Check    Check
	Critical bool // If true, failure makes the whole system unhealthy
	Timeout  time.Duration
}

// HealthReport represents the overall health report.
type HealthReport struct {
	Status     Status                  `json:"status"`
	Timestamp  time.Time               `json:"timestamp"`
	Components map[string]*CheckResult `json:"components"`
	Version    string                  `json:"version,omitempty"`
	Uptime     time.Duration           `json:"uptime"`
}

// Checker manages health checks for multiple components.
type Checker struct {
	components map[string]*Component
	results    map[string]*CheckResult
	mu         sync.RWMutex
	startTime  time.Time
	version    string
	interval   time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
}

// Config represents health checker configuration.
type Config struct {
	// Interval is the interval between health checks
	Interval time.Duration `json:"interval" yaml:"interval"`

	// Version is the application version
	Version string `json:"version" yaml:"version"`

	// DefaultTimeout is the default timeout for health checks
	DefaultTimeout time.Duration `json:"default_timeout" yaml:"default_timeout"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Interval:       30 * time.Second,
		DefaultTimeout: 5 * time.Second,
	}
}

// NewChecker creates a new health checker.
func NewChecker(cfg Config) *Checker {
	return &Checker{
		components: make(map[string]*Component),
		results:    make(map[string]*CheckResult),
		startTime:  time.Now(),
		version:    cfg.Version,
		interval:   cfg.Interval,
	}
}

// Register registers a health check component.
func (c *Checker) Register(component *Component) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.components[component.Name] = component
}

// Unregister removes a health check component.
func (c *Checker) Unregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.components, name)
	delete(c.results, name)
}

// Start starts the periodic health check loop.
func (c *Checker) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Run initial check
	c.CheckAll()

	// Start periodic checks
	go c.checkLoop()

	return nil
}

// Stop stops the health checker.
func (c *Checker) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// checkLoop runs periodic health checks.
func (c *Checker) checkLoop() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.CheckAll()
		}
	}
}

// CheckAll runs all registered health checks.
func (c *Checker) CheckAll() *HealthReport {
	c.mu.RLock()
	components := make([]*Component, 0, len(c.components))
	for _, comp := range c.components {
		components = append(components, comp)
	}
	c.mu.RUnlock()

	// Run checks concurrently
	var wg sync.WaitGroup
	results := make(map[string]*CheckResult)
	resultsMu := sync.Mutex{}

	for _, comp := range components {
		wg.Add(1)
		go func(comp *Component) {
			defer wg.Done()
			result := c.runCheck(comp)
			resultsMu.Lock()
			results[comp.Name] = result
			resultsMu.Unlock()
		}(comp)
	}

	wg.Wait()

	// Update cached results
	c.mu.Lock()
	for name, result := range results {
		c.results[name] = result
	}
	c.mu.Unlock()

	return c.buildReport(results)
}

// runCheck runs a single health check with timeout.
func (c *Checker) runCheck(comp *Component) *CheckResult {
	timeout := comp.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	start := time.Now()

	// Run check in goroutine to handle panics
	resultCh := make(chan *CheckResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- &CheckResult{
					Status:    StatusUnhealthy,
					Message:   fmt.Sprintf("panic: %v", r),
					Timestamp: time.Now(),
					Duration:  time.Since(start),
				}
			}
		}()
		resultCh <- comp.Check(ctx)
	}()

	select {
	case result := <-resultCh:
		if result.Timestamp.IsZero() {
			result.Timestamp = time.Now()
		}
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		return result
	case <-ctx.Done():
		return &CheckResult{
			Status:    StatusUnhealthy,
			Message:   "health check timed out",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}
}

// buildReport builds a health report from check results.
func (c *Checker) buildReport(results map[string]*CheckResult) *HealthReport {
	report := &HealthReport{
		Status:     StatusHealthy,
		Timestamp:  time.Now(),
		Components: results,
		Version:    c.version,
		Uptime:     time.Since(c.startTime),
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Determine overall status
	hasDegraded := false
	for name, result := range results {
		comp, ok := c.components[name]
		if !ok {
			continue
		}

		switch result.Status {
		case StatusUnhealthy:
			if comp.Critical {
				report.Status = StatusUnhealthy
				return report
			}
			hasDegraded = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasDegraded {
		report.Status = StatusDegraded
	}

	return report
}

// GetReport returns the current health report.
func (c *Checker) GetReport() *HealthReport {
	c.mu.RLock()
	results := make(map[string]*CheckResult)
	for name, result := range c.results {
		results[name] = result
	}
	c.mu.RUnlock()

	return c.buildReport(results)
}

// GetComponentStatus returns the status of a specific component.
func (c *Checker) GetComponentStatus(name string) (*CheckResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.results[name]
	return result, ok
}

// IsHealthy returns true if the system is healthy.
func (c *Checker) IsHealthy() bool {
	report := c.GetReport()
	return report.Status == StatusHealthy
}

// HTTPHandler returns an HTTP handler for health checks.
func (c *Checker) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := c.GetReport()

		w.Header().Set("Content-Type", "application/json")

		switch report.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still operational
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(report)
	})
}

// LivenessHandler returns an HTTP handler for liveness probes.
func (c *Checker) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness just checks if the process is running
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// ReadinessHandler returns an HTTP handler for readiness probes.
func (c *Checker) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := c.GetReport()

		if report.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("NOT READY"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("READY"))
	})
}

// Common health check implementations

// TCPCheck creates a TCP connectivity health check.
func TCPCheck(addr string, timeout time.Duration) Check {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()

		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return &CheckResult{
				Status:    StatusUnhealthy,
				Message:   fmt.Sprintf("failed to connect: %v", err),
				Timestamp: time.Now(),
				Duration:  time.Since(start),
			}
		}
		conn.Close()

		return &CheckResult{
			Status:    StatusHealthy,
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}
}

// HTTPCheck creates an HTTP health check.
func HTTPCheck(url string, timeout time.Duration, expectedStatus int) Check {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()

		client := &http.Client{Timeout: timeout}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return &CheckResult{
				Status:    StatusUnhealthy,
				Message:   fmt.Sprintf("failed to create request: %v", err),
				Timestamp: time.Now(),
				Duration:  time.Since(start),
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return &CheckResult{
				Status:    StatusUnhealthy,
				Message:   fmt.Sprintf("request failed: %v", err),
				Timestamp: time.Now(),
				Duration:  time.Since(start),
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode != expectedStatus {
			return &CheckResult{
				Status:    StatusUnhealthy,
				Message:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
				Timestamp: time.Now(),
				Duration:  time.Since(start),
				Details: map[string]interface{}{
					"expected_status": expectedStatus,
					"actual_status":   resp.StatusCode,
				},
			}
		}

		return &CheckResult{
			Status:    StatusHealthy,
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}
}

// MemoryCheck creates a memory usage health check.
func MemoryCheck(maxUsagePercent float64) Check {
	return func(ctx context.Context) *CheckResult {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		// Calculate usage percentage (simplified)
		usagePercent := float64(m.Alloc) / float64(m.Sys) * 100

		status := StatusHealthy
		if usagePercent > maxUsagePercent {
			status = StatusDegraded
		}
		if usagePercent > 95 {
			status = StatusUnhealthy
		}

		return &CheckResult{
			Status:    status,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"alloc_mb":      m.Alloc / 1024 / 1024,
				"sys_mb":        m.Sys / 1024 / 1024,
				"usage_percent": usagePercent,
				"num_gc":        m.NumGC,
			},
		}
	}
}

// GoroutineCheck creates a goroutine count health check.
func GoroutineCheck(maxGoroutines int) Check {
	return func(ctx context.Context) *CheckResult {
		count := runtime.NumGoroutine()

		status := StatusHealthy
		if count > maxGoroutines*80/100 {
			status = StatusDegraded
		}
		if count > maxGoroutines {
			status = StatusUnhealthy
		}

		return &CheckResult{
			Status:    status,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"goroutine_count": count,
				"max_goroutines":  maxGoroutines,
			},
		}
	}
}
