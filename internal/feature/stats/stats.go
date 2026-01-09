package stats

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// StatsCollector collects metrics
type StatsCollector interface {
	AddConnection()
	RemoveConnection()
	AddTraffic(ingress, egress int64)
	GetStats() Snapshot
	RegisterConnection(conn net.Conn)
	UnregisterConnection(conn net.Conn)
	GetActiveConnections() []ConnectionInfo
}

type Snapshot struct {
	ActiveConnections int64
	TotalConnections  int64
	IngressBytes      int64
	EgressBytes       int64
}

type ConnectionInfo struct {
	ID        string    `json:"id"`
	Remote    string    `json:"remote"`
	Local     string    `json:"local"`
	StartTime time.Time `json:"start_time"`
	Ingress   int64     `json:"ingress"`
	Egress    int64     `json:"egress"`
}

type SimpleCollector struct {
	activeConns int64
	totalConns  int64
	ingress     int64
	egress      int64
	
	connsMu sync.RWMutex
	conns   map[net.Conn]*ConnectionTracker
}

type ConnectionTracker struct {
	Conn      net.Conn
	StartTime time.Time
	Ingress   int64
	Egress    int64
}

func NewSimpleCollector() StatsCollector {
	return &SimpleCollector{
		conns: make(map[net.Conn]*ConnectionTracker),
	}
}

func (c *SimpleCollector) AddConnection() {
	atomic.AddInt64(&c.activeConns, 1)
	atomic.AddInt64(&c.totalConns, 1)
}

func (c *SimpleCollector) RemoveConnection() {
	atomic.AddInt64(&c.activeConns, -1)
}

func (c *SimpleCollector) AddTraffic(ingress, egress int64) {
	atomic.AddInt64(&c.ingress, ingress)
	atomic.AddInt64(&c.egress, egress)
}

func (c *SimpleCollector) GetStats() Snapshot {
	return Snapshot{
		ActiveConnections: atomic.LoadInt64(&c.activeConns),
		TotalConnections:  atomic.LoadInt64(&c.totalConns),
		IngressBytes:      atomic.LoadInt64(&c.ingress),
		EgressBytes:       atomic.LoadInt64(&c.egress),
	}
}

func (c *SimpleCollector) RegisterConnection(conn net.Conn) {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	c.conns[conn] = &ConnectionTracker{
		Conn:      conn,
		StartTime: time.Now(),
	}
}

func (c *SimpleCollector) UnregisterConnection(conn net.Conn) {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	delete(c.conns, conn)
}

func (c *SimpleCollector) UpdateConnectionTraffic(conn net.Conn, ingress, egress int64) {
	c.connsMu.RLock()
	tracker, ok := c.conns[conn]
	c.connsMu.RUnlock()
	if ok {
		atomic.AddInt64(&tracker.Ingress, ingress)
		atomic.AddInt64(&tracker.Egress, egress)
	}
}

func (c *SimpleCollector) GetActiveConnections() []ConnectionInfo {
	c.connsMu.RLock()
	defer c.connsMu.RUnlock()
	
	infos := make([]ConnectionInfo, 0, len(c.conns))
	for _, t := range c.conns {
		infos = append(infos, ConnectionInfo{
			ID:        t.Conn.RemoteAddr().String(), // Use remote addr as ID for now
			Remote:    t.Conn.RemoteAddr().String(),
			Local:     t.Conn.LocalAddr().String(),
			StartTime: t.StartTime,
			Ingress:   atomic.LoadInt64(&t.Ingress),
			Egress:    atomic.LoadInt64(&t.Egress),
		})
	}
	return infos
}

// StatsConn wraps a net.Conn to collect stats
type StatsConn struct {
	net.Conn
	collector StatsCollector
}

func NewStatsConn(conn net.Conn, collector StatsCollector) net.Conn {
	collector.AddConnection()
	collector.RegisterConnection(conn)
	return &StatsConn{
		Conn:      conn,
		collector: collector,
	}
}

func (c *StatsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.collector.AddTraffic(int64(n), 0)
		if sc, ok := c.collector.(*SimpleCollector); ok {
			sc.UpdateConnectionTraffic(c.Conn, int64(n), 0)
		}
	}
	return n, err
}

func (c *StatsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.collector.AddTraffic(0, int64(n))
		if sc, ok := c.collector.(*SimpleCollector); ok {
			sc.UpdateConnectionTraffic(c.Conn, 0, int64(n))
		}
	}
	return n, err
}

func (c *StatsConn) Close() error {
	c.collector.RemoveConnection()
	c.collector.UnregisterConnection(c.Conn)
	return c.Conn.Close()
}
