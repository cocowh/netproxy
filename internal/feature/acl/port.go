package acl

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// PortRange represents a range of ports
type PortRange struct {
	Start int
	End   int
}

// Contains checks if a port is within the range
func (r PortRange) Contains(port int) bool {
	return port >= r.Start && port <= r.End
}

// String returns a string representation of the range
func (r PortRange) String() string {
	if r.Start == r.End {
		return strconv.Itoa(r.Start)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

// PortMatcher matches ports against a list of ranges
type PortMatcher struct {
	mu     sync.RWMutex
	ranges []PortRange
}

// NewPortMatcher creates a new port matcher
func NewPortMatcher() *PortMatcher {
	return &PortMatcher{
		ranges: make([]PortRange, 0),
	}
}

// AddPort adds a single port
func (m *PortMatcher) AddPort(port int) {
	m.AddRange(port, port)
}

// AddRange adds a port range
func (m *PortMatcher) AddRange(start, end int) {
	if start > end {
		start, end = end, start
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.ranges = append(m.ranges, PortRange{Start: start, End: end})
	m.optimize()
}

// AddRangeString parses and adds a port range from string
// Supports formats: "80", "80-443", "1-1024"
func (m *PortMatcher) AddRangeString(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	parts := strings.Split(s, "-")
	switch len(parts) {
	case 1:
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid port: %s", s)
		}
		m.AddPort(port)
	case 2:
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid start port: %s", parts[0])
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid end port: %s", parts[1])
		}
		m.AddRange(start, end)
	default:
		return fmt.Errorf("invalid port range format: %s", s)
	}

	return nil
}

// ParsePorts parses a comma-separated list of ports/ranges
// Example: "80,443,8000-8080,22"
func (m *PortMatcher) ParsePorts(s string) error {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		if err := m.AddRangeString(part); err != nil {
			return err
		}
	}
	return nil
}

// Match checks if a port matches any range
func (m *PortMatcher) Match(port int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.ranges {
		if r.Contains(port) {
			return true
		}
	}
	return false
}

// MatchString parses and matches a port string
func (m *PortMatcher) MatchString(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return m.Match(port)
}

// Clear removes all ranges
func (m *PortMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ranges = make([]PortRange, 0)
}

// GetRanges returns a copy of all ranges
func (m *PortMatcher) GetRanges() []PortRange {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]PortRange, len(m.ranges))
	copy(result, m.ranges)
	return result
}

// optimize merges overlapping ranges
func (m *PortMatcher) optimize() {
	if len(m.ranges) <= 1 {
		return
	}

	// Sort by start port
	sort.Slice(m.ranges, func(i, j int) bool {
		return m.ranges[i].Start < m.ranges[j].Start
	})

	// Merge overlapping ranges
	merged := make([]PortRange, 0, len(m.ranges))
	current := m.ranges[0]

	for i := 1; i < len(m.ranges); i++ {
		if m.ranges[i].Start <= current.End+1 {
			// Overlapping or adjacent, merge
			if m.ranges[i].End > current.End {
				current.End = m.ranges[i].End
			}
		} else {
			// No overlap, add current and start new
			merged = append(merged, current)
			current = m.ranges[i]
		}
	}
	merged = append(merged, current)

	m.ranges = merged
}

// PortACL implements port-based access control
type PortACL struct {
	whitelist *PortMatcher
	blacklist *PortMatcher
	mode      PortACLMode
}

// PortACLMode defines the ACL mode
type PortACLMode int

const (
	// PortACLModeWhitelist only allows ports in whitelist
	PortACLModeWhitelist PortACLMode = iota
	// PortACLModeBlacklist blocks ports in blacklist, allows others
	PortACLModeBlacklist
)

// NewPortACL creates a new port ACL
func NewPortACL(mode PortACLMode) *PortACL {
	return &PortACL{
		whitelist: NewPortMatcher(),
		blacklist: NewPortMatcher(),
		mode:      mode,
	}
}

// SetMode sets the ACL mode
func (a *PortACL) SetMode(mode PortACLMode) {
	a.mode = mode
}

// AddWhitelist adds ports to whitelist
func (a *PortACL) AddWhitelist(ports string) error {
	return a.whitelist.ParsePorts(ports)
}

// AddBlacklist adds ports to blacklist
func (a *PortACL) AddBlacklist(ports string) error {
	return a.blacklist.ParsePorts(ports)
}

// Allow checks if a port is allowed
func (a *PortACL) Allow(port int) bool {
	switch a.mode {
	case PortACLModeWhitelist:
		return a.whitelist.Match(port)
	case PortACLModeBlacklist:
		return !a.blacklist.Match(port)
	default:
		return true
	}
}

// AllowString checks if a port string is allowed
func (a *PortACL) AllowString(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return a.Allow(port)
}

// PortRuleEngine implements RuleEngine with port-based rules
type PortRuleEngine struct {
	acl           *PortACL
	defaultAction Action
}

// NewPortRuleEngine creates a new port rule engine
func NewPortRuleEngine(mode PortACLMode, defaultAction Action) *PortRuleEngine {
	return &PortRuleEngine{
		acl:           NewPortACL(mode),
		defaultAction: defaultAction,
	}
}

// AddWhitelist adds ports to whitelist
func (e *PortRuleEngine) AddWhitelist(ports string) error {
	return e.acl.AddWhitelist(ports)
}

// AddBlacklist adds ports to blacklist
func (e *PortRuleEngine) AddBlacklist(ports string) error {
	return e.acl.AddBlacklist(ports)
}

// Decide implements RuleEngine
func (e *PortRuleEngine) Decide(ctx context.Context, metadata Metadata) Action {
	if !e.acl.AllowString(metadata.TargetPort) {
		return Block
	}
	return e.defaultAction
}

// CommonPorts provides common port ranges
var CommonPorts = struct {
	HTTP       string
	HTTPS      string
	SSH        string
	FTP        string
	SMTP       string
	DNS        string
	MySQL      string
	PostgreSQL string
	Redis      string
	MongoDB    string
	Privileged string
	HighPorts  string
	Web        string
	Database   string
}{
	HTTP:       "80",
	HTTPS:      "443",
	SSH:        "22",
	FTP:        "20-21",
	SMTP:       "25,465,587",
	DNS:        "53",
	MySQL:      "3306",
	PostgreSQL: "5432",
	Redis:      "6379",
	MongoDB:    "27017",
	Privileged: "1-1024",
	HighPorts:  "1025-65535",
	Web:        "80,443,8080,8443",
	Database:   "3306,5432,6379,27017",
}
