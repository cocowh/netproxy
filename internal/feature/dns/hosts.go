package dns

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// HostsResolver resolves domains using a hosts file
type HostsResolver struct {
	mu    sync.RWMutex
	hosts map[string][]net.IP // domain -> IPs (supports multiple IPs per domain)
	path  string
}

// NewHostsResolver creates a new hosts resolver
func NewHostsResolver() *HostsResolver {
	return &HostsResolver{
		hosts: make(map[string][]net.IP),
	}
}

// LoadFile loads hosts from a file (e.g., /etc/hosts)
func (r *HostsResolver) LoadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.path = path
	r.hosts = make(map[string][]net.IP)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: IP domain [alias...]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		// Add all domains/aliases
		for _, domain := range fields[1:] {
			// Skip comments at end of line
			if strings.HasPrefix(domain, "#") {
				break
			}

			domain = strings.ToLower(domain)
			domain = strings.TrimSuffix(domain, ".")

			r.hosts[domain] = append(r.hosts[domain], ip)
		}
	}

	return scanner.Err()
}

// LoadString loads hosts from a string
func (r *HostsResolver) LoadString(content string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hosts = make(map[string][]net.IP)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: IP domain [alias...]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		// Add all domains/aliases
		for _, domain := range fields[1:] {
			if strings.HasPrefix(domain, "#") {
				break
			}

			domain = strings.ToLower(domain)
			domain = strings.TrimSuffix(domain, ".")

			r.hosts[domain] = append(r.hosts[domain], ip)
		}
	}

	return nil
}

// AddHost adds a host entry
func (r *HostsResolver) AddHost(domain string, ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	r.hosts[domain] = append(r.hosts[domain], ip)
}

// SetHost sets a host entry (replaces existing)
func (r *HostsResolver) SetHost(domain string, ips ...net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	r.hosts[domain] = ips
}

// RemoveHost removes a host entry
func (r *HostsResolver) RemoveHost(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	delete(r.hosts, domain)
}

// Resolve looks up a domain in the hosts file
func (r *HostsResolver) Resolve(domain string) ([]net.IP, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	ips, ok := r.hosts[domain]
	return ips, ok
}

// ResolveIPv4 returns only IPv4 addresses
func (r *HostsResolver) ResolveIPv4(domain string) ([]net.IP, bool) {
	ips, ok := r.Resolve(domain)
	if !ok {
		return nil, false
	}

	var ipv4s []net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4s = append(ipv4s, ip4)
		}
	}

	return ipv4s, len(ipv4s) > 0
}

// ResolveIPv6 returns only IPv6 addresses
func (r *HostsResolver) ResolveIPv6(domain string) ([]net.IP, bool) {
	ips, ok := r.Resolve(domain)
	if !ok {
		return nil, false
	}

	var ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			ipv6s = append(ipv6s, ip)
		}
	}

	return ipv6s, len(ipv6s) > 0
}

// GetAllHosts returns all host entries
func (r *HostsResolver) GetAllHosts() map[string][]net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]net.IP, len(r.hosts))
	for domain, ips := range r.hosts {
		ipsCopy := make([]net.IP, len(ips))
		copy(ipsCopy, ips)
		result[domain] = ipsCopy
	}

	return result
}

// Count returns the number of host entries
func (r *HostsResolver) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts)
}

// Reload reloads the hosts file
func (r *HostsResolver) Reload() error {
	if r.path == "" {
		return nil
	}
	return r.LoadFile(r.path)
}

// HostsAwareResolver wraps an upstream resolver with hosts file support
type HostsAwareResolver struct {
	hosts    *HostsResolver
	upstream UpstreamResolver
}

// NewHostsAwareResolver creates a new hosts-aware resolver
func NewHostsAwareResolver(hosts *HostsResolver, upstream UpstreamResolver) *HostsAwareResolver {
	return &HostsAwareResolver{
		hosts:    hosts,
		upstream: upstream,
	}
}

// Resolve resolves a DNS query, checking hosts file first
func (r *HostsAwareResolver) Resolve(q *dns.Msg) (*dns.Msg, error) {
	if len(q.Question) == 0 {
		return r.upstream.Resolve(q)
	}

	question := q.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")

	// Check hosts file for A and AAAA queries
	switch question.Qtype {
	case dns.TypeA:
		if ips, ok := r.hosts.ResolveIPv4(domain); ok {
			return r.buildResponse(q, ips, dns.TypeA), nil
		}
	case dns.TypeAAAA:
		if ips, ok := r.hosts.ResolveIPv6(domain); ok {
			return r.buildResponse(q, ips, dns.TypeAAAA), nil
		}
	}

	// Fall back to upstream
	return r.upstream.Resolve(q)
}

// buildResponse builds a DNS response with the given IPs
func (r *HostsAwareResolver) buildResponse(q *dns.Msg, ips []net.IP, qtype uint16) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true

	for _, ip := range ips {
		var rr dns.RR
		switch qtype {
		case dns.TypeA:
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes TTL for hosts entries
				},
				A: ip.To4(),
			}
		case dns.TypeAAAA:
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip.To16(),
			}
		}
		if rr != nil {
			resp.Answer = append(resp.Answer, rr)
		}
	}

	return resp
}

// SetHostsFile sets the hosts file for the DNS server
func (s *Server) SetHostsFile(path string) error {
	hosts := NewHostsResolver()
	if err := hosts.LoadFile(path); err != nil {
		return err
	}

	// Wrap the default resolver with hosts support
	s.dispatcher.defaultResolver = NewHostsAwareResolver(hosts, s.dispatcher.defaultResolver)
	return nil
}

// SetHostsResolver sets a custom hosts resolver for the DNS server
func (s *Server) SetHostsResolver(hosts *HostsResolver) {
	s.dispatcher.defaultResolver = NewHostsAwareResolver(hosts, s.dispatcher.defaultResolver)
}
