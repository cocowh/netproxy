package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// UpstreamResolver defines the interface for DNS resolution
type UpstreamResolver interface {
	Resolve(q *dns.Msg) (*dns.Msg, error)
}

// UDPResolver implements DNS over UDP
type UDPResolver struct {
	Address string
}

func (r *UDPResolver) Resolve(q *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Net = "udp"
	resp, _, err := c.Exchange(q, r.Address)
	return resp, err
}

// DoHResolver implements DNS over HTTPS
type DoHResolver struct {
	URL    string
	Client *http.Client
}

func (r *DoHResolver) Resolve(q *dns.Msg) (*dns.Msg, error) {
	msg, err := q.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", r.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

// Server represents a DNS proxy server
type Server struct {
	addr       string
	dispatcher *DNSDispatcher
	cache      *cache.Cache
	tcpHandler *dns.Server
	udpHandler *dns.Server
	router     RouteMatcher // Interface for matching rules
}

// RouteMatcher matches domains to upstreams
type RouteMatcher interface {
	MatchDomain(domain string) (string, bool) // returns upstream, found
}

// NewServer creates a new DNS server
func NewServer(addr, upstream string) *Server {
	defaultResolver := createResolver(upstream)
	dispatcher := NewDNSDispatcher(defaultResolver)

	return &Server{
		addr:       addr,
		dispatcher: dispatcher,
		cache:      cache.New(5*time.Minute, 10*time.Minute),
	}
}

// SetRouter injects the router for policy-based resolution
func (s *Server) SetRouter(router RouteMatcher) {
	s.router = router
}

func createResolver(upstream string) UpstreamResolver {
	if strings.HasPrefix(upstream, "https://") || strings.HasPrefix(upstream, "http://") {
		return &DoHResolver{
			URL:    upstream,
			Client: &http.Client{Timeout: 5 * time.Second},
		}
	}
	return &UDPResolver{Address: upstream}
}

// AddRule adds a DNS routing rule
func (s *Server) AddRule(domain string, upstream string) {
	resolver := createResolver(upstream)
	s.dispatcher.AddRule(domain, resolver)
}

func (s *Server) Start(ctx context.Context) error {
	handler := &dnsProxyHandler{server: s}

	s.udpHandler = &dns.Server{Addr: s.addr, Net: "udp", Handler: handler}
	s.tcpHandler = &dns.Server{Addr: s.addr, Net: "tcp", Handler: handler}

	go func() {
		if err := s.udpHandler.ListenAndServe(); err != nil {
			fmt.Printf("DNS UDP ListenAndServe error: %v\n", err)
		}
	}()

	go func() {
		if err := s.tcpHandler.ListenAndServe(); err != nil {
			fmt.Printf("DNS TCP ListenAndServe error: %v\n", err)
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.udpHandler != nil {
		s.udpHandler.Shutdown()
	}
	if s.tcpHandler != nil {
		s.tcpHandler.Shutdown()
	}
	return nil
}

type dnsProxyHandler struct {
	server *Server
}

func (h *dnsProxyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	key := questionKey(question)

	// Check cache
	if val, found := h.server.cache.Get(key); found {
		if resp, ok := val.(*dns.Msg); ok {
			respCopy := resp.Copy()
			respCopy.SetReply(r)
			w.WriteMsg(respCopy)
			return
		}
	}

	// Dispatch request
	// 1. Check Router Policies if available
	var resolver UpstreamResolver
	if h.server.router != nil {
		if upstream, found := h.server.router.MatchDomain(question.Name); found {
			// Create on-the-fly resolver for this upstream
			resolver = createResolver(upstream)
		}
	}
	
	// 2. Fallback to internal dispatcher (static rules)
	if resolver == nil {
		resolver = h.server.dispatcher.Dispatch(question.Name)
	}

	resp, err := resolver.Resolve(r)
	if err != nil {
		fmt.Printf("DNS Resolve error: %v\n", err)
		dns.HandleFailed(w, r)
		return
	}

	// Cache response
	if resp != nil {
		// Calculate TTL
		ttl := 300 * time.Second
		if len(resp.Answer) > 0 {
			ttl = time.Duration(resp.Answer[0].Header().Ttl) * time.Second
		}
		// Enforce min/max TTL policies if needed, for now stick to record TTL
		h.server.cache.Set(key, resp, ttl)
	}

	if err := w.WriteMsg(resp); err != nil {
		fmt.Printf("DNS WriteMsg error: %v\n", err)
	}
}

// DNSDispatcher handles Split-DNS routing
type DNSDispatcher struct {
	defaultResolver UpstreamResolver
	rules           map[string]UpstreamResolver // domain -> resolver
	// Optimization: Use Trie for better matching if rule count is high.
	// For now, map suffix matching is sufficient for basic implementation.
}

func NewDNSDispatcher(defaultResolver UpstreamResolver) *DNSDispatcher {
	return &DNSDispatcher{
		defaultResolver: defaultResolver,
		rules:           make(map[string]UpstreamResolver),
	}
}

func (d *DNSDispatcher) AddRule(domain string, resolver UpstreamResolver) {
	// Normalize domain
	domain = strings.TrimSuffix(domain, ".")
	d.rules[domain] = resolver
}

func (d *DNSDispatcher) Dispatch(domain string) UpstreamResolver {
	// Normalize
	queryDomain := strings.TrimSuffix(domain, ".")

	// 1. Exact match
	if resolver, ok := d.rules[queryDomain]; ok {
		return resolver
	}

	// 2. Suffix match
	// Iterate rules (inefficient for many rules, but OK for now)
	// Longest match wins?
	var bestMatch string
	var bestResolver UpstreamResolver

	for ruleDomain, resolver := range d.rules {
		if strings.HasSuffix(queryDomain, "."+ruleDomain) {
			if len(ruleDomain) > len(bestMatch) {
				bestMatch = ruleDomain
				bestResolver = resolver
			}
		}
	}

	if bestResolver != nil {
		return bestResolver
	}

	return d.defaultResolver
}

func questionKey(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
}
