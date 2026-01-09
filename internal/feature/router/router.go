package router

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cocowh/netproxy/internal/feature/acl"
	"github.com/cocowh/netproxy/internal/feature/loadbalancer"
	"github.com/oschwald/geoip2-golang"
)

// DNS resolver for GeoIP matching
var (
	defaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}
	// DNS cache for resolved IPs
	dnsCache     = make(map[string]dnsCacheEntry)
	dnsCacheMu   sync.RWMutex
	dnsCacheTTL  = 5 * time.Minute
)

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

// resolveTargetIP resolves the target host to an IP address
// If the host is already an IP, it returns it directly
// If it's a domain, it performs DNS resolution with caching
func resolveTargetIP(host string) net.IP {
	// First, try to parse as IP directly
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}

	// Check cache
	dnsCacheMu.RLock()
	if entry, ok := dnsCache[host]; ok && time.Now().Before(entry.expiresAt) {
		dnsCacheMu.RUnlock()
		return entry.ip
	}
	dnsCacheMu.RUnlock()

	// Perform DNS resolution
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := defaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	// Cache the result
	dnsCacheMu.Lock()
	dnsCache[host] = dnsCacheEntry{
		ip:        ips[0],
		expiresAt: time.Now().Add(dnsCacheTTL),
	}
	dnsCacheMu.Unlock()

	return ips[0]
}

// Router defines the routing interface
type Router interface {
	Route(ctx context.Context, metadata acl.Metadata) (RouteResult, error)
	AddRule(rule string, action acl.Action) error
}

type RouteResult struct {
	Action   acl.Action
	Target   string   // Upstream proxy address if action is Proxy (deprecated, use NextHops[0])
	NextHops []string // Chain of proxy nodes
}

type Matcher interface {
	Match(metadata acl.Metadata) bool
}

type Rule struct {
	Matcher Matcher
	Action  acl.Action
}

type SimpleRouter struct {
	ruleEngine     acl.RuleEngine
	proxyList      []string // List of available proxies
	balancer       loadbalancer.Balancer
	rules          []Rule // Keep for compatibility or linear fallback
	domainTrie     *TrieNode
	cidkTrie       *CIDRTrie
	geoipPath      string
	geoipAvailable bool
	geoipDB        *geoip2.Reader
	remoteDNS      string
}

// MatchDomain implements dns.RouteMatcher
func (r *SimpleRouter) MatchDomain(domain string) (string, bool) {
	// Search Domain Trie
	if action, found := r.domainTrie.Search(domain); found {
		if action == acl.Proxy {
			// Return remote DNS for proxied domains
			if r.remoteDNS != "" {
				return r.remoteDNS, true
			}
			// Fallback to Google DNS if not configured
			return "https://8.8.8.8/dns-query", true
		}
	}

	return "", false
}

func NewSimpleRouter(engine acl.RuleEngine, proxyList []string, balancer loadbalancer.Balancer, geoipPath, remoteDNS string) Router {
	if balancer == nil {
		balancer = loadbalancer.NewRoundRobinBalancer()
	}
	return &SimpleRouter{
		ruleEngine:     engine,
		proxyList:      proxyList,
		balancer:       balancer,
		domainTrie:     NewTrie(),
		cidkTrie:       NewCIDRTrie(),
		geoipPath:      geoipPath,
		geoipAvailable: geoipPath != "",
		remoteDNS:      remoteDNS,
	}
}

func (r *SimpleRouter) Route(ctx context.Context, metadata acl.Metadata) (RouteResult, error) {
	// 1. Check Domain Trie
	if metadata.TargetHost != "" {
		if action, found := r.domainTrie.Search(metadata.TargetHost); found {
			return r.handleAction(ctx, action)
		}
	}

	// 2. Check CIDR Trie (if TargetHost is IP or metadata has IP)
	// If TargetHost is IP, we can check it.
	// Or check metadata.TargetIP if available (we only have TargetHost string in Metadata struct currently, which might be IP)
	// Let's assume TargetHost can be IP.
	targetIP := net.ParseIP(metadata.TargetHost)
	if targetIP == nil && metadata.ClientIP != nil {
		// Maybe check ClientIP? No, Router.Route routes based on TARGET.
		// If TargetHost is domain, we can't check CIDR unless resolved.
	}

	if targetIP != nil {
		if action, found := r.cidkTrie.Match(targetIP); found {
			return r.handleAction(ctx, action)
		}
	}
	// TODO: Resolve domain to IP and check? (Potential performance hit / privacy leak if DNS is remote)
	// For now, only match if direct IP.

	// 3. Check GeoIP (Linear rules or specialized)
	// Since we don't have a specialized GeoIP structure in this refactor yet (other than the linear ones),
	// we fall back to linear rules which might contain GeoIP matchers.
	for _, rule := range r.rules {
		if rule.Matcher.Match(metadata) {
			return r.handleAction(ctx, rule.Action)
		}
	}

	// 4. Fallback to basic rule engine
	action := r.ruleEngine.Decide(ctx, metadata)
	return r.handleAction(ctx, action)
}

func (r *SimpleRouter) handleAction(ctx context.Context, action acl.Action) (RouteResult, error) {
	if action == acl.Proxy {
		return r.createProxyResult(ctx)
	}
	return RouteResult{Action: action}, nil
}

func (r *SimpleRouter) createProxyResult(ctx context.Context) (RouteResult, error) {
	if len(r.proxyList) == 0 {
		return RouteResult{}, errors.New("no proxy available")
	}
	// Use LoadBalancer to pick next hop
	nextHop := r.balancer.Next(ctx, r.proxyList)
	if nextHop == "" {
		return RouteResult{}, errors.New("load balancer failed to select proxy")
	}

	return RouteResult{
		Action:   acl.Proxy,
		Target:   nextHop,
		NextHops: []string{nextHop},
	}, nil
}

func (r *SimpleRouter) AddRule(ruleStr string, action acl.Action) error {
	// Rule format: "type:value"
	// Examples:
	// "geoip:cn"
	// "domain:example.com"

	parts := strings.SplitN(ruleStr, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid rule format")
	}

	matchType := parts[0]
	matchValue := parts[1]

	var matcher Matcher

	switch matchType {
	case "geoip":
		if !r.geoipAvailable {
			return errors.New("geoip database not available")
		}
		// Optimized GeoIP matching
		// We use the shared GeoIP database loaded in the router instance if available
		if r.geoipDB == nil {
			db, err := geoip2.Open(r.geoipPath)
			if err != nil {
				return err
			}
			r.geoipDB = db
		}

		matcher = &GeoIPMatcherAdapter{
			matcher: NewGeoIPMatcher(r.geoipDB, matchValue),
		}

	case "domain":
		// Optimized: Insert into Trie
		r.domainTrie.Insert(matchValue, action)
		// We don't add to linear rules to avoid double matching,
		// BUT we need to ensure precedence.
		// If we mix linear and Trie, logic gets complex.
		// For now, let's say "domain" rules go to Trie, "geoip" go to linear.
		return nil

	case "cidr":
		// New: Insert into CIDR Trie
		if err := r.cidkTrie.Insert(matchValue, action); err != nil {
			return err
		}
		return nil

	default:
		return errors.New("unknown matcher type")
	}

	r.rules = append(r.rules, Rule{
		Matcher: matcher,
		Action:  action,
	})
	return nil
}

// GeoIPMatcherAdapter adapts GeoIPMatcher to Matcher interface
// It matches based on the TARGET IP (destination), not the client IP (source)
type GeoIPMatcherAdapter struct {
	matcher *GeoIPMatcher
}

func (m *GeoIPMatcherAdapter) Match(metadata acl.Metadata) bool {
	// Resolve target host to IP for GeoIP matching
	// This is the correct behavior: match based on destination IP
	// to implement routing rules like "access to CN IPs -> direct, access to foreign IPs -> proxy"
	if metadata.TargetHost == "" {
		return false
	}

	// Resolve target host to IP (handles both IP strings and domain names)
	targetIP := resolveTargetIP(metadata.TargetHost)
	if targetIP == nil {
		return false
	}

	return m.matcher.Match(targetIP)
}

// DomainMatcherAdapter adapts DomainMatcher to Matcher interface
type DomainMatcherAdapter struct {
	matcher *DomainMatcher
}

func (m *DomainMatcherAdapter) Match(metadata acl.Metadata) bool {
	return m.matcher.Match(metadata.TargetHost)
}
