package router

import (
	"strings"
)

// DomainMatcher matches domain names (exact or suffix)
type DomainMatcher struct {
	domain string
}

// NewDomainMatcher creates a new DomainMatcher
func NewDomainMatcher(domain string) *DomainMatcher {
	return &DomainMatcher{
		domain: strings.ToLower(domain),
	}
}

// Match checks if the host matches the domain or is a subdomain
func (m *DomainMatcher) Match(host string) bool {
	host = strings.ToLower(host)
	// Exact match
	if host == m.domain {
		return true
	}
	// Suffix match (e.g. "api.example.com" matches "example.com")
	// We ensure there is a dot before the domain to avoid partial matches like "example.come"
	if strings.HasSuffix(host, "."+m.domain) {
		return true
	}
	return false
}
