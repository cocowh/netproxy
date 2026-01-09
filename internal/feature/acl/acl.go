package acl

import (
	"context"
	"net"
	"strings"
)

type Action int

const (
	Allow Action = iota
	Block
	Proxy
	Direct
)

type Metadata struct {
	ClientIP   net.IP
	TargetHost string
	TargetPort string // Changed to string for flexibility
	Network    string // Added Network (tcp/udp)
	Protocol   string
	User       string
}

type RuleEngine interface {
	Decide(ctx context.Context, metadata Metadata) Action
}

// SimpleRuleEngine implements basic list-based ACL
type SimpleRuleEngine struct {
	defaultAction Action
	blockIPs      map[string]bool
	blockHosts    map[string]bool
}

func NewSimpleRuleEngine(defaultAction Action, blockIPs, blockHosts []string) RuleEngine {
	bIPs := make(map[string]bool)
	for _, ip := range blockIPs {
		bIPs[ip] = true
	}
	bHosts := make(map[string]bool)
	for _, host := range blockHosts {
		bHosts[host] = true
	}
	return &SimpleRuleEngine{
		defaultAction: defaultAction,
		blockIPs:      bIPs,
		blockHosts:    bHosts,
	}
}

func (e *SimpleRuleEngine) Decide(ctx context.Context, metadata Metadata) Action {
	if e.blockIPs[metadata.ClientIP.String()] {
		return Block
	}
	if e.blockHosts[metadata.TargetHost] {
		return Block
	}
	// Also check domain suffixes
	for host := range e.blockHosts {
		if strings.HasSuffix(metadata.TargetHost, host) {
			return Block
		}
	}
	return e.defaultAction
}
