package router

import (
	"fmt"
	"net"

	"github.com/cocowh/netproxy/internal/feature/acl"
)

// CIDRNode represents a node in the IP Trie
type CIDRNode struct {
	children [2]*CIDRNode // 0 and 1
	action   acl.Action
	hasRule  bool
}

// CIDRTrie represents a Trie for CIDR matching
type CIDRTrie struct {
	root *CIDRNode
}

// NewCIDRTrie creates a new CIDR Trie
func NewCIDRTrie() *CIDRTrie {
	return &CIDRTrie{
		root: &CIDRNode{},
	}
}

// Insert adds a CIDR rule to the Trie
func (t *CIDRTrie) Insert(cidrStr string, action acl.Action) error {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Try parsing as single IP
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return fmt.Errorf("invalid CIDR or IP: %s", cidrStr)
		}
		// Convert single IP to /32 or /128
		if ip4 := ip.To4(); ip4 != nil {
			ipNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}

	node := t.root
	ones, bits := ipNet.Mask.Size()
	ip := ipNet.IP

	// Ensure IP is 4 bytes or 16 bytes consistent with bits
	if bits == 32 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	
	if ip == nil {
		return fmt.Errorf("invalid IP in CIDR: %s", cidrStr)
	}

	for i := 0; i < ones; i++ {
		bit := getBit(ip, i)
		if node.children[bit] == nil {
			node.children[bit] = &CIDRNode{}
		}
		node = node.children[bit]
	}
	
	node.action = action
	node.hasRule = true
	return nil
}

// Match finds the most specific rule for an IP
func (t *CIDRTrie) Match(ip net.IP) (acl.Action, bool) {
	node := t.root
	var lastAction acl.Action
	var found bool

	// Check if IPv4
	ip4 := ip.To4()
	if ip4 != nil {
		ip = ip4
	} else {
		ip = ip.To16()
	}
	
	if ip == nil {
		return 0, false
	}

	bits := len(ip) * 8

	for i := 0; i < bits; i++ {
		if node.hasRule {
			lastAction = node.action
			found = true
		}

		bit := getBit(ip, i)
		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]
	}
	
	// Check the last node
	if node.hasRule {
		lastAction = node.action
		found = true
	}

	return lastAction, found
}

func getBit(ip net.IP, index int) byte {
	byteIndex := index / 8
	bitIndex := 7 - (index % 8)
	if (ip[byteIndex] & (1 << bitIndex)) != 0 {
		return 1
	}
	return 0
}
