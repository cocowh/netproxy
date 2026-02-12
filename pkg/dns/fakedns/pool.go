// Package fakedns implements a FakeDNS server that assigns fake IPs to domains.
// This is useful for transparent proxying where we need to intercept DNS queries
// and return fake IPs that can be mapped back to the original domain.
package fakedns

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// Pool manages a pool of fake IP addresses
type Pool struct {
	network  *net.IPNet
	start    uint32
	end      uint32
	current  uint32
	size     uint32
	mu       sync.Mutex
}

// NewPool creates a new IP pool from a CIDR notation
// Example: "198.18.0.0/16" creates a pool with 65536 addresses
func NewPool(cidr string) (*Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Only support IPv4 for now
	if network.IP.To4() == nil {
		return nil, errors.New("only IPv4 CIDR is supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 CIDR is supported")
	}

	size := uint32(1) << uint32(bits-ones)
	start := binary.BigEndian.Uint32(network.IP.To4())

	return &Pool{
		network: network,
		start:   start,
		end:     start + size - 1,
		current: start,
		size:    size,
	}, nil
}

// Allocate allocates the next available IP from the pool
func (p *Pool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, p.current)

	// Move to next IP, wrap around if needed
	p.current++
	if p.current > p.end {
		p.current = p.start
	}

	return ip, nil
}

// Contains checks if an IP is within the pool's range
func (p *Pool) Contains(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return p.network.Contains(ip4)
}

// Size returns the total number of IPs in the pool
func (p *Pool) Size() uint32 {
	return p.size
}

// Network returns the network CIDR
func (p *Pool) Network() *net.IPNet {
	return p.network
}

// IPv6Pool manages a pool of fake IPv6 addresses
type IPv6Pool struct {
	prefix  net.IP
	mask    net.IPMask
	current [16]byte
	mu      sync.Mutex
}

// NewIPv6Pool creates a new IPv6 pool from a CIDR notation
// Example: "fc00::/64" creates a pool for FakeDNS IPv6
func NewIPv6Pool(cidr string) (*IPv6Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	if network.IP.To4() != nil {
		return nil, errors.New("IPv6 CIDR required")
	}

	var current [16]byte
	copy(current[:], network.IP.To16())

	return &IPv6Pool{
		prefix:  network.IP,
		mask:    network.Mask,
		current: current,
	}, nil
}

// Allocate allocates the next available IPv6 from the pool
func (p *IPv6Pool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := make(net.IP, 16)
	copy(ip, p.current[:])

	// Increment the current address
	for i := 15; i >= 0; i-- {
		p.current[i]++
		if p.current[i] != 0 {
			break
		}
	}

	return ip, nil
}

// Contains checks if an IP is within the pool's range
func (p *IPv6Pool) Contains(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return false
	}

	for i := range p.mask {
		if (ip16[i] & p.mask[i]) != (p.prefix[i] & p.mask[i]) {
			return false
		}
	}
	return true
}
