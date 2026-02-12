// Package tun provides cross-platform TUN device support.
package tun

import (
	"io"
	"net"
)

// Device represents a TUN device interface
type Device interface {
	io.ReadWriteCloser

	// Name returns the device name (e.g., "tun0", "utun8")
	Name() string

	// MTU returns the device MTU
	MTU() int

	// SetMTU sets the device MTU
	SetMTU(mtu int) error
}

// Config holds TUN device configuration
type Config struct {
	// Name is the desired device name (may be ignored on some platforms)
	Name string

	// MTU is the Maximum Transmission Unit
	MTU int

	// Address is the IP address to assign to the device (e.g., "10.0.0.1/24")
	Address string

	// Gateway is the gateway address for routing
	Gateway string

	// Routes are additional routes to add through this device
	Routes []string
}

// DefaultConfig returns a default TUN configuration
func DefaultConfig() *Config {
	return &Config{
		Name:    "tun0",
		MTU:     1500,
		Address: "10.0.0.1/24",
		Gateway: "10.0.0.1",
	}
}

// IPPacket represents a parsed IP packet
type IPPacket struct {
	Version    int
	Protocol   int
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	PayloadLen int
	RawData    []byte
}

// ParseIPPacket parses raw bytes into an IPPacket
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, ErrPacketTooShort
	}

	pkt := &IPPacket{
		RawData: data,
	}

	// Parse IP version
	pkt.Version = int(data[0] >> 4)

	if pkt.Version == 4 {
		return parseIPv4Packet(pkt, data)
	} else if pkt.Version == 6 {
		return parseIPv6Packet(pkt, data)
	}

	return nil, ErrInvalidIPVersion
}

func parseIPv4Packet(pkt *IPPacket, data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, ErrPacketTooShort
	}

	headerLen := int(data[0]&0x0f) * 4
	if len(data) < headerLen {
		return nil, ErrPacketTooShort
	}

	pkt.Protocol = int(data[9])
	pkt.SrcIP = net.IP(data[12:16])
	pkt.DstIP = net.IP(data[16:20])
	pkt.PayloadLen = len(data) - headerLen

	// Parse transport layer ports for TCP/UDP
	if pkt.Protocol == 6 || pkt.Protocol == 17 { // TCP or UDP
		if len(data) >= headerLen+4 {
			pkt.SrcPort = uint16(data[headerLen])<<8 | uint16(data[headerLen+1])
			pkt.DstPort = uint16(data[headerLen+2])<<8 | uint16(data[headerLen+3])
		}
	}

	return pkt, nil
}

func parseIPv6Packet(pkt *IPPacket, data []byte) (*IPPacket, error) {
	if len(data) < 40 {
		return nil, ErrPacketTooShort
	}

	pkt.Protocol = int(data[6]) // Next Header
	pkt.SrcIP = net.IP(data[8:24])
	pkt.DstIP = net.IP(data[24:40])
	pkt.PayloadLen = int(data[4])<<8 | int(data[5])

	// Parse transport layer ports for TCP/UDP
	if pkt.Protocol == 6 || pkt.Protocol == 17 { // TCP or UDP
		if len(data) >= 44 {
			pkt.SrcPort = uint16(data[40])<<8 | uint16(data[41])
			pkt.DstPort = uint16(data[42])<<8 | uint16(data[43])
		}
	}

	return pkt, nil
}

// IsTCP returns true if the packet is TCP
func (p *IPPacket) IsTCP() bool {
	return p.Protocol == 6
}

// IsUDP returns true if the packet is UDP
func (p *IPPacket) IsUDP() bool {
	return p.Protocol == 17
}

// IsICMP returns true if the packet is ICMP
func (p *IPPacket) IsICMP() bool {
	return p.Protocol == 1 || p.Protocol == 58 // ICMPv4 or ICMPv6
}
