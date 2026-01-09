package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// SSDialer implements ProxyDialer for Shadowsocks proxy
type SSDialer struct {
	next    ProxyDialer
	address string
	cipher  core.Cipher
}

// NewSSDialer creates a new Shadowsocks dialer
func NewSSDialer(next ProxyDialer, address, method, password string) (ProxyDialer, error) {
	cipher, err := core.PickCipher(method, []byte{}, password)
	if err != nil {
		return nil, fmt.Errorf("failed to pick cipher: %v", err)
	}

	return &SSDialer{
		next:    next,
		address: address,
		cipher:  cipher,
	}, nil
}

func (d *SSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// 1. Connect to SS server
	conn, err := d.next.Dial(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	// 2. Wrap connection with encryption
	conn = d.cipher.StreamConn(conn)

	// 3. Write target address (SOCKS5 address format is used by SS)
	targetAddr := socks.ParseAddr(addr)
	if targetAddr == nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address: %s", addr)
	}

	if _, err := conn.Write(targetAddr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d *SSDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// SS UDP Relay involves sending UDP packets over UDP to SS server,
	// wrapped with target address.
	// We need a PacketConn that communicates with SS Server UDP port.
	// And wraps/unwraps packets.

	// Create a PacketConn to SS Server
	c, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	ssAddr, err := net.ResolveUDPAddr("udp", d.address)
	if err != nil {
		c.Close()
		return nil, err
	}

	// Wrap the raw PacketConn with encryption
	securePC := d.cipher.PacketConn(c)

	return &ssPacketConn{
		PacketConn: securePC,
		serverAddr: ssAddr,
	}, nil
}

type ssPacketConn struct {
	net.PacketConn
	serverAddr net.Addr
}

// WriteTo wraps data with target address, encrypts (via PacketConn), and sends to SS server
func (c *ssPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// 1. Format Target Address
	target := socks.ParseAddr(addr.String())
	if target == nil {
		return 0, fmt.Errorf("invalid target address: %s", addr.String())
	}

	// 2. Buffer = Target + Data
	buf := append(target, b...)

	// 3. Send to SS Server
	_, err := c.PacketConn.WriteTo(buf, c.serverAddr)
	if err != nil {
		return 0, err
	}

	// Return original length of data to satisfy interface
	return len(b), nil
}

// ReadFrom receives from SS server, decrypts (via PacketConn), unwraps target address, and returns data
func (c *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// 1. Read from SS Server (Decryption happens here)
	buf := make([]byte, 65535)
	n, _, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	// 2. Parse Target Address (Source Address of the packet)
	if n < 1 {
		return 0, nil, fmt.Errorf("short packet")
	}

	addrType := buf[0]
	var addrLen int

	switch addrType {
	case socks.AtypIPv4:
		addrLen = 1 + 4 + 2 // Type + IPv4 + Port
	case socks.AtypDomainName:
		if n < 2 {
			return 0, nil, fmt.Errorf("short packet for domain")
		}
		domainLen := int(buf[1])
		addrLen = 1 + 1 + domainLen + 2 // Type + Len + Domain + Port
	case socks.AtypIPv6:
		addrLen = 1 + 16 + 2 // Type + IPv6 + Port
	default:
		return 0, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	if n < addrLen {
		return 0, nil, fmt.Errorf("short packet")
	}

	srcAddr := &SocksAddr{raw: buf[:addrLen]}

	// Copy Data
	data := buf[addrLen:n]
	copy(b, data)

	return len(data), srcAddr, nil
}

// SocksAddr implements net.Addr for SOCKS5 address format
type SocksAddr struct {
	raw []byte
}

func (a *SocksAddr) Network() string { return "udp" }
func (a *SocksAddr) String() string {
	return socks.Addr(a.raw).String()
}
