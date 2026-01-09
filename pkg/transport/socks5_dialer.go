package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"golang.org/x/net/proxy"
)

// SOCKS5Dialer implements ProxyDialer for SOCKS5 proxy
type SOCKS5Dialer struct {
	next    ProxyDialer
	address string
	auth    *proxy.Auth
}

// NewSOCKS5Dialer creates a new SOCKS5 dialer that dials through 'next' dialer
func NewSOCKS5Dialer(next ProxyDialer, address string, user, password string) ProxyDialer {
	var auth *proxy.Auth
	if user != "" || password != "" {
		auth = &proxy.Auth{User: user, Password: password}
	}
	return &SOCKS5Dialer{
		next:    next,
		address: address,
		auth:    auth,
	}
}

func (d *SOCKS5Dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	adapter := &contextAdapter{ctx: ctx, dialer: d.next}
	s5, err := proxy.SOCKS5("tcp", d.address, d.auth, adapter)
	if err != nil {
		return nil, err
	}
	return s5.Dial(network, addr)
}

type contextAdapter struct {
	ctx    context.Context
	dialer ProxyDialer
}

func (c *contextAdapter) Dial(network, addr string) (net.Conn, error) {
	return c.dialer.Dial(c.ctx, network, addr)
}

// DialPacket implements ProxyDialer.DialPacket for SOCKS5
func (d *SOCKS5Dialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// 1. Establish TCP Control Connection
	controlConn, err := d.next.Dial(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial socks5 control: %w", err)
	}

	// 2. Client Handshake
	// Ver=5, NMethods=1, Method=0(NoAuth) or 2(UserPass)
	methods := []byte{0x05, 0x01, 0x00}
	if d.auth != nil {
		methods[2] = 0x02
	}
	if _, err := controlConn.Write(methods); err != nil {
		controlConn.Close()
		return nil, err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(controlConn, reply); err != nil {
		controlConn.Close()
		return nil, err
	}

	if reply[0] != 0x05 {
		controlConn.Close()
		return nil, fmt.Errorf("socks5: invalid version")
	}
	method := reply[1]

	if method == 0x02 && d.auth != nil {
		// Auth
		userBytes := []byte(d.auth.User)
		passBytes := []byte(d.auth.Password)
		buf := make([]byte, 0, 3+len(userBytes)+len(passBytes))
		buf = append(buf, 0x01)
		buf = append(buf, byte(len(userBytes)))
		buf = append(buf, userBytes...)
		buf = append(buf, byte(len(passBytes)))
		buf = append(buf, passBytes...)

		if _, err := controlConn.Write(buf); err != nil {
			controlConn.Close()
			return nil, err
		}

		authReply := make([]byte, 2)
		if _, err := io.ReadFull(controlConn, authReply); err != nil {
			controlConn.Close()
			return nil, err
		}
		if authReply[1] != 0x00 {
			controlConn.Close()
			return nil, fmt.Errorf("socks5: auth failed")
		}
	} else if method != 0x00 {
		controlConn.Close()
		return nil, fmt.Errorf("socks5: unsupported method %d", method)
	}

	// 3. Request UDP Associate
	// CMD=0x03 (UDP Associate)
	// Addr=0.0.0.0:0 (Client expects to send from anywhere, or we can bind)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := controlConn.Write(req); err != nil {
		controlConn.Close()
		return nil, err
	}

	// 4. Read Reply
	// VER REP RSV ATYP BND.ADDR BND.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(controlConn, header); err != nil {
		controlConn.Close()
		return nil, err
	}

	if header[1] != 0x00 {
		controlConn.Close()
		return nil, fmt.Errorf("socks5: udp associate failed: %d", header[1])
	}

	var relayIP net.IP
	var relayPort int

	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 6)
		if _, err := io.ReadFull(controlConn, buf); err != nil {
			controlConn.Close()
			return nil, err
		}
		relayIP = net.IP(buf[:4])
		relayPort = int(binary.BigEndian.Uint16(buf[4:]))
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(controlConn, lenBuf); err != nil {
			controlConn.Close()
			return nil, err
		}
		length := int(lenBuf[0])
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(controlConn, buf); err != nil {
			controlConn.Close()
			return nil, err
		}
		relayIP = nil            // Indicates domain based
		_ = string(buf[:length]) // Domain
		relayPort = int(binary.BigEndian.Uint16(buf[length:]))
	case 0x04: // IPv6
		buf := make([]byte, 18)
		if _, err := io.ReadFull(controlConn, buf); err != nil {
			controlConn.Close()
			return nil, err
		}
		relayIP = net.IP(buf[:16])
		relayPort = int(binary.BigEndian.Uint16(buf[16:]))
	default:
		controlConn.Close()
		return nil, fmt.Errorf("socks5: unsupported address type %d", header[3])
	}

	// Construct Relay Address String
	relayAddrStr := ""
	if relayIP != nil {
		if relayIP.IsUnspecified() {
			// Replace with Server Address IP
			host, _, _ := net.SplitHostPort(d.address)
			relayAddrStr = net.JoinHostPort(host, strconv.Itoa(relayPort))
		} else {
			relayAddrStr = net.JoinHostPort(relayIP.String(), strconv.Itoa(relayPort))
		}
	}

	// 5. Establish UDP connection to Relay
	packetConn, err := d.next.DialPacket(ctx, "udp", relayAddrStr)
	if err != nil {
		controlConn.Close()
		return nil, err
	}

	return &socks5UDPConn{
		PacketConn:  packetConn,
		controlConn: controlConn,
		relayAddr:   relayAddrStr,
	}, nil
}

type socks5UDPConn struct {
	net.PacketConn
	controlConn net.Conn
	relayAddr   string
}

func (c *socks5UDPConn) Close() error {
	c.controlConn.Close()
	return c.PacketConn.Close()
}

func (c *socks5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Encapsulate SOCKS5 UDP Header
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA

	header := make([]byte, 0, 10+len(b))
	header = append(header, 0, 0, 0) // RSV, FRAG

	// Parse addr
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, 0x01)
			header = append(header, ip4...)
		} else {
			header = append(header, 0x04)
			header = append(header, ip...)
		}
	} else {
		header = append(header, 0x03)
		header = append(header, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	header = append(header, portBuf...)

	header = append(header, b...)

	// Send to Relay
	rAddr, err := net.ResolveUDPAddr("udp", c.relayAddr)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(header, rAddr)
	if err != nil {
		return 0, err
	}
	// Return len(b) to masquerade as normal WriteTo
	return len(b), nil
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Read from Relay
	n, _, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	// Strip SOCKS5 Header
	// RSV(2) FRAG(1) ATYP(1) ...
	if n < 4 {
		return 0, nil, fmt.Errorf("short packet")
	}

	// Parse Source Addr
	var srcAddr net.Addr
	offset := 0
	atyp := b[3]
	switch atyp {
	case 0x01: // IPv4
		if n < 10 {
			return 0, nil, fmt.Errorf("short packet")
		}
		ip := net.IP(b[4:8])
		port := int(binary.BigEndian.Uint16(b[8:10]))
		srcAddr = &net.UDPAddr{IP: ip, Port: port}
		offset = 10
	case 0x03: // Domain
		if n < 5 {
			return 0, nil, fmt.Errorf("short packet")
		}
		domLen := int(b[4])
		if n < 5+domLen+2 {
			return 0, nil, fmt.Errorf("short packet")
		}
		domain := string(b[5 : 5+domLen])
		port := int(binary.BigEndian.Uint16(b[5+domLen : 5+domLen+2]))
		ipAddr, _ := net.ResolveIPAddr("ip", domain)
		if ipAddr != nil {
			srcAddr = &net.UDPAddr{IP: ipAddr.IP, Port: port}
		} else {
			srcAddr = &net.UDPAddr{IP: net.IPv4zero, Port: port}
		}
		offset = 5 + domLen + 2
	case 0x04: // IPv6
		if n < 22 {
			return 0, nil, fmt.Errorf("short packet")
		}
		ip := net.IP(b[4:20])
		port := int(binary.BigEndian.Uint16(b[20:22]))
		srcAddr = &net.UDPAddr{IP: ip, Port: port}
		offset = 22
	}

	copy(b, b[offset:n])
	return n - offset, srcAddr, nil
}
