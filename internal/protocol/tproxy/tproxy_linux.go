//go:build linux

// Package tproxy provides Linux TPROXY transparent proxy support.
package tproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/pkg/transport"
)

const (
	// SO_ORIGINAL_DST is the socket option to get original destination.
	SO_ORIGINAL_DST = 80

	// IP_TRANSPARENT allows binding to non-local addresses.
	IP_TRANSPARENT = 19

	// IPV6_TRANSPARENT allows binding to non-local IPv6 addresses.
	IPV6_TRANSPARENT = 75

	// IP_RECVORIGDSTADDR receives original destination address.
	IP_RECVORIGDSTADDR = 20

	// IPV6_RECVORIGDSTADDR receives original IPv6 destination address.
	IPV6_RECVORIGDSTADDR = 74
)

// tproxyHandler implements the transparent proxy handler for Linux.
type tproxyHandler struct {
	config *Config
	dialer transport.ProxyDialer
}

// newPlatformHandler creates a new Linux TPROXY handler.
func newPlatformHandler(config *Config, dialer interface{}) (Handler, error) {
	if config == nil {
		config = DefaultConfig()
	}

	var d transport.ProxyDialer
	if dialer != nil {
		var ok bool
		d, ok = dialer.(transport.ProxyDialer)
		if !ok {
			d = &transport.DirectDialer{}
		}
	} else {
		d = &transport.DirectDialer{}
	}

	return &tproxyHandler{
		config: config,
		dialer: d,
	}, nil
}

// Handle processes a transparent proxy connection.
func (h *tproxyHandler) Handle(ctx context.Context, conn net.Conn) error {
	// Get original destination
	origDst, err := h.GetOriginalDst(conn)
	if err != nil {
		return fmt.Errorf("failed to get original destination: %w", err)
	}

	// Get dialer from context or use default
	dialer := h.dialer
	if d, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		dialer = d
	}

	// Dial to original destination
	targetConn, err := dialer.Dial(ctx, "tcp", origDst.String())
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", origDst.String(), err)
	}
	defer targetConn.Close()

	// Relay data
	return transport.Relay(conn, targetConn)
}

// GetOriginalDst returns the original destination address for a connection.
func (h *tproxyHandler) GetOriginalDst(conn net.Conn) (net.Addr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not TCP")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Try IPv4 first
	addr, err := getOriginalDstIPv4(fd)
	if err == nil {
		return addr, nil
	}

	// Try IPv6
	if h.config.EnableIPv6 {
		addr, err = getOriginalDstIPv6(fd)
		if err == nil {
			return addr, nil
		}
	}

	return nil, fmt.Errorf("failed to get original destination")
}

// getOriginalDstIPv4 gets the original IPv4 destination.
func getOriginalDstIPv4(fd int) (*net.TCPAddr, error) {
	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// getOriginalDstIPv6 gets the original IPv6 destination.
func getOriginalDstIPv6(fd int) (*net.TCPAddr, error) {
	var addr syscall.RawSockaddrInet6
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IPV6),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST (IPv6) failed: %v", errno)
	}

	ip := make(net.IP, 16)
	copy(ip, addr.Addr[:])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// tproxyListener implements a transparent proxy TCP listener.
type tproxyListener struct {
	net.Listener
	config *Config
}

// newPlatformListener creates a new Linux TPROXY listener.
func newPlatformListener(ctx context.Context, config *Config) (Listener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create listener config with control function
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Set IP_TRANSPARENT
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, IP_TRANSPARENT, 1)
				if err != nil {
					return
				}

				// Set SO_REUSEADDR
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					return
				}

				// Set mark if configured
				if config.Mark > 0 {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, config.Mark)
				}
			})
			return err
		},
	}

	listener, err := lc.Listen(ctx, "tcp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TPROXY listener: %w", err)
	}

	return &tproxyListener{
		Listener: listener,
		config:   config,
	}, nil
}

// GetOriginalDst returns the original destination for a connection.
func (l *tproxyListener) GetOriginalDst(conn net.Conn) (net.Addr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not TCP")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Try IPv4 first
	addr, err := getOriginalDstIPv4(fd)
	if err == nil {
		return addr, nil
	}

	// Try IPv6
	if l.config.EnableIPv6 {
		addr, err = getOriginalDstIPv6(fd)
		if err == nil {
			return addr, nil
		}
	}

	return nil, fmt.Errorf("failed to get original destination")
}

// tproxyPacketListener implements a transparent proxy UDP listener.
type tproxyPacketListener struct {
	net.PacketConn
	config *Config
}

// newPlatformPacketListener creates a new Linux TPROXY packet listener.
func newPlatformPacketListener(ctx context.Context, config *Config) (PacketListener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create packet listener config with control function
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Set IP_TRANSPARENT
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, IP_TRANSPARENT, 1)
				if err != nil {
					return
				}

				// Set IP_RECVORIGDSTADDR to receive original destination
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, IP_RECVORIGDSTADDR, 1)
				if err != nil {
					return
				}

				// Set SO_REUSEADDR
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					return
				}

				// Set mark if configured
				if config.Mark > 0 {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, config.Mark)
				}
			})
			return err
		},
	}

	conn, err := lc.ListenPacket(ctx, "udp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TPROXY packet listener: %w", err)
	}

	return &tproxyPacketListener{
		PacketConn: conn,
		config:     config,
	}, nil
}

// GetOriginalDst extracts the original destination from OOB data.
func (l *tproxyPacketListener) GetOriginalDst(oob []byte) (net.Addr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("failed to parse control message: %w", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == IP_RECVORIGDSTADDR {
			// Parse IPv4 address
			if len(msg.Data) >= 8 {
				ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
				port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
				return &net.UDPAddr{IP: ip, Port: port}, nil
			}
		}

		if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == IPV6_RECVORIGDSTADDR {
			// Parse IPv6 address
			if len(msg.Data) >= 28 {
				ip := make(net.IP, 16)
				copy(ip, msg.Data[8:24])
				port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
				return &net.UDPAddr{IP: ip, Port: port}, nil
			}
		}
	}

	return nil, fmt.Errorf("original destination not found in OOB data")
}

// ReadMsgUDP reads a UDP message with OOB data.
func (l *tproxyPacketListener) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	udpConn, ok := l.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, 0, 0, nil, fmt.Errorf("not a UDP connection")
	}
	return udpConn.ReadMsgUDP(b, oob)
}
