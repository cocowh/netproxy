//go:build darwin

// Package tproxy provides macOS pf transparent proxy support.
package tproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/pkg/transport"
)

// pf device path
const pfDevicePath = "/dev/pf"

// pf ioctl commands
const (
	DIOCNATLOOK = 0xc0544417 // Get NAT state
)

// pfioc_natlook structure for pf NAT lookup
type pfiocNatlook struct {
	saddr     [16]byte // Source address
	daddr     [16]byte // Destination address
	rsaddr    [16]byte // Real source address
	rdaddr    [16]byte // Real destination address
	sport     uint16   // Source port
	dport     uint16   // Destination port
	rsport    uint16   // Real source port
	rdport    uint16   // Real destination port
	af        uint8    // Address family (AF_INET or AF_INET6)
	proto     uint8    // Protocol (IPPROTO_TCP or IPPROTO_UDP)
	direction uint8    // Direction
	_         [1]byte  // Padding
}

// tproxyHandler implements the transparent proxy handler for macOS.
type tproxyHandler struct {
	config *Config
	dialer transport.ProxyDialer
	pfFile *os.File
}

// newPlatformHandler creates a new macOS pf handler.
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

	// Open pf device
	pfFile, err := os.Open(pfDevicePath)
	if err != nil {
		// pf device may not be available, continue without it
		pfFile = nil
	}

	return &tproxyHandler{
		config: config,
		dialer: d,
		pfFile: pfFile,
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

	// Get local and remote addresses
	localAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	remoteAddr := tcpConn.RemoteAddr().(*net.TCPAddr)

	// If pf device is available, use DIOCNATLOOK
	if h.pfFile != nil {
		origDst, err := h.pfNatlook(localAddr, remoteAddr)
		if err == nil {
			return origDst, nil
		}
	}

	// Fallback: use getsockname (for rdr rules)
	return h.getSockName(tcpConn)
}

// pfNatlook performs a pf NAT lookup to get the original destination.
func (h *tproxyHandler) pfNatlook(local, remote *net.TCPAddr) (*net.TCPAddr, error) {
	var nl pfiocNatlook

	// Determine address family
	isIPv6 := remote.IP.To4() == nil
	if isIPv6 {
		nl.af = syscall.AF_INET6
		copy(nl.saddr[:], remote.IP.To16())
		copy(nl.daddr[:], local.IP.To16())
	} else {
		nl.af = syscall.AF_INET
		copy(nl.saddr[:], remote.IP.To4())
		copy(nl.daddr[:], local.IP.To4())
	}

	nl.sport = htons(uint16(remote.Port))
	nl.dport = htons(uint16(local.Port))
	nl.proto = syscall.IPPROTO_TCP
	nl.direction = 1 // PF_IN

	// Perform ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		h.pfFile.Fd(),
		DIOCNATLOOK,
		uintptr(unsafe.Pointer(&nl)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("DIOCNATLOOK failed: %v", errno)
	}

	// Extract real destination
	var ip net.IP
	if isIPv6 {
		ip = make(net.IP, 16)
		copy(ip, nl.rdaddr[:])
	} else {
		ip = net.IPv4(nl.rdaddr[0], nl.rdaddr[1], nl.rdaddr[2], nl.rdaddr[3])
	}

	port := ntohs(nl.rdport)

	return &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}, nil
}

// getSockName gets the original destination using getsockname.
func (h *tproxyHandler) getSockName(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Try IPv4
	var addr4 syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr4))

	_, _, errno := syscall.Syscall(
		syscall.SYS_GETSOCKNAME,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr4)),
		uintptr(unsafe.Pointer(&addrLen)),
	)

	if errno == 0 && addr4.Family == syscall.AF_INET {
		ip := net.IPv4(addr4.Addr[0], addr4.Addr[1], addr4.Addr[2], addr4.Addr[3])
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr4.Port))[:]))
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	// Try IPv6
	var addr6 syscall.RawSockaddrInet6
	addrLen = uint32(unsafe.Sizeof(addr6))

	_, _, errno = syscall.Syscall(
		syscall.SYS_GETSOCKNAME,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr6)),
		uintptr(unsafe.Pointer(&addrLen)),
	)

	if errno == 0 && addr6.Family == syscall.AF_INET6 {
		ip := make(net.IP, 16)
		copy(ip, addr6.Addr[:])
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr6.Port))[:]))
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	return nil, fmt.Errorf("getsockname failed")
}

// htons converts host byte order to network byte order (16-bit).
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// ntohs converts network byte order to host byte order (16-bit).
func ntohs(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// tproxyListener implements a transparent proxy TCP listener for macOS.
type tproxyListener struct {
	net.Listener
	config *Config
	pfFile *os.File
}

// newPlatformListener creates a new macOS pf listener.
func newPlatformListener(ctx context.Context, config *Config) (Listener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	// Open pf device
	pfFile, err := os.Open(pfDevicePath)
	if err != nil {
		pfFile = nil
	}

	return &tproxyListener{
		Listener: listener,
		config:   config,
		pfFile:   pfFile,
	}, nil
}

// GetOriginalDst returns the original destination for a connection.
func (l *tproxyListener) GetOriginalDst(conn net.Conn) (net.Addr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not TCP")
	}

	localAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	remoteAddr := tcpConn.RemoteAddr().(*net.TCPAddr)

	if l.pfFile != nil {
		return pfNatlookStatic(l.pfFile, localAddr, remoteAddr)
	}

	return nil, fmt.Errorf("pf device not available")
}

// pfNatlookStatic performs a pf NAT lookup (static version).
func pfNatlookStatic(pfFile *os.File, local, remote *net.TCPAddr) (*net.TCPAddr, error) {
	var nl pfiocNatlook

	isIPv6 := remote.IP.To4() == nil
	if isIPv6 {
		nl.af = syscall.AF_INET6
		copy(nl.saddr[:], remote.IP.To16())
		copy(nl.daddr[:], local.IP.To16())
	} else {
		nl.af = syscall.AF_INET
		copy(nl.saddr[:], remote.IP.To4())
		copy(nl.daddr[:], local.IP.To4())
	}

	nl.sport = htons(uint16(remote.Port))
	nl.dport = htons(uint16(local.Port))
	nl.proto = syscall.IPPROTO_TCP
	nl.direction = 1

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		pfFile.Fd(),
		DIOCNATLOOK,
		uintptr(unsafe.Pointer(&nl)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("DIOCNATLOOK failed: %v", errno)
	}

	var ip net.IP
	if isIPv6 {
		ip = make(net.IP, 16)
		copy(ip, nl.rdaddr[:])
	} else {
		ip = net.IPv4(nl.rdaddr[0], nl.rdaddr[1], nl.rdaddr[2], nl.rdaddr[3])
	}

	port := ntohs(nl.rdport)

	return &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}, nil
}

// tproxyPacketListener implements a transparent proxy UDP listener for macOS.
type tproxyPacketListener struct {
	net.PacketConn
	config *Config
}

// newPlatformPacketListener creates a new macOS pf packet listener.
func newPlatformPacketListener(ctx context.Context, config *Config) (PacketListener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	conn, err := net.ListenPacket("udp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create packet listener: %w", err)
	}

	return &tproxyPacketListener{
		PacketConn: conn,
		config:     config,
	}, nil
}

// GetOriginalDst extracts the original destination from OOB data.
// Note: macOS doesn't support IP_RECVORIGDSTADDR like Linux.
// This is a placeholder that returns an error.
func (l *tproxyPacketListener) GetOriginalDst(oob []byte) (net.Addr, error) {
	return nil, fmt.Errorf("UDP transparent proxy not fully supported on macOS")
}
