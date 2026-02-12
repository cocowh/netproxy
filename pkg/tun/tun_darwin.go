//go:build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// System constants for macOS utun
	sysprotoControl = 2
	afSys           = 32
	pfSystem        = afSys
	sockDgram       = syscall.SOCK_DGRAM

	// Control socket constants
	ctlioCtlInfo = 0xc0644e03
	utunControl  = "com.apple.net.utun_control"
	utunOptIfname = 2
)

// ctlInfo is the control info structure for macOS
type ctlInfo struct {
	id   uint32
	name [96]byte
}

// sockaddrCtl is the control socket address structure
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scId       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// darwinTUN implements the Device interface for macOS
type darwinTUN struct {
	fd     int
	name   string
	mtu    int
	config *Config
	mu     sync.RWMutex
	closed bool
}

// New creates a new TUN device on macOS (utun)
func New(config *Config) (Device, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create a system socket
	fd, err := syscall.Socket(pfSystem, sockDgram, sysprotoControl)
	if err != nil {
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Get the control ID for utun
	var info ctlInfo
	copy(info.name[:], utunControl)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ctlioCtlInfo, uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO failed: %v", errno)
	}

	// Connect to the control socket
	// Unit 0 means the kernel will assign the next available utun number
	addr := sockaddrCtl{
		scLen:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily:  afSys,
		ssSysaddr: 2, // AF_SYS_CONTROL
		scId:      info.id,
		scUnit:    0, // Let kernel assign
	}

	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect failed: %v", errno)
	}

	// Get the interface name
	var ifname [32]byte
	ifnameLen := uint32(len(ifname))
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysprotoControl,
		utunOptIfname,
		uintptr(unsafe.Pointer(&ifname[0])),
		uintptr(unsafe.Pointer(&ifnameLen)),
		0,
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME failed: %v", errno)
	}

	name := string(ifname[:ifnameLen-1])

	dev := &darwinTUN{
		fd:     fd,
		name:   name,
		mtu:    config.MTU,
		config: config,
	}

	// Configure IP address if specified
	if config.Address != "" {
		if err := dev.configureAddress(config.Address); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to configure address: %w", err)
		}
	}

	// Set MTU
	if config.MTU > 0 {
		if err := dev.SetMTU(config.MTU); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Add routes if specified
	for _, route := range config.Routes {
		if err := dev.addRoute(route); err != nil {
			// Log but don't fail
			fmt.Printf("warning: failed to add route %s: %v\n", route, err)
		}
	}

	return dev, nil
}

// Read reads a packet from the TUN device
// macOS utun prepends a 4-byte header (protocol family)
func (t *darwinTUN) Read(p []byte) (int, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return 0, ErrDeviceNotOpen
	}
	t.mu.RUnlock()

	// Read with 4-byte header
	buf := make([]byte, len(p)+4)
	n, err := syscall.Read(t.fd, buf)
	if err != nil {
		return 0, err
	}

	if n <= 4 {
		return 0, nil
	}

	// Skip the 4-byte header
	copy(p, buf[4:n])
	return n - 4, nil
}

// Write writes a packet to the TUN device
// macOS utun requires a 4-byte header (protocol family)
func (t *darwinTUN) Write(p []byte) (int, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return 0, ErrDeviceNotOpen
	}
	t.mu.RUnlock()

	if len(p) == 0 {
		return 0, nil
	}

	// Determine protocol family from IP version
	var proto uint32
	if p[0]>>4 == 4 {
		proto = syscall.AF_INET
	} else if p[0]>>4 == 6 {
		proto = syscall.AF_INET6
	} else {
		return 0, fmt.Errorf("unknown IP version")
	}

	// Prepend 4-byte header
	buf := make([]byte, len(p)+4)
	binary.BigEndian.PutUint32(buf[:4], proto)
	copy(buf[4:], p)

	n, err := syscall.Write(t.fd, buf)
	if err != nil {
		return 0, err
	}

	if n <= 4 {
		return 0, nil
	}

	return n - 4, nil
}

// Close closes the TUN device
func (t *darwinTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// Remove routes
	for _, route := range t.config.Routes {
		t.removeRoute(route)
	}

	return syscall.Close(t.fd)
}

// Name returns the device name
func (t *darwinTUN) Name() string {
	return t.name
}

// MTU returns the device MTU
func (t *darwinTUN) MTU() int {
	return t.mtu
}

// SetMTU sets the device MTU
func (t *darwinTUN) SetMTU(mtu int) error {
	cmd := exec.Command("ifconfig", t.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	t.mtu = mtu
	return nil
}

// configureAddress configures the IP address on the interface
func (t *darwinTUN) configureAddress(address string) error {
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", address, err)
	}

	// For point-to-point interface, we need both local and remote addresses
	// Use the gateway as the remote address, or generate one
	gateway := t.config.Gateway
	if gateway == "" {
		// Use the next IP as gateway
		gateway = nextIP(ip).String()
	}

	if ip.To4() != nil {
		// IPv4
		cmd := exec.Command("ifconfig", t.name, "inet", ip.String(), gateway, "netmask", ipMaskToString(ipNet.Mask))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure IPv4 address: %w", err)
		}
	} else {
		// IPv6
		ones, _ := ipNet.Mask.Size()
		cmd := exec.Command("ifconfig", t.name, "inet6", fmt.Sprintf("%s/%d", ip.String(), ones))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure IPv6 address: %w", err)
		}
	}

	return nil
}

// addRoute adds a route through this interface
func (t *darwinTUN) addRoute(route string) error {
	_, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		// Try as a single IP
		ip := net.ParseIP(route)
		if ip == nil {
			return fmt.Errorf("invalid route: %s", route)
		}
		if ip.To4() != nil {
			route = ip.String() + "/32"
		} else {
			route = ip.String() + "/128"
		}
	} else {
		route = ipNet.String()
	}

	gateway := t.config.Gateway
	if gateway == "" {
		return fmt.Errorf("gateway required for adding routes")
	}

	cmd := exec.Command("route", "-n", "add", "-net", route, gateway)
	return cmd.Run()
}

// removeRoute removes a route
func (t *darwinTUN) removeRoute(route string) error {
	_, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		ip := net.ParseIP(route)
		if ip == nil {
			return fmt.Errorf("invalid route: %s", route)
		}
		if ip.To4() != nil {
			route = ip.String() + "/32"
		} else {
			route = ip.String() + "/128"
		}
	} else {
		route = ipNet.String()
	}

	cmd := exec.Command("route", "-n", "delete", "-net", route)
	return cmd.Run()
}

// Helper functions

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func ipMaskToString(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return mask.String()
}
