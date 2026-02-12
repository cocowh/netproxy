//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	tunDevice   = "/dev/net/tun"
	ifnamsiz    = 16
	iffTun      = 0x0001
	iffNoPi     = 0x1000
	tunSetIff   = 0x400454ca
)

// ifreq is the Linux interface request structure
type ifreq struct {
	name  [ifnamsiz]byte
	flags uint16
	_     [22]byte // padding
}

// linuxTUN implements the Device interface for Linux
type linuxTUN struct {
	file   *os.File
	name   string
	mtu    int
	config *Config
	mu     sync.RWMutex
	closed bool
}

// New creates a new TUN device on Linux
func New(config *Config) (Device, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Open TUN device
	file, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	// Configure the device
	var req ifreq
	copy(req.name[:], config.Name)
	req.flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIff, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	// Get the actual device name
	name := strings.TrimRight(string(req.name[:]), "\x00")

	dev := &linuxTUN{
		file:   file,
		name:   name,
		mtu:    config.MTU,
		config: config,
	}

	// Configure IP address if specified
	if config.Address != "" {
		if err := dev.configureAddress(config.Address); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to configure address: %w", err)
		}
	}

	// Set MTU
	if config.MTU > 0 {
		if err := dev.SetMTU(config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Bring up the interface
	if err := dev.setUp(); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to bring up interface: %w", err)
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
func (t *linuxTUN) Read(p []byte) (int, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return 0, ErrDeviceNotOpen
	}
	t.mu.RUnlock()

	return t.file.Read(p)
}

// Write writes a packet to the TUN device
func (t *linuxTUN) Write(p []byte) (int, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return 0, ErrDeviceNotOpen
	}
	t.mu.RUnlock()

	return t.file.Write(p)
}

// Close closes the TUN device
func (t *linuxTUN) Close() error {
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

	return t.file.Close()
}

// Name returns the device name
func (t *linuxTUN) Name() string {
	return t.name
}

// MTU returns the device MTU
func (t *linuxTUN) MTU() int {
	return t.mtu
}

// SetMTU sets the device MTU
func (t *linuxTUN) SetMTU(mtu int) error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	t.mtu = mtu
	return nil
}

// configureAddress configures the IP address on the interface
func (t *linuxTUN) configureAddress(address string) error {
	// Parse address to validate
	_, _, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", address, err)
	}

	cmd := exec.Command("ip", "addr", "add", address, "dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	return nil
}

// setUp brings up the interface
func (t *linuxTUN) setUp() error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up")
	return cmd.Run()
}

// addRoute adds a route through this interface
func (t *linuxTUN) addRoute(route string) error {
	cmd := exec.Command("ip", "route", "add", route, "dev", t.name)
	return cmd.Run()
}

// removeRoute removes a route
func (t *linuxTUN) removeRoute(route string) error {
	cmd := exec.Command("ip", "route", "del", route, "dev", t.name)
	return cmd.Run()
}
