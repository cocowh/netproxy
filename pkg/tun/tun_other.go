//go:build !linux && !darwin

package tun

// New creates a new TUN device (not supported on this platform)
func New(config *Config) (Device, error) {
	return nil, ErrDeviceNotSupported
}
