package tun

import "errors"

var (
	// ErrPacketTooShort indicates the packet is too short to parse
	ErrPacketTooShort = errors.New("packet too short")

	// ErrInvalidIPVersion indicates an invalid IP version
	ErrInvalidIPVersion = errors.New("invalid IP version")

	// ErrDeviceNotSupported indicates TUN is not supported on this platform
	ErrDeviceNotSupported = errors.New("TUN device not supported on this platform")

	// ErrDeviceAlreadyOpen indicates the device is already open
	ErrDeviceAlreadyOpen = errors.New("device already open")

	// ErrDeviceNotOpen indicates the device is not open
	ErrDeviceNotOpen = errors.New("device not open")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied, root/admin required")
)
