package protocol

import (
	"context"
	"net"
)

// Handler handles a network connection for a specific protocol
type Handler interface {
	// Handle processes the connection
	// Returns error if handling failed
	Handle(ctx context.Context, conn net.Conn) error
}

// PacketHandler handles network packets for a specific protocol
type PacketHandler interface {
	// HandlePacket processes a packet connection
	// Returns error if handling failed
	HandlePacket(ctx context.Context, conn net.PacketConn) error
}
