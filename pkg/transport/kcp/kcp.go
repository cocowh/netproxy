package kcp

import (
	"context"
	"net"

	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/xtaci/kcp-go/v5"
)

type kcpTransport struct {
	dataShards   int
	parityShards int
	key          string
	salt         string
}

// NewKCPTransport creates a new KCP transporter
func NewKCPTransport(dataShards, parityShards int, key, salt string) transport.Transporter {
	return &kcpTransport{
		dataShards:   dataShards,
		parityShards: parityShards,
		key:          key,
		salt:         salt,
	}
}

func (t *kcpTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	block, _ := kcp.NewAESBlockCrypt([]byte(t.key))
	return kcp.DialWithOptions(addr, block, t.dataShards, t.parityShards)
}

func (t *kcpTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	block, _ := kcp.NewAESBlockCrypt([]byte(t.key))
	return kcp.ListenWithOptions(addr, block, t.dataShards, t.parityShards)
}

func (t *kcpTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// kcp-go does not expose ListenPacket directly with options nicely for raw packet handling
	// in the same way, but it works over UDP.
	// For KCP, we usually treat it as a stream protocol over UDP.
	return nil, net.UnknownNetworkError("kcp does not support ListenPacket (stream only)")
}

func (t *kcpTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("kcp does not support DialPacket")
}
