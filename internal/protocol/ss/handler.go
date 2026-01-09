package ss

import (
	"context"
	"fmt"
	"io"
	"net"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/pkg/protocol"
	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

type ssHandler struct {
	cipher core.Cipher
	logger logger.Logger
}

// NewSSHandler creates a new Shadowsocks protocol handler
func NewSSHandler(method, password string, log logger.Logger) (protocol.Handler, error) {
	cipher, err := core.PickCipher(method, []byte{}, password)
	if err != nil {
		return nil, fmt.Errorf("failed to pick cipher: %v", err)
	}

	return &ssHandler{
		cipher: cipher,
		logger: log,
	}, nil
}

func (h *ssHandler) Handle(ctx context.Context, conn net.Conn) error {
	// ShadowSocks handshake:
	// 1. Receive salt (if AEAD) and decrypt payload
	// 2. Read target address
	// 3. Dial target and relay

	// Use shadowsocks-go's conn wrapper to handle encryption/decryption transparently
	conn = h.cipher.StreamConn(conn)

	// Read target address
	targetAddr, err := readAddress(conn)
	if err != nil {
		h.logger.Error("Failed to read target address", logger.Any("error", err))
		return err
	}

	h.logger.Info("Connecting to target", logger.Any("target", targetAddr))

	// Establish connection to target
	var targetConn net.Conn
	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		targetConn, err = dialer.Dial(ctx, "tcp", targetAddr.String())
	} else {
		targetConn, err = net.Dial("tcp", targetAddr.String())
	}

	if err != nil {
		h.logger.Error("Failed to dial target", logger.Any("target", targetAddr), logger.Any("error", err))
		return err
	}
	defer targetConn.Close()

	// Relay data
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, targetConn)
		errChan <- err
	}()

	return <-errChan
}

// readAddress reads the target address from the stream.
// Copied/Adapted from go-shadowsocks2 or similar implementation logic since it's not exported publicly in a convenient way often.
// Address format: [1-byte type] [variable-length host] [2-byte port]
func readAddress(c net.Conn) (net.Addr, error) {
	// buf size for max domain length (256) + 1 type + 2 port
	buf := make([]byte, 260)

	// Read address type
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return nil, err
	}

	var reqLen int
	switch buf[0] {
	case 1: // IPv4
		reqLen = 3 + 2 // 3 remaining bytes of IPv4 + 2 port
	case 3: // Domain
		if _, err := io.ReadFull(c, buf[1:2]); err != nil {
			return nil, err
		}
		reqLen = int(buf[1]) + 2
	case 4: // IPv6
		reqLen = 15 + 2 // 15 remaining bytes of IPv6 + 2 port
	default:
		return nil, fmt.Errorf("unknown address type: %d", buf[0])
	}

	if _, err := io.ReadFull(c, buf[1:1+reqLen]); err != nil {
		return nil, err
	}

	// Parsing address logic
	switch buf[0] {
	case 1: // IPv4
		return &net.TCPAddr{
			IP:   net.IP(buf[1 : 1+4]),
			Port: int(buf[1+4])<<8 | int(buf[1+4+1]),
		}, nil
	case 3: // Domain
		host := string(buf[2 : 2+int(buf[1])])
		port := int(buf[2+int(buf[1])])<<8 | int(buf[2+int(buf[1])+1])
		return &tcpAddr{host, port}, nil
	case 4: // IPv6
		return &net.TCPAddr{
			IP:   net.IP(buf[1 : 1+16]),
			Port: int(buf[1+16])<<8 | int(buf[1+16+1]),
		}, nil
	}
	return nil, nil
}

type tcpAddr struct {
	host string
	port int
}

func (a *tcpAddr) Network() string { return "tcp" }
func (a *tcpAddr) String() string  { return fmt.Sprintf("%s:%d", a.host, a.port) }
