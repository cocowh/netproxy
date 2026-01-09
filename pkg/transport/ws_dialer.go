package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// WSDialer wraps a ProxyDialer with WebSocket
type WSDialer struct {
	next ProxyDialer
	path string
	host string
}

// NewWSDialer creates a new WSDialer
func NewWSDialer(next ProxyDialer, path, host string) ProxyDialer {
	return &WSDialer{
		next: next,
		path: path,
		host: host,
	}
}

// Dial dials the address and performs WebSocket handshake
func (d *WSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.next.Dial(ctx, "tcp", d.host) // Dial the WS server
	if err != nil {
		return nil, err
	}

	// Prepare WS Handshake
	u := url.URL{Scheme: "ws", Host: d.host, Path: d.path}
	header := http.Header{}
	header.Add("Host", d.host)

	wsConn, _, err := websocket.NewClient(conn, &u, header, 1024, 1024)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket handshake failed: %w", err)
	}

	// Wrap websocket.Conn to net.Conn
	return &wsConnWrapper{Conn: wsConn}, nil
}

func (d *WSDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// Similar to TLS, we want to tunnel UDP over WS.
	// We connect to the proxy endpoint via WS, then use the WS connection as a PacketConn.
	// WS naturally supports message framing (BinaryMessage), so we don't need length prefixing like TLS.
	// Each UDP packet maps to one WS Message.
	
	// Reuse Dial logic to establish WS connection
	conn, err := d.Dial(ctx, "tcp", d.host)
	if err != nil {
		return nil, err
	}
	
	wsWrapper, ok := conn.(*wsConnWrapper)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("internal error: ws conn type mismatch")
	}
	
	return &wsPacketConn{
		conn: wsWrapper.Conn,
	}, nil
}

type wsPacketConn struct {
	conn *websocket.Conn
}

func (c *wsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read next message
	msgType, r, err := c.conn.NextReader()
	if err != nil {
		return 0, nil, err
	}
	
	if msgType != websocket.BinaryMessage {
		// Ignore non-binary messages as we expect UDP packets in binary frames
		// Drain and discard
		if _, err := io.Copy(io.Discard, r); err != nil {
			return 0, nil, err
		}
		// Recursive call to read next valid message
		return c.ReadFrom(p)
	}
	
	// Read content into p
	n, err = io.ReadFull(r, p)
	if err == io.ErrUnexpectedEOF {
		// This means the message was smaller than p, which is normal for UDP
		err = nil 
	} else if err == io.EOF {
		// Empty message?
		err = nil
	} else if err == nil {
		// Buffer filled exactly. Drain the rest of the message reader.
		go io.Copy(io.Discard, r)
	}
	
	return n, c.conn.RemoteAddr(), err
}

func (c *wsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsPacketConn) Close() error {
	return c.conn.Close()
}

func (c *wsPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t) // Sets both?
}

func (c *wsPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// wsConnWrapper adapts *websocket.Conn to net.Conn
type wsConnWrapper struct {
	*websocket.Conn
	reader io.Reader
}

func (w *wsConnWrapper) Read(b []byte) (n int, err error) {
	if w.reader == nil {
		// Get next message reader
		_, r, err := w.Conn.NextReader()
		if err != nil {
			return 0, err
		}
		w.reader = r
	}
	n, err = w.reader.Read(b)
	if err == io.EOF {
		w.reader = nil
		return n, nil
	}
	return n, err
}

func (w *wsConnWrapper) Write(b []byte) (n int, err error) {
	if err := w.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConnWrapper) SetDeadline(t time.Time) error {
	if err := w.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.Conn.SetWriteDeadline(t)
}
