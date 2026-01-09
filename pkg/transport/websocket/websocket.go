package websocket

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/gorilla/websocket"
)

type wsTransport struct {
	path string
}

// NewWSTransport creates a new Websocket transporter
func NewWSTransport(path string) transport.Transporter {
	return &wsTransport{
		path: path,
	}
}

func (t *wsTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	url := "ws://" + addr + t.path
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

func (t *wsTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	// Websocket usually runs over HTTP server.
	// For transport interface, we might need a custom Listener that upgrades HTTP requests.
	// This is complex because net.Listener expects Accept() -> net.Conn.
	// We can implement a bridge.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln, t.path), nil
}

func (t *wsTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("websocket does not support ListenPacket")
}

func (t *wsTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("websocket does not support DialPacket")
}

// Wrapper for websocket.Conn to net.Conn
type wsConn struct {
	conn *websocket.Conn
	buff []byte
}

func NewConn(conn *websocket.Conn) net.Conn {
	return &wsConn{conn: conn}
}

func (c *wsConn) Read(b []byte) (int, error) {
	if len(c.buff) > 0 {
		n := copy(b, c.buff)
		c.buff = c.buff[n:]
		return n, nil
	}

	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		c.buff = msg[n:]
	}
	return n, nil
}

func (c *wsConn) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error {
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Listener Wrapper
type wsListener struct {
	net.Listener
	path   string
	conns  chan net.Conn
	closed chan struct{}
}

func NewListener(ln net.Listener, path string) *wsListener {
	l := &wsListener{
		Listener: ln,
		path:     path,
		conns:    make(chan net.Conn),
		closed:   make(chan struct{}),
	}
	go l.serve()
	return l
}

func (l *wsListener) serve() {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux.HandleFunc(l.path, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		select {
		case l.conns <- NewConn(conn):
		case <-l.closed:
			conn.Close()
		}
	})

	server := &http.Server{Handler: mux}
	server.Serve(l.Listener)
}

func (l *wsListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *wsListener) Close() error {
	close(l.closed)
	return l.Listener.Close()
}

// WSPacketConn implements net.PacketConn over WebSocket
type WSPacketConn struct {
	conn *websocket.Conn
}

func NewWSPacketConn(conn *websocket.Conn) *WSPacketConn {
	return &WSPacketConn{conn: conn}
}

func (c *WSPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *WSPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WSPacketConn) Close() error {
	return c.conn.Close()
}

func (c *WSPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *WSPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WSPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WSPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
