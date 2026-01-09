package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/pkg/protocol"
	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/elazarl/goproxy"
)

type httpHandler struct {
	proxy *goproxy.ProxyHttpServer
	auth  auth.Authenticator
}

// NewHTTPHandler creates a new HTTP/HTTPS proxy handler
func NewHTTPHandler(authenticator auth.Authenticator) protocol.Handler {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	return &httpHandler{
		proxy: proxy,
		auth:  authenticator,
	}
}

func (h *httpHandler) Handle(ctx context.Context, conn net.Conn) error {
	// goproxy expects a net/http Handler interface but operates on requests.
	// For a raw conn, we need to bridge it or use a custom implementation.
	// goproxy library is designed to work with http.Server.
	// Since we are handling raw connections, we might need to peek at the connection
	// to see if it's CONNECT or regular HTTP, then serve it.

	// However, usually we use http.Serve to handle the listener.
	// But our architecture accepts a net.Conn.
	// We can manually read the request and pass it to goproxy, or use a simplified internal implementation.
	// For simplicity and to fit the interface, let's implement a basic HTTP/HTTPS handler
	// or adapt goproxy to handle a single connection.

	// Reading the request from conn
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	// Authentication Check
	if h.auth != nil {
		authHeader := req.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			return h.send407(conn)
		}

		// Parse Basic Auth
		fields := strings.SplitN(authHeader, " ", 2)
		if len(fields) != 2 || fields[0] != "Basic" {
			return h.send407(conn)
		}

		payload, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return h.send407(conn)
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 {
			return h.send407(conn)
		}

		if _, err := h.auth.Authenticate(ctx, pair[0], pair[1]); err != nil {
			return h.send407(conn)
		}
	}

	// Check if it's HTTPS CONNECT
	if req.Method == http.MethodConnect {
		return h.handleConnect(ctx, conn, req)
	}

	// Regular HTTP
	return h.handleHTTP(ctx, conn, req)
}

func (h *httpHandler) send407(conn net.Conn) error {
	conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"NetProxy\"\r\n\r\n"))
	return fmt.Errorf("proxy authentication required")
}

func (h *httpHandler) handleConnect(ctx context.Context, conn net.Conn, req *http.Request) error {
	// Establish connection to target
	var targetConn net.Conn
	var err error

	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		targetConn, err = dialer.Dial(ctx, "tcp", req.Host)
	} else {
		targetConn, err = net.Dial("tcp", req.Host)
	}

	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return err
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Tunnel data
	return tunnel(conn, targetConn)
}

func (h *httpHandler) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request) error {
	// For standard HTTP proxy, the URL must be absolute
	if !req.URL.IsAbs() {
		// If not absolute (transparent proxy case), we need to determine host.
		// Standard proxy requests have absolute URL.
		// If we are acting as a transparent proxy, Host header is used.
		if req.Host == "" {
			return fmt.Errorf("no host in request")
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}

	// Forward request to target
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	// If a dialer is in the context, use it for DialContext
	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(ctx, network, addr)
		}
	}

	// Request URI must be stripped for client request
	req.RequestURI = ""

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Write response back to client
	return resp.Write(conn)
}

func tunnel(c1, c2 net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(c1, c2)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(c2, c1)
		errCh <- err
	}()
	return <-errCh
}
