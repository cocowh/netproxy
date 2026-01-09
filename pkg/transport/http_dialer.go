package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// HTTPDialer implements ProxyDialer for HTTP CONNECT proxy
type HTTPDialer struct {
	next    ProxyDialer
	address string
	user    string
	password     string
}

// NewHTTPDialer creates a new HTTP proxy dialer
func NewHTTPDialer(next ProxyDialer, address, user, password string) ProxyDialer {
	return &HTTPDialer{
		next:    next,
		address: address,
		user:    user,
		password:     password,
	}
}

func (d *HTTPDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// 1. Connect to HTTP Proxy Server
	conn, err := d.next.Dial(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	// 2. Send CONNECT Request
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: addr},
		Header: make(http.Header),
		Host:   addr,
	}

	if d.user != "" || d.password != "" {
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(d.user+":"+d.password))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write connect request: %v", err)
	}

	// 3. Read Response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read connect response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy returned status: %s", resp.Status)
	}

	return conn, nil
}

func (d *HTTPDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// HTTP proxies usually don't support UDP (unless HTTP/3 or CONNECT-UDP extension).
	return nil, fmt.Errorf("UDP not supported by HTTP proxy")
}
