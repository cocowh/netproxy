// Package obfs implements traffic obfuscation protocols.
// HTTP obfuscation disguises traffic as normal HTTP requests/responses.
package obfs

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// HTTPObfs implements HTTP obfuscation
type HTTPObfs struct {
	host       string
	path       string
	isClient   bool
	headerSent bool
	headerRead bool
	mu         sync.Mutex
}

// HTTPObfsConfig configures HTTP obfuscation
type HTTPObfsConfig struct {
	Host string // Host header value
	Path string // Request path
}

// DefaultHTTPObfsConfig returns default configuration
func DefaultHTTPObfsConfig() *HTTPObfsConfig {
	return &HTTPObfsConfig{
		Host: "www.bing.com",
		Path: "/",
	}
}

// NewHTTPObfsClient creates a client-side HTTP obfuscation wrapper
func NewHTTPObfsClient(conn net.Conn, config *HTTPObfsConfig) net.Conn {
	if config == nil {
		config = DefaultHTTPObfsConfig()
	}
	return &HTTPObfsConn{
		Conn: conn,
		obfs: &HTTPObfs{
			host:     config.Host,
			path:     config.Path,
			isClient: true,
		},
	}
}

// NewHTTPObfsServer creates a server-side HTTP obfuscation wrapper
func NewHTTPObfsServer(conn net.Conn, config *HTTPObfsConfig) net.Conn {
	if config == nil {
		config = DefaultHTTPObfsConfig()
	}
	return &HTTPObfsConn{
		Conn: conn,
		obfs: &HTTPObfs{
			host:     config.Host,
			path:     config.Path,
			isClient: false,
		},
	}
}

// HTTPObfsConn wraps a connection with HTTP obfuscation
type HTTPObfsConn struct {
	net.Conn
	obfs      *HTTPObfs
	readBuf   bytes.Buffer
	writeBuf  bytes.Buffer
	readMux   sync.Mutex
	writeMux  sync.Mutex
}

// Read reads data from the obfuscated connection
func (c *HTTPObfsConn) Read(b []byte) (int, error) {
	c.readMux.Lock()
	defer c.readMux.Unlock()

	// Return buffered data first
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	c.obfs.mu.Lock()
	headerRead := c.obfs.headerRead
	c.obfs.mu.Unlock()

	if !headerRead {
		// Read and parse HTTP header
		reader := bufio.NewReader(c.Conn)

		if c.obfs.isClient {
			// Client reads HTTP response
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				return 0, fmt.Errorf("read HTTP response: %w", err)
			}
			defer resp.Body.Close()

			// Read body into buffer
			_, err = io.Copy(&c.readBuf, resp.Body)
			if err != nil && err != io.EOF {
				return 0, fmt.Errorf("read response body: %w", err)
			}
		} else {
			// Server reads HTTP request
			req, err := http.ReadRequest(reader)
			if err != nil {
				return 0, fmt.Errorf("read HTTP request: %w", err)
			}
			defer req.Body.Close()

			// Read body into buffer
			_, err = io.Copy(&c.readBuf, req.Body)
			if err != nil && err != io.EOF {
				return 0, fmt.Errorf("read request body: %w", err)
			}
		}

		c.obfs.mu.Lock()
		c.obfs.headerRead = true
		c.obfs.mu.Unlock()

		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(b)
		}
	}

	// After header, read raw data
	return c.Conn.Read(b)
}

// Write writes data to the obfuscated connection
func (c *HTTPObfsConn) Write(b []byte) (int, error) {
	c.writeMux.Lock()
	defer c.writeMux.Unlock()

	c.obfs.mu.Lock()
	headerSent := c.obfs.headerSent
	c.obfs.mu.Unlock()

	if !headerSent {
		var header bytes.Buffer

		if c.obfs.isClient {
			// Client sends HTTP request
			header.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", c.obfs.path))
			header.WriteString(fmt.Sprintf("Host: %s\r\n", c.obfs.host))
			header.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
			header.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
			header.WriteString("Accept-Language: en-US,en;q=0.5\r\n")
			header.WriteString("Accept-Encoding: gzip, deflate\r\n")
			header.WriteString("Connection: keep-alive\r\n")
			header.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(b)))
			header.WriteString("\r\n")
		} else {
			// Server sends HTTP response
			header.WriteString("HTTP/1.1 200 OK\r\n")
			header.WriteString("Server: nginx\r\n")
			header.WriteString("Content-Type: text/html; charset=utf-8\r\n")
			header.WriteString("Transfer-Encoding: chunked\r\n")
			header.WriteString("Connection: keep-alive\r\n")
			header.WriteString("\r\n")
		}

		// Write header
		if _, err := c.Conn.Write(header.Bytes()); err != nil {
			return 0, err
		}

		c.obfs.mu.Lock()
		c.obfs.headerSent = true
		c.obfs.mu.Unlock()
	}

	// Write data
	return c.Conn.Write(b)
}

// SimpleHTTPObfs implements a simpler HTTP obfuscation compatible with simple-obfs
type SimpleHTTPObfs struct {
	host     string
	isClient bool
}

// SimpleHTTPObfsConn wraps a connection with simple HTTP obfuscation
type SimpleHTTPObfsConn struct {
	net.Conn
	obfs       *SimpleHTTPObfs
	firstRead  bool
	firstWrite bool
	readBuf    []byte
	mu         sync.Mutex
}

// NewSimpleHTTPObfsClient creates a simple-obfs compatible client wrapper
func NewSimpleHTTPObfsClient(conn net.Conn, host string) net.Conn {
	if host == "" {
		host = "www.bing.com"
	}
	return &SimpleHTTPObfsConn{
		Conn: conn,
		obfs: &SimpleHTTPObfs{
			host:     host,
			isClient: true,
		},
		firstRead:  true,
		firstWrite: true,
	}
}

// NewSimpleHTTPObfsServer creates a simple-obfs compatible server wrapper
func NewSimpleHTTPObfsServer(conn net.Conn) net.Conn {
	return &SimpleHTTPObfsConn{
		Conn: conn,
		obfs: &SimpleHTTPObfs{
			isClient: false,
		},
		firstRead:  true,
		firstWrite: true,
	}
}

// Read reads from the obfuscated connection
func (c *SimpleHTTPObfsConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return buffered data first
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	if c.firstRead {
		c.firstRead = false

		// Read until we find the end of HTTP header
		buf := make([]byte, 4096)
		n, err := c.Conn.Read(buf)
		if err != nil {
			return 0, err
		}

		// Find header end
		headerEnd := bytes.Index(buf[:n], []byte("\r\n\r\n"))
		if headerEnd == -1 {
			// No header found, return as-is
			return copy(b, buf[:n]), nil
		}

		// Skip header, return payload
		payload := buf[headerEnd+4 : n]
		if len(payload) > 0 {
			copied := copy(b, payload)
			if copied < len(payload) {
				c.readBuf = append(c.readBuf, payload[copied:]...)
			}
			return copied, nil
		}

		// Header only, read more
		return c.Conn.Read(b)
	}

	return c.Conn.Read(b)
}

// Write writes to the obfuscated connection
func (c *SimpleHTTPObfsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.firstWrite {
		c.firstWrite = false

		var buf bytes.Buffer
		if c.obfs.isClient {
			// Encode payload in base64 for the request
			encoded := base64.StdEncoding.EncodeToString(b)
			buf.WriteString(fmt.Sprintf("GET /?data=%s HTTP/1.1\r\n", encoded))
			buf.WriteString(fmt.Sprintf("Host: %s\r\n", c.obfs.host))
			buf.WriteString("User-Agent: curl/7.64.1\r\n")
			buf.WriteString("Accept: */*\r\n")
			buf.WriteString("\r\n")
		} else {
			buf.WriteString("HTTP/1.1 200 OK\r\n")
			buf.WriteString("Content-Type: application/octet-stream\r\n")
			buf.WriteString("Connection: keep-alive\r\n")
			buf.WriteString("\r\n")
			buf.Write(b)
		}

		_, err := c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return c.Conn.Write(b)
}
