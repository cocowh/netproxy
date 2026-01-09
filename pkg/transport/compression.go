package transport

import (
	"net"

	"github.com/golang/snappy"
)

// CompressionConn wraps a net.Conn with Snappy compression
type CompressionConn struct {
	net.Conn
	reader *snappy.Reader
	writer *snappy.Writer
}

func NewCompressionConn(conn net.Conn) net.Conn {
	return &CompressionConn{
		Conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
	}
}

func (c *CompressionConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *CompressionConn) Write(b []byte) (n int, err error) {
	n, err = c.writer.Write(b)
	if err != nil {
		return n, err
	}
	// Snappy buffered writer needs Flush to actually send data
	err = c.writer.Flush()
	return n, err
}
