package transport

import (
	"io"
	"net"
)

// Relay copies data between two connections
func Relay(a, b net.Conn) error {
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(b, a)
		errChan <- err
	}()

	// Wait for first error or EOF
	return <-errChan
}
