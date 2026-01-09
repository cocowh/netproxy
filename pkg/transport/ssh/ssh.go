package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cocowh/netproxy/pkg/transport"
	"golang.org/x/crypto/ssh"
)

type sshTransport struct {
	user       string
	password   string
	keyFile    string
	remoteAddr string // The SSH server address to connect to
	client     *ssh.Client
	mu         sync.Mutex
}

// NewSSHTransport creates a new SSH transporter (Tunnel Client)
func NewSSHTransport(user, password, keyFile, remoteAddr string) transport.Transporter {
	return &sshTransport{
		user:       user,
		password:   password,
		keyFile:    keyFile,
		remoteAddr: remoteAddr,
	}
}

func (t *sshTransport) connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		return nil
	}

	config := &ssh.ClientConfig{
		User:            t.user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Timeout: 0, // Timeout is ignored when using DialContext on the net.Conn
	}

	if t.keyFile != "" {
		key, err := os.ReadFile(t.keyFile)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(t.password)}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.remoteAddr)
	if err != nil {
		return err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, t.remoteAddr, config)
	if err != nil {
		conn.Close()
		return err
	}

	t.client = ssh.NewClient(c, chans, reqs)
	return nil
}

func (t *sshTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if err := t.connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to ssh server: %w", err)
	}

	t.mu.Lock()
	client := t.client
	t.mu.Unlock()

	// Open a tunnel via the SSH connection
	// Note: context cancellation is tricky here because ssh.Client.Dial doesn't support context
	return client.Dial("tcp", addr)
}

func (t *sshTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	if err := t.connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to ssh server: %w", err)
	}

	t.mu.Lock()
	client := t.client
	t.mu.Unlock()

	// Reverse port forwarding (Listen on remote SSH server)
	return client.Listen("tcp", addr)
}

func (t *sshTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("ssh does not support ListenPacket")
}

func (t *sshTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("ssh does not support DialPacket")
}
