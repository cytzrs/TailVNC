// Package authtoken provides a one-time shared-secret handshake used to
// authenticate the loopback IPC between the TailVNC service (Session 0) and
// its user-session agent (SEC-2). Without it any local process could connect
// to 127.0.0.1:<agent-port> and seize unauthenticated desktop control.
package authtoken

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net"
	"time"
)

// Generate returns n cryptographically random bytes.
func Generate(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Listener wraps a net.Listener. Each accepted connection must send exactly
// len(token) bytes matching token within 5 seconds, else it is closed and the
// next pending connection is tried (a misbehaving local peer cannot DoS the
// agent's accept loop by spamming bad tokens).
type Listener struct {
	net.Listener
	token []byte
}

// NewListener wraps ln so every connection must authenticate with token.
// If token is empty NewListener returns ln unchanged (no auth — used when the
// agent runs standalone, e.g. --agent without a service parent).
func NewListener(ln net.Listener, token []byte) net.Listener {
	if len(token) == 0 {
		return ln
	}
	return &Listener{Listener: ln, token: token}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		buf := make([]byte, len(l.token))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(c, buf)
		_ = c.SetReadDeadline(time.Time{})
		if err != nil || subtle.ConstantTimeCompare(buf, l.token) != 1 {
			c.Close()
			continue
		}
		return c, nil
	}
}
