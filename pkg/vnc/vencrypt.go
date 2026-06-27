//go:build windows

package vnc

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

// VeNCrypt security type constants (RFC: libvncserver VeNCrypt extension).
const (
	secVeNCrypt       = 19   // RFB security type that initiates VeNCrypt sub-protocol
	vencMajorVersion  = 0
	vencMinorVersion  = 2
	authTLSVnc        = 260 // TLS tunnel + standard VNC auth inside
	authX509Vnc       = 262 // X.509 TLS + standard VNC auth inside
)

// vencryptAuthTypes is the list of VeNCrypt auth types we advertise to clients,
// in order of preference.
var vencryptAuthTypes = []uint32{authX509Vnc, authTLSVnc}

// doVeNCrypt performs the VeNCrypt sub-protocol handshake and returns a TLS-wrapped
// connection. After this returns, the caller continues with standard RFB auth
// (VNC challenge-response) inside the encrypted tunnel.
//
// Protocol flow (VeNCrypt v0.2):
//   Server → Client: majver (1 byte), minver (1 byte)
//   Client → Server: majver (1 byte), minver (1 byte)
//   Server → Client: u8 count, u32[count] auth types
//   Client → Server: u32 selected auth type
//   Server → Client: u8 ack (1 = accepted)
//   → TLS handshake (crypto/tls.Accept)
func (s *session) doVeNCrypt() (*tls.Conn, error) {
	if s.tlsConfig == nil {
		return nil, fmt.Errorf("VeNCrypt requested but no TLS config")
	}

	// 1. Server → Client: version (major, minor)
	if _, err := s.conn.Write([]byte{vencMajorVersion, vencMinorVersion}); err != nil {
		return nil, fmt.Errorf("vencrypt: write version: %w", err)
	}

	// 2. Client → Server: version response
	var clientVer [2]byte
	if _, err := io.ReadFull(s.conn, clientVer[:]); err != nil {
		return nil, fmt.Errorf("vencrypt: read version: %w", err)
	}
	if clientVer[0] != vencMajorVersion || clientVer[1] != vencMinorVersion {
		// Reject unsupported version.
		s.conn.Write([]byte{0}) // not accepted
		return nil, fmt.Errorf("vencrypt: client version %d.%d not supported (need %d.%d)",
			clientVer[0], clientVer[1], vencMajorVersion, vencMinorVersion)
	}

	// 3. Server → Client: auth type list (u8 count + u32[count])
	buf := make([]byte, 1+len(vencryptAuthTypes)*4)
	buf[0] = byte(len(vencryptAuthTypes))
	for i, t := range vencryptAuthTypes {
		binary.BigEndian.PutUint32(buf[1+i*4:], t)
	}
	if _, err := s.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("vencrypt: write auth types: %w", err)
	}

	// 4. Client → Server: selected auth type
	var selBuf [4]byte
	if _, err := io.ReadFull(s.conn, selBuf[:]); err != nil {
		return nil, fmt.Errorf("vencrypt: read auth selection: %w", err)
	}
	selected := binary.BigEndian.Uint32(selBuf[:])

	// Validate selection.
	valid := false
	for _, t := range vencryptAuthTypes {
		if t == selected {
			valid = true
			break
		}
	}
	if !valid {
		s.conn.Write([]byte{0}) // not accepted
		return nil, fmt.Errorf("vencrypt: client selected unsupported auth type %d", selected)
	}

	// 5. Server → Client: ack (1 = accepted)
	if _, err := s.conn.Write([]byte{1}); err != nil {
		return nil, fmt.Errorf("vencrypt: write ack: %w", err)
	}

	log.Printf("[%s] VeNCrypt: starting TLS handshake (auth type %d)", s.addr(), selected)

	// 6. TLS handshake.
	tlsConn := tls.Server(s.conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("vencrypt: TLS handshake: %w", err)
	}

	log.Printf("[%s] VeNCrypt: TLS established", s.addr())
	return tlsConn, nil
}
