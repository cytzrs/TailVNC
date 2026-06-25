package authtoken

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	tok, err := Generate(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("len=%d, want 32", len(tok))
	}
	tok2, _ := Generate(32)
	if bytes.Equal(tok, tok2) {
		t.Fatal("Generate produced identical tokens twice")
	}
}

// TestListenerAcceptsGoodRejectsBad: a wrong-token connection is dropped and
// the next (valid) connection is the one Accept returns.
func TestListenerAcceptsGoodRejectsBad(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	tok, _ := Generate(32)
	ln := NewListener(inner, tok)

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	// Bad client first (wrong token) — must be silently dropped.
	bad, _ := net.Dial("tcp", inner.Addr().String())
	bad.Write(bytes.Repeat([]byte{0}, 32))

	// Good client (correct token) — must be the one accepted.
	good, _ := net.Dial("tcp", inner.Addr().String())
	good.Write(tok)

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept err: %v", r.err)
		}
		// Echo a marker through the accepted conn; it must reach `good`.
		if _, err := r.c.Write([]byte("OK")); err != nil {
			t.Fatalf("write: %v", err)
		}
		good.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2)
		if _, err := good.Read(buf); err != nil {
			t.Fatalf("good read: %v", err)
		}
		if string(buf) != "OK" {
			t.Fatal("accepted wrong conn — bad client leaked through")
		}
		r.c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out — good client not accepted")
	}
	bad.Close()
	good.Close()
}
