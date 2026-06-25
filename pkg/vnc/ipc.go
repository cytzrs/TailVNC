//go:build windows

package vnc

import (
	"io"
	"log"
	"net"
	"time"
)

// proxyToAgent connects to the local agent VNC server and bidirectionally
// proxies bytes between the remote VNC client and the agent.
// Retries for up to 10 seconds to give the agent time to start.
func proxyToAgent(client net.Conn, port string) {
	defer client.Close()

	addr := "127.0.0.1:" + port

	var agentConn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		agentConn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		log.Printf("[proxy] %s: cannot reach agent at %s: %v", client.RemoteAddr(), addr, err)
		return
	}
	defer agentConn.Close()

	log.Printf("[proxy] %s ↔ agent:%s", client.RemoteAddr(), port)

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		dst.Close()
		done <- struct{}{}
	}
	go cp(agentConn, client)
	go cp(client, agentConn)
	<-done
	<-done
}
