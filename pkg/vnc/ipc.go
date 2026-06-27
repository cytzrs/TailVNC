//go:build windows

package vnc

import (
	"io"
	"log"
	"net"
	"time"

	winio "github.com/tailscale/go-winio"
)

// AgentPipeName is the fixed Windows Named Pipe path used for service→agent IPC.
// Using a named pipe instead of TCP loopback eliminates network-stack overhead
// and allows kernel-level ACL control (only SYSTEM and Administrators can connect).
const AgentPipeName = `\\.\pipe\TailVNC_Agent`

// agentPipeName is retained as an alias for internal use within the vnc package.
const agentPipeName = AgentPipeName

// proxyToAgent connects to the local agent VNC server via a Windows Named Pipe
// and bidirectionally proxies bytes between the remote VNC client and the agent.
// Retries for up to 10 seconds to give the agent time to start.
// If token is non-empty it is written first (SEC-2): the agent's pipe
// listener drops connections that do not present it.
func proxyToAgent(client net.Conn, _ string, token []byte) {
	defer client.Close()

	var agentConn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		agentConn, err = winio.DialPipe(agentPipeName, nil)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		log.Printf("[proxy] %s: cannot reach agent pipe %s: %v", client.RemoteAddr(), agentPipeName, err)
		return
	}
	defer agentConn.Close()

	// SEC-2: present the one-time token before any RFB bytes flow.
	if len(token) > 0 {
		_ = agentConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := agentConn.Write(token); err != nil {
			log.Printf("[proxy] %s: token write failed: %v", client.RemoteAddr(), err)
			return
		}
		_ = agentConn.SetWriteDeadline(time.Time{})
	}

	log.Printf("[proxy] %s ↔ agent pipe", client.RemoteAddr())

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
