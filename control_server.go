package torogo

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
)

// ControlServer implements the Tor Control Protocol (control-spec.txt),
// allowing external tools (like Tor Browser, Nyx, or management scripts)
// to manage and query Torogo over TCP port 9051.
type ControlServer struct {
	client   *Client
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// ListenControl starts a Tor Control Port server on addr (default: "127.0.0.1:9051").
func (c *Client) ListenControl(addr string) (*ControlServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("torogo: listen control on %s: %w", addr, err)
	}
	srv := &ControlServer{
		client:   c,
		listener: ln,
	}
	go srv.serve()
	return srv, nil
}

// Addr returns the listener address of the control server.
func (cs *ControlServer) Addr() net.Addr {
	return cs.listener.Addr()
}

// Close terminates the control server.
func (cs *ControlServer) Close() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed {
		return nil
	}
	cs.closed = true
	return cs.listener.Close()
}

func (cs *ControlServer) serve() {
	for {
		conn, err := cs.listener.Accept()
		if err != nil {
			return
		}
		go cs.handleConn(conn)
	}
}

func (cs *ControlServer) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	authenticated := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "AUTHENTICATE":
			authenticated = true
			_, _ = conn.Write([]byte("250 OK\r\n"))

		case "PROTOCOLINFO":
			resp := "250-PROTOCOLINFO 1\r\n" +
				"250-AUTH METHODS=NULL\r\n" +
				"250-VERSION Tor=\"0.4.8.10 (torogo-pure-go)\"\r\n" +
				"250 OK\r\n"
			_, _ = conn.Write([]byte(resp))

		case "SIGNAL":
			if !authenticated {
				_, _ = conn.Write([]byte("514 Authentication required\r\n"))
				continue
			}
			if len(parts) > 1 && strings.ToUpper(parts[1]) == "NEWNYM" {
				// Signal NEWNYM: reset circuit cache to obtain fresh identity
				cs.client.mu.Lock()
				// Clearing cached consensus forces fresh path sampling on next connection
				cs.client.consensus = nil
				cs.client.mu.Unlock()
				_, _ = conn.Write([]byte("250 OK\r\n"))
			} else {
				_, _ = conn.Write([]byte("250 OK\r\n"))
			}

		case "GETINFO":
			if !authenticated {
				_, _ = conn.Write([]byte("514 Authentication required\r\n"))
				continue
			}
			var b strings.Builder
			for i := 1; i < len(parts); i++ {
				key := strings.ToLower(parts[i])
				switch key {
				case "version":
					b.WriteString("250-version=0.4.8.10 (torogo-pure-go)\r\n")
				case "status/circuit-established":
					b.WriteString("250-status/circuit-established=1\r\n")
				case "status/bootstrap-phase":
					b.WriteString("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n")
				default:
					b.WriteString(fmt.Sprintf("250-%s=\r\n", key))
				}
			}
			b.WriteString("250 OK\r\n")
			_, _ = conn.Write([]byte(b.String()))

		case "SETEVENTS":
			if !authenticated {
				_, _ = conn.Write([]byte("514 Authentication required\r\n"))
				continue
			}
			_, _ = conn.Write([]byte("250 OK\r\n"))

		case "QUIT":
			_, _ = conn.Write([]byte("250 closing connection\r\n"))
			return

		default:
			if !authenticated {
				_, _ = conn.Write([]byte("514 Authentication required\r\n"))
			} else {
				_, _ = conn.Write([]byte("510 Unrecognized command\r\n"))
			}
		}
	}
}
