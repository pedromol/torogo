package torogo

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestControlServerCommands(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient(ctx, WithLazyBootstrap())
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	defer client.Close()

	srv, err := client.ListenControl("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenControl error: %v", err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial control server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 1. PROTOCOLINFO without auth (allowed)
	_, _ = conn.Write([]byte("PROTOCOLINFO 1\r\n"))
	var protoLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read PROTOCOLINFO error: %v", err)
		}
		protoLines = append(protoLines, strings.TrimSpace(line))
		if strings.HasPrefix(line, "250 OK") {
			break
		}
	}
	if len(protoLines) < 3 {
		t.Fatalf("unexpected PROTOCOLINFO response: %v", protoLines)
	}

	// 2. AUTHENTICATE
	_, _ = conn.Write([]byte("AUTHENTICATE\r\n"))
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "250 OK") {
		t.Fatalf("expected 250 OK for AUTHENTICATE, got: %s", line)
	}

	// 3. GETINFO version
	_, _ = conn.Write([]byte("GETINFO version\r\n"))
	line1, _ := reader.ReadString('\n')
	line2, _ := reader.ReadString('\n')
	if !strings.Contains(line1, "torogo") || !strings.HasPrefix(line2, "250 OK") {
		t.Fatalf("unexpected GETINFO version response: %s %s", line1, line2)
	}

	// 4. SIGNAL NEWNYM
	_, _ = conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	line, err = reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "250 OK") {
		t.Fatalf("expected 250 OK for SIGNAL NEWNYM, got: %s", line)
	}

	// 5. QUIT
	_, _ = conn.Write([]byte("QUIT\r\n"))
	line, _ = reader.ReadString('\n')
	if !strings.Contains(line, "closing connection") {
		t.Fatalf("expected closing connection on QUIT, got: %s", line)
	}
}
