package torogo

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSOCKS5ServerLifecycle(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, WithLazyBootstrap())
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	defer c.Close()

	srv, err := c.ListenSOCKS5("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenSOCKS5 error: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial SOCKS5 server: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting error: %v", err)
	}

	var resp [2]byte
	if _, err := conn.Read(resp[:]); err != nil {
		t.Fatalf("read greeting response error: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected SOCKS5 auth response: %v", resp)
	}
}
