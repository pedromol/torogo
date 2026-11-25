package tor

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseBridgeLine(t *testing.T) {
	// Standard obfs4 bridge line
	line := "Bridge obfs4 192.0.2.1:443 7F25776C684351BD7C8F2241D3B6CCDAE5D285EC cert=4q3p9S0... iat-mode=0"
	cfg, err := ParseBridgeLine(line)
	if err != nil {
		t.Fatalf("ParseBridgeLine failed: %v", err)
	}

	if cfg.Transport != "obfs4" {
		t.Fatalf("expected transport obfs4, got %s", cfg.Transport)
	}
	if cfg.Address != "192.0.2.1:443" {
		t.Fatalf("expected address 192.0.2.1:443, got %s", cfg.Address)
	}
	if cfg.Fingerprint != "7F25776C684351BD7C8F2241D3B6CCDAE5D285EC" {
		t.Fatalf("expected fingerprint match, got %s", cfg.Fingerprint)
	}
	if cfg.Args["cert"] != "4q3p9S0..." || cfg.Args["iat-mode"] != "0" {
		t.Fatalf("args mismatch: %+v", cfg.Args)
	}

	// Vanilla bridge line without transport prefix
	vanilla := "Bridge 198.51.100.2:9001"
	cfgV, err := ParseBridgeLine(vanilla)
	if err != nil {
		t.Fatalf("ParseBridgeLine vanilla failed: %v", err)
	}
	if cfgV.Transport != "vanilla" || cfgV.Address != "198.51.100.2:9001" {
		t.Fatalf("vanilla parse mismatch: %+v", cfgV)
	}
}

func TestSocks5DialerHandshake(t *testing.T) {
	// Mock SOCKS5 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	proxyAddr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read greeting: VER 5, NMETHODS 1, METHOD 0
		var greet [3]byte
		if _, err := io.ReadFull(conn, greet[:]); err != nil {
			return
		}
		if greet[0] != 5 || greet[1] != 1 || greet[2] != 0 {
			return
		}

		// Send choice: VER 5, METHOD 0
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// Read request: VER 5, CMD 1, RSV 0, ATYP 1, IP4 (4), PORT (2)
		var req [10]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}

		// Send reply: VER 5, REP 0 (success), RSV 0, ATYP 1, BND.ADDR 0.0.0.0:0
		reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
		_, _ = conn.Write(reply)

		// Echo test
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err == nil {
			_, _ = conn.Write(buf[:])
		}
	}()

	dialer := &Socks5Dialer{
		ProxyAddr: proxyAddr,
		Timeout:   2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "192.0.2.1:8080")
	if err != nil {
		t.Fatalf("Socks5Dialer DialContext failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != "ping" {
		t.Fatalf("expected ping, got %s", string(resp))
	}
}
