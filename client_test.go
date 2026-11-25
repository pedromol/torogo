package torogo

import (
	"context"
	"testing"
	"time"
)

func TestClientOptions(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, WithLazyBootstrap(), WithCircuitTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("unexpected error creating lazy client: %v", err)
	}
	defer c.Close()

	if c.opts.circuitTimeout != 10*time.Second {
		t.Errorf("expected 10s circuit timeout, got %v", c.opts.circuitTimeout)
	}

	httpClient := c.HTTPClient()
	if httpClient == nil {
		t.Fatal("HTTPClient returned nil")
	}
	if httpClient.Transport == nil {
		t.Fatal("HTTPClient Transport is nil")
	}

	transport := c.Transport()
	if transport == nil {
		t.Fatal("Transport returned nil")
	}
	if transport.DialContext == nil {
		t.Fatal("Transport DialContext is nil")
	}
}

func TestClientDialErrors(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, WithLazyBootstrap())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer c.Close()

	// Unsupported network
	if _, err := c.DialContext(ctx, "udp", "example.com:53"); err == nil {
		t.Error("expected error for unsupported network udp")
	}

	// Invalid address format
	if _, err := c.DialContext(ctx, "tcp", "example.com"); err == nil {
		t.Error("expected error for address missing port")
	}

	// Invalid port
	if _, err := c.DialContext(ctx, "tcp", "example.com:notaport"); err == nil {
		t.Error("expected error for invalid port")
	}

	// Out of range port
	if _, err := c.DialContext(ctx, "tcp", "example.com:99999"); err == nil {
		t.Error("expected error for port > 65535")
	}
}

func TestClientClosed(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, WithLazyBootstrap())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	_, err = c.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error dialing closed client, got nil")
	}

	_, err = c.Dial("tcp", "example.com:80")
	if err == nil {
		t.Error("expected error dialing closed client via Dial, got nil")
	}
}
