package tor

import (
	"net"
	"testing"
)

func TestParseResolvedPayload(t *testing.T) {
	// Payload with IPv4: TYPE 0x04, LEN 4, IP 192.0.2.1, TTL 300 (4 bytes)
	data := []byte{
		0x04, 0x04, 192, 0, 2, 1, 0, 0, 1, 44,
	}

	ips, err := parseResolvedPayload(data)
	if err != nil {
		t.Fatalf("parseResolvedPayload error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("expected 192.0.2.1, got %v", ips[0])
	}

	// Payload with error 0xF1 (Host not found)
	errData := []byte{0xF1, 0x01, 0x00}
	if _, err := parseResolvedPayload(errData); err == nil {
		t.Fatalf("expected error for 0xF1 response")
	}
}
