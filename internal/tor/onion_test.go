package tor

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestOnionV3EncodingAndDecoding(t *testing.T) {
	var pubkey [32]byte
	if _, err := rand.Read(pubkey[:]); err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	addrStr := EncodeOnionV3(pubkey)
	if len(addrStr) != 56+6 { // 56 base32 chars + ".onion"
		t.Fatalf("expected length 62, got %d (%s)", len(addrStr), addrStr)
	}

	parsed, err := ParseOnionV3(addrStr)
	if err != nil {
		t.Fatalf("ParseOnionV3 failed: %v", err)
	}

	if parsed.PublicKey != pubkey {
		t.Fatalf("parsed pubkey does not match original")
	}
	if parsed.Version != OnionV3Version {
		t.Fatalf("expected version %d, got %d", OnionV3Version, parsed.Version)
	}
	if parsed.Address != addrStr {
		t.Fatalf("expected address %s, got %s", addrStr, parsed.Address)
	}
}

func TestKnownOnionV3Address(t *testing.T) {
	// DuckDuckGo official v3 onion service
	ddg := "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	parsed, err := ParseOnionV3(ddg)
	if err != nil {
		t.Fatalf("failed to parse DuckDuckGo v3 onion address: %v", err)
	}
	if parsed.Version != 3 {
		t.Fatalf("expected version 3, got %d", parsed.Version)
	}

	// Verify re-encoding produces the same string
	reEncoded := EncodeOnionV3(parsed.PublicKey)
	if reEncoded != ddg {
		t.Fatalf("re-encoded mismatch: expected %s, got %s", ddg, reEncoded)
	}
}

func TestInvalidOnionV3Addresses(t *testing.T) {
	// Too short
	if _, err := ParseOnionV3("tooshort.onion"); err == nil {
		t.Fatalf("expected error for short onion address")
	}

	// Corrupted checksum
	badChecksum := "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczbb.onion"
	if _, err := ParseOnionV3(badChecksum); err == nil {
		t.Fatalf("expected error for corrupted checksum")
	}
}

func TestTimePeriod(t *testing.T) {
	// A fixed point in time
	refTime := time.Date(2026, 1, 1, 18, 0, 0, 0, time.UTC)
	tp := CalculateTimePeriod(refTime)
	if tp == 0 {
		t.Fatalf("expected non-zero time period")
	}

	// 24 hours later should be tp + 1
	nextDay := refTime.Add(24 * time.Hour)
	tpNext := CalculateTimePeriod(nextDay)
	if tpNext != tp+1 {
		t.Fatalf("expected tpNext to be %d, got %d", tp+1, tpNext)
	}
}

func TestRendezvousCookie(t *testing.T) {
	c1, err := NewRendezvousCookie()
	if err != nil {
		t.Fatalf("NewRendezvousCookie failed: %v", err)
	}
	c2, err := NewRendezvousCookie()
	if err != nil {
		t.Fatalf("NewRendezvousCookie failed: %v", err)
	}
	if c1 == c2 {
		t.Fatalf("cookies should be unique")
	}
}
