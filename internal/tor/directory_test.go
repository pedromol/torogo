package tor

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestAuthorityList(t *testing.T) {
	if len(Authorities) == 0 {
		t.Fatal("Authorities list is empty")
	}

	for _, auth := range Authorities {
		t.Run(auth.Nickname, func(t *testing.T) {
			if auth.Fingerprint == "" {
				t.Error("fingerprint empty")
			}
			if auth.IP == "" {
				t.Error("IP empty")
			}
			if auth.DirPort == 0 && auth.ORPort == 0 {
				t.Error("both ports zero")
			}

			if len(auth.Fingerprint) != 40 {
				t.Errorf("fingerprint length %d != 40", len(auth.Fingerprint))
			}
			if _, err := hex.DecodeString(auth.Fingerprint); err != nil {
				t.Errorf("fingerprint not valid hex: %v", err)
			}
		})
	}
}

func TestAuthorityLookup(t *testing.T) {
	t.Run("finds moria1 by fingerprint", func(t *testing.T) {
		auth := authorityByFingerprint("F533C81CEF0BC0267857C99B2F471ADF249FA232")
		if auth == nil {
			t.Error("moria1 not found")
		}
		if auth.Nickname != "moria1" {
			t.Errorf("expected moria1, got %s", auth.Nickname)
		}
	})

	t.Run("case insensitive lookup", func(t *testing.T) {
		auth := authorityByFingerprint("f533c81cef0bc0267857c99b2f471adf249fa232")
		if auth == nil {
			t.Error("case insensitive lookup failed")
		}
	})

	t.Run("returns nil for unknown", func(t *testing.T) {
		auth := authorityByFingerprint("0000000000000000000000000000000000000000")
		if auth != nil {
			t.Error("expected nil for unknown fingerprint")
		}
	})
}

func TestBandwidthWeightedSelection(t *testing.T) {
	bwWeights := map[string]int64{
		"Wgg": 10000,
		"Wgd": 5000,
		"Wmg": 5000,
		"Wmm": 10000,
		"Wee": 10000,
		"Wed": 10000,
	}

	rs1 := &RouterStatus{
		Nickname:  "SmallGuard",
		Bandwidth: 100,
		Flags:     map[string]bool{"Guard": true},
	}
	rs2 := &RouterStatus{
		Nickname:  "BigGuard",
		Bandwidth: 10000,
		Flags:     map[string]bool{"Guard": true},
	}

	w1 := routerWeightForPosition(rs1, PosGuard, bwWeights)
	w2 := routerWeightForPosition(rs2, PosGuard, bwWeights)

	if w2 <= w1 {
		t.Fatalf("expected BigGuard weight (%d) > SmallGuard weight (%d)", w2, w1)
	}

	shuffled := weightedShuffleRouters([]*RouterStatus{rs1, rs2}, PosGuard, bwWeights)
	if len(shuffled) != 2 {
		t.Fatalf("expected 2 routers, got %d", len(shuffled))
	}
}

func TestRelayFamilyExclusion(t *testing.T) {
	var id1, id2 [20]byte
	copy(id1[:], []byte("11111111111111111111"))
	copy(id2[:], []byte("22222222222222222222"))

	rs1 := &RouterStatus{Nickname: "Node1", Identity: id1}
	rs2 := &RouterStatus{Nickname: "Node2", Identity: id2}

	md1 := &Microdesc{Family: []string{"NODE2"}}
	md2 := &Microdesc{}

	if !sameFamily(rs1, md1, rs2, md2) {
		t.Fatalf("expected rs1 and rs2 to be recognized as same family")
	}

	md1Unrelated := &Microdesc{Family: []string{"OTHERNODE"}}
	if sameFamily(rs1, md1Unrelated, rs2, md2) {
		t.Fatalf("expected unrelated nodes not to be same family")
	}
}

func TestShuffledAuthorities(t *testing.T) {
	shuffled := shuffledAuthorities()
	if len(shuffled) != len(Authorities) {
		t.Errorf("expected %d authorities, got %d", len(Authorities), len(shuffled))
	}
	found := map[string]bool{}
	for _, a := range shuffled {
		found[a.Fingerprint] = true
	}
	if len(found) != len(Authorities) {
		t.Errorf("duplicate authorities found in shuffled slice")
	}
}

func TestSameRelay(t *testing.T) {
	r1 := &RouterStatus{Identity: [20]byte{1, 2, 3}}
	r2 := &RouterStatus{Identity: [20]byte{1, 2, 3}}
	r3 := &RouterStatus{Identity: [20]byte{4, 5, 6}}

	if !sameRelay(r1, r2) {
		t.Error("expected sameRelay(r1, r2) = true")
	}
	if sameRelay(r1, r3) {
		t.Error("expected sameRelay(r1, r3) = false")
	}
	if !sameRelay(r1, r1) {
		t.Error("expected sameRelay(r1, r1) = true")
	}
}

func TestSameSlash16(t *testing.T) {
	tests := []struct {
		ip1  string
		ip2  string
		want bool
	}{
		{"192.168.1.1", "192.168.2.2", true},
		{"10.0.0.1", "10.0.100.200", true},
		{"10.1.0.1", "10.2.0.1", false},
		{"192.168.1.1", "10.168.1.1", false},
		{"::1", "::1", true},
		{"::1", "::2", false},
	}
	for _, tc := range tests {
		ip1 := net.ParseIP(tc.ip1)
		ip2 := net.ParseIP(tc.ip2)
		got := sameSlash16(ip1, ip2)
		if got != tc.want {
			t.Errorf("sameSlash16(%s, %s) = %v, want %v", tc.ip1, tc.ip2, got, tc.want)
		}
	}
}

func TestShuffleRouters(t *testing.T) {
	var routers []*RouterStatus
	for i := 0; i < 20; i++ {
		routers = append(routers, &RouterStatus{Nickname: string(rune('A' + i))})
	}
	orig := make([]*RouterStatus, len(routers))
	copy(orig, routers)

	shuffleRouters(routers)
	if len(routers) != len(orig) {
		t.Fatalf("length changed during shuffle")
	}

	// Verify all elements are still present
	present := map[string]bool{}
	for _, r := range routers {
		present[r.Nickname] = true
	}
	if len(present) != len(orig) {
		t.Errorf("lost elements during shuffle")
	}
}

func TestRandomInt(t *testing.T) {
	if randomInt(0) != 0 {
		t.Error("randomInt(0) should be 0")
	}
	if randomInt(1) != 0 {
		t.Error("randomInt(1) should be 0")
	}
	for i := 0; i < 50; i++ {
		val := randomInt(10)
		if val < 0 || val >= 10 {
			t.Errorf("randomInt(10) out of range: %d", val)
		}
	}
}

func TestConsensusSignatureVerification(t *testing.T) {
	t.Run("finds directory-signature boundary", func(t *testing.T) {
		doc := "network-status-version 3\nvote-status consensus\nvalid-after 2026-01-01 00:00:00\nfresh-until 2026-01-01 01:00:00\nvalid-until 2026-01-01 02:00:00\ndirectory-signature "
		idx := findDirectorySignatureBoundary([]byte(doc))
		if idx < 0 {
			t.Error("failed to find directory-signature boundary")
		}
		if !strings.HasPrefix(doc[idx:], "directory-signature ") {
			t.Errorf("boundary at wrong position: %s", doc[idx:])
		}
	})

	t.Run("handles missing boundary", func(t *testing.T) {
		doc := "no signature here"
		idx := findDirectorySignatureBoundary([]byte(doc))
		if idx >= 0 {
			t.Error("expected -1 for missing boundary")
		}
	})
}

// Helper function to find the directory-signature boundary for testing
func findDirectorySignatureBoundary(doc []byte) int {
	for i := 0; i <= len(doc)-20; i++ {
		if string(doc[i:i+20]) == "directory-signature " {
			return i
		}
	}
	return -1
}
