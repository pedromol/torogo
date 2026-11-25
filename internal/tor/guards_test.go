package tor

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestGuardManagerSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "guards.json")

	gm, err := NewGuardManager(filePath)
	if err != nil {
		t.Fatalf("NewGuardManager failed: %v", err)
	}

	gm.guards = []PersistedGuard{
		{
			Fingerprint: "0123456789abcdef0123456789abcdef01234567",
			Nickname:    "GuardOne",
			IP:          "192.0.2.1",
			ORPort:      9001,
			AddedAt:     time.Now().UTC(),
			LastSeen:    time.Now().UTC(),
			FailCount:   0,
		},
	}
	if err := gm.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	gm2, err := NewGuardManager(filePath)
	if err != nil {
		t.Fatalf("NewGuardManager reload failed: %v", err)
	}
	if len(gm2.Guards()) != 1 {
		t.Fatalf("expected 1 guard, got %d", len(gm2.Guards()))
	}
	if gm2.Guards()[0].Nickname != "GuardOne" {
		t.Fatalf("expected GuardOne, got %s", gm2.Guards()[0].Nickname)
	}

	// Test RecordFailure and RecordSuccess
	gm2.RecordFailure("0123456789abcdef0123456789abcdef01234567")
	if gm2.Guards()[0].FailCount != 1 {
		t.Fatalf("expected FailCount 1, got %d", gm2.Guards()[0].FailCount)
	}

	gm2.RecordSuccess("0123456789abcdef0123456789abcdef01234567")
	if gm2.Guards()[0].FailCount != 0 {
		t.Fatalf("expected FailCount 0, got %d", gm2.Guards()[0].FailCount)
	}
}

func TestGuardSelectionWithConsensus(t *testing.T) {
	var dummyID [20]byte
	copy(dummyID[:], []byte("01234567890123456789"))

	cons := &Consensus{
		Routers: []*RouterStatus{
			{
				Nickname: "TestGuard",
				Identity: dummyID,
				IP:       net.ParseIP("192.0.2.1"),
				ORPort:   9001,
				Flags:    map[string]bool{"Guard": true, "Running": true, "Valid": true},
			},
		},
	}

	rs := findRouterByHexFingerprint(cons, "3031323334353637383930313233343536373839")
	if rs == nil || rs.Nickname != "TestGuard" {
		t.Fatalf("expected to find TestGuard router by hex fingerprint")
	}
	if !isEligibleGuard(rs) {
		t.Fatalf("expected router to be eligible guard")
	}
}
