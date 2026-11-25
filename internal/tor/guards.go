package tor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxPrimaryGuards = 3
	MaxGuardFailures        = 3
	GuardLifetime           = 60 * 24 * time.Hour // 60 days
)

// PersistedGuard stores information about a persistent guard node.
type PersistedGuard struct {
	Fingerprint string    `json:"fingerprint"` // Hex encoded 20-byte identity digest
	Nickname    string    `json:"nickname"`
	IP          string    `json:"ip"`
	ORPort      int       `json:"or_port"`
	AddedAt     time.Time `json:"added_at"`
	LastSeen    time.Time `json:"last_seen"`
	FailCount   int       `json:"fail_count"`
}

// GuardManager manages persistent guard nodes on disk.
type GuardManager struct {
	mu       sync.Mutex
	filePath string
	disabled bool
	guards   []PersistedGuard
}

// NewGuardManager initializes a GuardManager.
// If filePath is empty, it uses ~/.torogo/guards.json.
// If path is ":memory:" or disabled, guards are not persisted to disk.
func NewGuardManager(filePath string) (*GuardManager, error) {
	if filePath == ":memory:" {
		return &GuardManager{disabled: true}, nil
	}
	if filePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return &GuardManager{disabled: true}, nil
		}
		filePath = filepath.Join(home, ".torogo", "guards.json")
	}

	gm := &GuardManager{
		filePath: filePath,
	}
	_ = gm.Load()
	return gm, nil
}

// Load loads guards from the state file.
func (gm *GuardManager) Load() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.disabled || gm.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(gm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var loaded []PersistedGuard
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	now := time.Now().UTC()
	var valid []PersistedGuard
	for _, g := range loaded {
		if now.Sub(g.AddedAt) < GuardLifetime {
			valid = append(valid, g)
		}
	}
	gm.guards = valid
	return nil
}

// Save writes guards to the state file.
func (gm *GuardManager) Save() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.saveLocked()
}

func (gm *GuardManager) saveLocked() error {
	if gm.disabled || gm.filePath == "" {
		return nil
	}
	dir := filepath.Dir(gm.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(gm.guards, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := gm.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, gm.filePath)
}

// Guards returns a copy of current persisted guards.
func (gm *GuardManager) Guards() []PersistedGuard {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	out := make([]PersistedGuard, len(gm.guards))
	copy(out, gm.guards)
	return out
}

// SelectGuard selects a guard node using persisted guards first, or picks a new one from consensus.
func (gm *GuardManager) SelectGuard(ctx context.Context, cons *Consensus) (*RouterStatus, *Microdesc, error) {
	if cons == nil || len(cons.Routers) == 0 {
		return nil, nil, fmt.Errorf("tor: consensus is empty")
	}

	gm.mu.Lock()
	persisted := make([]PersistedGuard, len(gm.guards))
	copy(persisted, gm.guards)
	gm.mu.Unlock()

	// 1. Check existing persisted guards
	for i, pg := range persisted {
		if pg.FailCount >= MaxGuardFailures {
			continue
		}
		rs := findRouterByHexFingerprint(cons, pg.Fingerprint)
		if rs != nil && isEligibleGuard(rs) {
			md, err := FetchMicrodesc(ctx, cons, rs)
			if err == nil {
				gm.RecordSuccess(pg.Fingerprint)
				return rs, md, nil
			}
			gm.RecordFailure(pg.Fingerprint)
		} else if rs == nil {
			// Router not in current consensus
			gm.RecordFailure(pg.Fingerprint)
		}
		_ = i
	}

	// 2. Pick a new guard from consensus
	var candidates []*RouterStatus
	for _, rs := range cons.Routers {
		if isEligibleGuard(rs) {
			candidates = append(candidates, rs)
		}
	}
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("tor: no eligible guards in consensus")
	}
	shuffleRouters(candidates)

	var lastErr error
	for _, rs := range candidates {
		md, err := FetchMicrodesc(ctx, cons, rs)
		if err != nil {
			lastErr = err
			continue
		}

		// Persist newly selected guard
		fp := hex.EncodeToString(rs.Identity[:])
		now := time.Now().UTC()
		newGuard := PersistedGuard{
			Fingerprint: fp,
			Nickname:    rs.Nickname,
			IP:          rs.IP.String(),
			ORPort:      int(rs.ORPort),
			AddedAt:     now,
			LastSeen:    now,
			FailCount:   0,
		}

		gm.mu.Lock()
		// If capacity reached, remove the one with highest failures or oldest
		if len(gm.guards) >= DefaultMaxPrimaryGuards {
			worstIdx := 0
			for idx := 1; idx < len(gm.guards); idx++ {
				if gm.guards[idx].FailCount > gm.guards[worstIdx].FailCount {
					worstIdx = idx
				}
			}
			gm.guards = append(gm.guards[:worstIdx], gm.guards[worstIdx+1:]...)
		}
		gm.guards = append(gm.guards, newGuard)
		_ = gm.saveLocked()
		gm.mu.Unlock()

		return rs, md, nil
	}

	return nil, nil, fmt.Errorf("tor: failed to fetch microdescriptor for new guard: %w", lastErr)
}

func (gm *GuardManager) RecordSuccess(fingerprint string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	for i := range gm.guards {
		if strings.EqualFold(gm.guards[i].Fingerprint, fingerprint) {
			gm.guards[i].FailCount = 0
			gm.guards[i].LastSeen = time.Now().UTC()
			_ = gm.saveLocked()
			return
		}
	}
}

func (gm *GuardManager) RecordFailure(fingerprint string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	for i := range gm.guards {
		if strings.EqualFold(gm.guards[i].Fingerprint, fingerprint) {
			gm.guards[i].FailCount++
			_ = gm.saveLocked()
			return
		}
	}
}

func isEligibleGuard(rs *RouterStatus) bool {
	return rs != nil &&
		rs.HasFlag("Guard") &&
		rs.HasFlag("Running") &&
		rs.HasFlag("Valid") &&
		!rs.HasFlag("NoEdConsensus")
}

func findRouterByHexFingerprint(cons *Consensus, hexFP string) *RouterStatus {
	raw, err := hex.DecodeString(hexFP)
	if err != nil || len(raw) != 20 {
		return nil
	}
	var id [20]byte
	copy(id[:], raw)
	for _, rs := range cons.Routers {
		if rs.Identity == id {
			return rs
		}
	}
	return nil
}
