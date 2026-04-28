// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakePickerManager implements Manager for picker tests. It returns the
// configured installID without going through GitHub's installations API,
// which lets the picker tests focus on tier selection logic only.
type fakePickerManager struct {
	installID int64
	installed bool
}

func (f *fakePickerManager) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	if !f.installed {
		return nil, 0, status.Error(codes.NotFound, "not installed")
	}
	return nil, f.installID, nil
}

func newFakePickerManagers(installIDs ...int64) []Manager {
	out := make([]Manager, len(installIDs))
	for i, id := range installIDs {
		out[i] = &fakePickerManager{installID: id, installed: true}
	}
	return out
}

func TestPickByQuotaNilConfig(t *testing.T) {
	managers := newFakePickerManagers(1, 2, 3)
	if _, _, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", nil); ok {
		t.Errorf("nil config: ok = true, want false")
	}
}

func TestPickByQuotaNilStore(t *testing.T) {
	managers := newFakePickerManagers(1, 2, 3)
	cfg := &QuotaConfig{Store: nil, SoftFloor: 15000, HardFloor: 1500}
	if _, _, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg); ok {
		t.Errorf("nil store: ok = true, want false")
	}
}

func TestPickByQuotaColdStartFallsThrough(t *testing.T) {
	// All installs unknown → must report ok=false so the caller falls back
	// to its cold-start strategy (FNV / atomic counter).
	managers := newFakePickerManagers(1, 2, 3)
	store := NewQuotaStore(time.Minute)
	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}

	if _, _, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg); ok {
		t.Errorf("cold start: ok = true, want false (no install has data)")
	}
}

func TestPickByQuotaSomeKnownPicksKnownComfortable(t *testing.T) {
	// One install has known headroom comfortably above the soft floor; the
	// other two are unknown (treated as soft+1). The known install must win
	// because its remaining is greater.
	managers := newFakePickerManagers(1, 2, 3)
	store := NewQuotaStore(time.Minute)
	store.Update(2, 49000, 50000) // install 2 known, well above SoftFloor

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false, want true (one install has data)")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (49000 > soft+1 = 15001)", id)
	}
}

func TestPickByQuotaArgmaxRemainingPrefers50k(t *testing.T) {
	// 50k install at full vs 15k install at full — argmax(remaining) picks
	// the 50k. This is the core "heavy caller lands on the install with
	// most absolute room" property.
	managers := newFakePickerManagers(1, 2)
	store := NewQuotaStore(time.Minute)
	store.Update(1, 15000, 15000) // 15k tier full
	store.Update(2, 50000, 50000) // 50k tier full

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (50k beats 15k by absolute remaining)", id)
	}
}

func TestPickByQuotaPrefersComfortableOverTight(t *testing.T) {
	// install 1: tight (3000 remaining)
	// install 2: comfortable (16000 remaining)
	// Picker must choose 2 even though 1 also has data.
	managers := newFakePickerManagers(1, 2)
	store := NewQuotaStore(time.Minute)
	store.Update(1, 3000, 15000)
	store.Update(2, 16000, 50000)

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (comfortable tier wins over tight)", id)
	}
}

func TestPickByQuotaAllTightPicksMaxRemaining(t *testing.T) {
	// All installs in tight tier — argmax(remaining) picks the highest.
	managers := newFakePickerManagers(1, 2, 3)
	store := NewQuotaStore(time.Minute)
	store.Update(1, 3000, 15000)
	store.Update(2, 8000, 50000) // tight (below soft floor of 15k) but most slack
	store.Update(3, 5000, 15000)

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (max remaining 8000 in tight tier)", id)
	}
}

func TestPickByQuotaAllLastResortStillReturns(t *testing.T) {
	// All installs below hard floor — must still pick the best one rather
	// than refusing service.
	managers := newFakePickerManagers(1, 2, 3)
	store := NewQuotaStore(time.Minute)
	store.Update(1, 100, 15000)
	store.Update(2, 800, 15000) // most remaining (still <hardFloor)
	store.Update(3, 50, 50000)

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (max remaining among last-resort)", id)
	}
}

func TestPickByQuotaSkipsNotInstalled(t *testing.T) {
	// Two installed managers and one not-installed (returns NotFound).
	managers := []Manager{
		&fakePickerManager{installID: 1, installed: true},
		&fakePickerManager{installID: 2, installed: false},
		&fakePickerManager{installID: 3, installed: true},
	}
	store := NewQuotaStore(time.Minute)
	store.Update(1, 20000, 50000)
	store.Update(3, 30000, 50000)
	// install 2 has data too, but the manager returns NotFound for the owner
	store.Update(2, 99000, 50000)

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 3 {
		t.Errorf("picked install %d, want 3 (max remaining among installed)", id)
	}
}

func TestPickByQuotaTieBreakingDeterministic(t *testing.T) {
	// Two 50k installs both fresh at 50000 remaining (hour reset). The
	// picker must return a deterministic answer, and over many calls (with
	// the chosen install's remaining decremented), traffic must alternate
	// between them — neither install should be starved.
	managers := newFakePickerManagers(1, 2)
	store := NewQuotaStore(time.Minute)

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}

	chosen := map[int64]int{}
	rem := map[int64]int{1: 50000, 2: 50000}
	for range 100 {
		store.Update(1, rem[1], 50000)
		store.Update(2, rem[2], 50000)
		_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
		if !ok {
			t.Fatalf("ok = false")
		}
		chosen[id]++
		rem[id] -= 30
	}

	// Both installs should have been picked roughly equally.
	if chosen[1] < 40 || chosen[2] < 40 {
		t.Errorf("alternation broken: install 1 picked %d times, install 2 picked %d times (want ~50 each)", chosen[1], chosen[2])
	}
}

func TestPickByQuota50kBelowSoftFloorTakesBackseat(t *testing.T) {
	// 50k install drained to 14000 (below the 15k soft floor) → tight tier.
	// 15k install fresh at 15000 (== soft floor) → comfortable tier.
	// Picker prefers the comfortable 15k over the tight 50k, demonstrating
	// the "stop preferring 50k when it drops below 15k remaining" rule.
	managers := newFakePickerManagers(1, 2)
	store := NewQuotaStore(time.Minute)
	store.Update(1, 14000, 50000) // tight: was preferred, now dipped below soft
	store.Update(2, 15000, 15000) // comfortable: at boundary

	cfg := &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500}
	_, id, ok := pickByQuota(context.Background(), managers, "owner", "owner/repo", "id", cfg)
	if !ok {
		t.Fatalf("ok = false")
	}
	if id != 2 {
		t.Errorf("picked install %d, want 2 (comfortable beats tight even when tight has more cap)", id)
	}
}
