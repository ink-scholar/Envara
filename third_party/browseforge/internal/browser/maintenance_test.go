package browser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"browseforge/internal/profile"
)

func TestMaintenanceBlocksLaunchUntilExactTokenRelease(t *testing.T) {
	m := newConcurrentManager(t)
	var launches atomic.Int32
	m.launchProfileOverride = func(p *profile.Profile) (*Session, error) {
		launches.Add(1)
		s, _ := newConcurrentSession(p.ID)
		return s, nil
	}
	token, err := m.AcquireProfileMaintenance(context.Background(), []string{"B", "A"})
	if err != nil || len(token) != 64 {
		t.Fatalf("acquire: %v", err)
	}
	for _, id := range []string{"A", "B"} {
		if _, err := m.LaunchSession(&profile.Profile{ID: id}); ErrorCode(err) != "CACHE_MAINTENANCE_BUSY" {
			t.Fatalf("launch during maintenance: %v", err)
		}
	}
	if launches.Load() != 0 || len(m.ListSessions()) != 0 {
		t.Fatal("maintenance reached the browser launcher")
	}
	if err := m.ReleaseProfileMaintenance(strings.Repeat("0", 64)); ErrorCode(err) != "CACHE_MAINTENANCE_TOKEN_INVALID" {
		t.Fatalf("foreign release: %v", err)
	}
	if _, err := m.LaunchSession(&profile.Profile{ID: "C"}); err != nil {
		t.Fatalf("unrelated launch blocked: %v", err)
	}
	if err := m.ReleaseProfileMaintenance(token); err != nil {
		t.Fatal(err)
	}
	second, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseProfileMaintenance(token); ErrorCode(err) != "CACHE_MAINTENANCE_TOKEN_INVALID" || !m.profileMaintenanceActive("A") {
		t.Fatal("an old token changed a newer lease")
	}
	if err := m.ReleaseProfileMaintenance(second); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LaunchSession(&profile.Profile{ID: "A"}); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceAdmissionWaitsForInFlightLaunchAndRefusesItsLiveSession(t *testing.T) {
	m := newConcurrentManager(t)
	started, finish := make(chan struct{}), make(chan struct{})
	unblock := releaseConcurrentBarrier(t, finish)
	m.launchProfileOverride = func(p *profile.Profile) (*Session, error) {
		close(started)
		<-finish
		s, _ := newConcurrentSession(p.ID)
		return s, nil
	}
	launched, acquired := make(chan error, 1), make(chan error, 1)
	go func() { _, err := m.LaunchSession(&profile.Profile{ID: "A"}); launched <- err }()
	requireConcurrentResult(t, started, "launch did not start")
	go func() { _, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"}); acquired <- err }()
	awaitConcurrentCondition(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.activeOperations == 2
	}, "maintenance did not join the profile reservation")
	select {
	case err := <-acquired:
		t.Fatalf("maintenance admitted before launch completed: %v", err)
	default:
	}
	unblock()
	if err := requireConcurrentResult(t, launched, "launch remained blocked"); err != nil {
		t.Fatal(err)
	}
	if err := requireConcurrentResult(t, acquired, "maintenance remained blocked"); ErrorCode(err) != "CACHE_MAINTENANCE_BUSY" {
		t.Fatalf("live browser was admitted: %v", err)
	}
	if len(m.ListSessions()) != 1 || m.profileMaintenanceActive("A") {
		t.Fatal("failed admission changed the live browser")
	}
}

func TestMaintenanceBatchIsAtomicAndConcurrentBatchesDoNotDeadlock(t *testing.T) {
	m := newConcurrentManager(t)
	existing, _ := newConcurrentSession("B")
	m.sessions[existing.ID] = existing
	if _, err := m.AcquireProfileMaintenance(context.Background(), []string{"A", "B"}); ErrorCode(err) != "CACHE_MAINTENANCE_BUSY" {
		t.Fatal(err)
	}
	if m.profileMaintenanceActive("A") || m.profileMaintenanceActive("B") {
		t.Fatal("partial batch admission survived refusal")
	}
	if err := m.CloseSession(existing.ID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		token string
		err   error
	}
	results := make(chan result, 2)
	for _, ids := range [][]string{{"A", "B"}, {"B", "A"}} {
		go func(ids []string) {
			token, err := m.AcquireProfileMaintenance(context.Background(), ids)
			results <- result{token, err}
		}(ids)
	}
	first := requireConcurrentResult(t, results, "first batch deadlocked")
	second := requireConcurrentResult(t, results, "second batch deadlocked")
	if first.err != nil {
		first, second = second, first
	}
	if first.err != nil || ErrorCode(second.err) != "CACHE_MAINTENANCE_BUSY" {
		t.Fatalf("overlapping admissions: %v / %v", first.err, second.err)
	}
	if err := m.ReleaseProfileMaintenance(first.token); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceCancellationAndShutdownNeverStrandOperationLocks(t *testing.T) {
	m := newConcurrentManager(t)
	release, err := m.reserveProfile("A")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := m.AcquireProfileMaintenance(ctx, []string{"A"}); result <- err }()
	awaitConcurrentCondition(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.activeOperations == 2
	}, "maintenance did not wait for profile")
	cancel()
	release()
	if err := requireConcurrentResult(t, result, "cancelled admission remained blocked"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if m.profileMaintenanceActive("A") {
		t.Fatal("cancelled admission installed a lease")
	}
	token, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	requireConcurrentResult(t, closed, "an idle maintenance lease blocked shutdown cleanup")
	if err := m.ReleaseProfileMaintenance(token); err != nil {
		t.Fatalf("shutdown blocked lease cleanup: %v", err)
	}
	if _, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"}); !errors.Is(err, ErrManagerClosing) {
		t.Fatalf("closed manager admitted maintenance: %v", err)
	}
}

func TestMaintenanceStoreGuardProtectsCreateUpdateDeleteAndStorageIdentity(t *testing.T) {
	m := newConcurrentManager(t)
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetMutationGuard(m.ReserveProfileMutation)
	p := &profile.Profile{ID: "A", Name: "fixture", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(p.ProfileDir, "browser-data", "keep.txt")
	if err := os.WriteFile(file, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := store.Update("A", map[string]any{"name": "changed"})
	for _, err := range []error{updateErr, store.Delete("A"), store.Create(&profile.Profile{ID: "A", Name: "replace", RuntimeID: "cloakbrowser"})} {
		if ErrorCode(err) != "CACHE_MAINTENANCE_BUSY" {
			t.Fatalf("store mutation bypassed maintenance: %v", err)
		}
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "owned fixture" || p.Name != "fixture" {
		t.Fatal("refused mutation changed profile storage")
	}
	if err := store.CreatePreservingIdentity(&profile.Profile{ID: "B", RuntimeID: "cloakbrowser"}); err != nil {
		t.Fatalf("unrelated import was blocked: %v", err)
	}
	if _, err := store.Update("B", map[string]any{"profile_dir": p.ProfileDir}); err == nil {
		t.Fatal("another profile redirected writes into maintenance storage")
	}
	if err := m.ReleaseProfileMaintenance(token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update("A", map[string]any{"id": "B"}); err == nil {
		t.Fatal("profile lock identity could be replaced")
	}
	if _, err := store.Update("A", map[string]any{"name": "after"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("A"); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceInvalidRequestsNeverAcquireProfiles(t *testing.T) {
	m := newConcurrentManager(t)
	for _, ids := range [][]string{nil, {}, {"A", "A"}, {"../A"}, {strings.Repeat("A", 129)}, make([]string, 501)} {
		if _, err := m.AcquireProfileMaintenance(context.Background(), ids); ErrorCode(err) != "CACHE_MAINTENANCE_INVALID" {
			t.Fatalf("invalid request admitted: %v", err)
		}
	}
	if len(m.maintenanceProfiles) != 0 || m.activeOperations != 0 {
		t.Fatal("invalid request retained a reservation")
	}
}
