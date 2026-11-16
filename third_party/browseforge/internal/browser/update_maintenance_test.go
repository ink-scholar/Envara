package browser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/profile"
	"github.com/playwright-community/playwright-go"
)

func TestUpdateMaintenanceBlocksAllProfilesAndRequiresItsExactRelease(t *testing.T) {
	m := newConcurrentManager(t)
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetMutationGuard(m.ReserveProfileMutation)
	p := &profile.Profile{ID: "existing", Name: "keep", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(p.ProfileDir, "browser-data", "keep")
	if err := os.WriteFile(marker, []byte("fixture data"), 0600); err != nil {
		t.Fatal(err)
	}
	m.launchProfileOverride = func(*profile.Profile) (*Session, error) { t.Fatal("update reached launcher"); return nil, nil }
	token, err := m.AcquireUpdateMaintenance(context.Background())
	if err != nil || len(token) != 64 {
		t.Fatalf("acquire: %v", err)
	}
	_, launchErr := m.LaunchSession(&profile.Profile{ID: "new"})
	_, updateErr := store.Update(p.ID, map[string]any{"name": "changed"})
	_, duplicateErr := store.Duplicate(p.ID)
	_, pageErr := m.SessionPage("sess_existing")
	_, profileLeaseErr := m.AcquireProfileMaintenance(context.Background(), []string{p.ID})
	_, operationErr := m.ReserveUpdateOperation()
	for _, err := range []error{launchErr, updateErr, duplicateErr, pageErr, profileLeaseErr, operationErr,
		store.Create(&profile.Profile{ID: "new", RuntimeID: "cloakbrowser"}), store.Delete(p.ID),
		m.SetSessionPage("sess_existing", &desktopTestPage{})} {
		if ErrorCode(err) != "UPDATE_MAINTENANCE_BUSY" {
			t.Fatalf("operation bypassed update lease: %v", err)
		}
	}
	if len(m.ListSessions()) != 0 || len(store.List("", "")) != 1 || p.Name != "keep" {
		t.Fatal("refused operation changed state")
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "fixture data" {
		t.Fatal("refused operation changed files")
	}
	for _, err := range []error{m.ReleaseProfileMaintenance(token), m.ReleaseUpdateMaintenance(strings.Repeat("0", 64)), m.ReleaseUpdateMaintenance(token + "0")} {
		if ErrorCode(err) != "CACHE_MAINTENANCE_TOKEN_INVALID" {
			t.Fatal(err)
		}
	}
	if _, err := m.AcquireUpdateMaintenance(context.Background()); ErrorCode(err) != "UPDATE_MAINTENANCE_BUSY" {
		t.Fatal(err)
	}
	if err := m.ReleaseUpdateMaintenance(token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(p.ID, map[string]any{"name": "after"}); err != nil {
		t.Fatal(err)
	}
	next, err := m.AcquireUpdateMaintenance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseUpdateMaintenance(token); ErrorCode(err) != "CACHE_MAINTENANCE_TOKEN_INVALID" {
		t.Fatal("old token released a new lease")
	}
	m.Close()
	if m.updateMaintenanceToken != next {
		t.Fatal("shutdown silently cleared update lease")
	}
	if err := m.ReleaseUpdateMaintenance(next); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireUpdateMaintenance(context.Background()); !errors.Is(err, ErrManagerClosing) {
		t.Fatal(err)
	}
}

type updateBlockedCloseContext struct {
	desktopTestContext
	started chan struct{}
	unblock chan struct{}
}

func (c *updateBlockedCloseContext) Close(...playwright.BrowserContextCloseOptions) error {
	close(c.started)
	<-c.unblock
	return c.desktopTestContext.Close()
}

func TestUpdateAdmissionImmediatelyRefusesZeroSessionWorkInFlight(t *testing.T) {
	t.Run("launch", func(t *testing.T) {
		m := newConcurrentManager(t)
		started, proceed := make(chan struct{}), make(chan struct{})
		unblock := releaseConcurrentBarrier(t, proceed)
		defer unblock()
		m.launchProfileOverride = func(p *profile.Profile) (*Session, error) {
			close(started)
			<-proceed
			s, _ := newConcurrentSession(p.ID)
			return s, nil
		}
		done := make(chan error, 1)
		go func() { _, err := m.LaunchSession(&profile.Profile{ID: "A"}); done <- err }()
		requireConcurrentResult(t, started, "launch did not start")
		if len(m.ListSessions()) != 0 {
			t.Fatal("fixture already registered a session")
		}
		assertUpdateBusyWithoutWaiting(t, m)
		unblock()
		if err := requireConcurrentResult(t, done, "launch did not finish"); err != nil {
			t.Fatal(err)
		}
		assertUpdateBusyWithoutWaiting(t, m)
	})
	t.Run("close", func(t *testing.T) {
		m := newConcurrentManager(t)
		s, _ := newConcurrentSession("A")
		ctx := &updateBlockedCloseContext{started: make(chan struct{}), unblock: make(chan struct{})}
		unblock := releaseConcurrentBarrier(t, ctx.unblock)
		defer unblock()
		s.Context = ctx
		m.sessions[s.ID] = s
		done := make(chan error, 1)
		go func() { done <- m.CloseSession(s.ID) }()
		requireConcurrentResult(t, ctx.started, "close did not start")
		if len(m.ListSessions()) != 0 {
			t.Fatal("fixture did not remove the closing session")
		}
		assertUpdateBusyWithoutWaiting(t, m)
		unblock()
		if err := requireConcurrentResult(t, done, "close did not finish"); err != nil {
			t.Fatal(err)
		}
		token, err := m.AcquireUpdateMaintenance(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.ReleaseUpdateMaintenance(token); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("store mutation before Store mutex", func(t *testing.T) {
		m := newConcurrentManager(t)
		store, err := profile.NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		started, proceed := make(chan struct{}), make(chan struct{})
		unblock := releaseConcurrentBarrier(t, proceed)
		defer unblock()
		store.SetMutationGuard(func(id string) (func(), error) {
			release, err := m.ReserveProfileMutation(id)
			if err != nil {
				return nil, err
			}
			close(started)
			<-proceed
			return release, nil
		})
		done := make(chan error, 1)
		go func() { done <- store.Create(&profile.Profile{ID: "new", RuntimeID: "cloakbrowser"}) }()
		requireConcurrentResult(t, started, "store mutation did not reserve")
		assertUpdateBusyWithoutWaiting(t, m)
		unblock()
		if err := requireConcurrentResult(t, done, "store mutation did not finish"); err != nil {
			t.Fatal(err)
		}
		token, err := m.AcquireUpdateMaintenance(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.ReleaseUpdateMaintenance(token); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("request remainder", func(t *testing.T) {
		m := newConcurrentManager(t)
		release, err := m.ReserveUpdateOperation()
		if err != nil {
			t.Fatal(err)
		}
		assertUpdateBusyWithoutWaiting(t, m)
		release()
		token, err := m.AcquireUpdateMaintenance(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.ReleaseUpdateMaintenance(token); err != nil {
			t.Fatal(err)
		}
	})
}

func assertUpdateBusyWithoutWaiting(t *testing.T, m *Manager) {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := m.AcquireUpdateMaintenance(context.Background()); done <- err }()
	if err := requireConcurrentResult(t, done, "update waited for active user work"); ErrorCode(err) != "UPDATE_MAINTENANCE_BUSY" {
		t.Fatal(err)
	}
}

func TestUpdateAdmissionIsAtomicWithRequestsAndCacheLeases(t *testing.T) {
	m := newConcurrentManager(t)
	cacheToken, err := m.AcquireProfileMaintenance(context.Background(), []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	assertUpdateBusyWithoutWaiting(t, m)
	if err := m.ReleaseUpdateMaintenance(cacheToken); ErrorCode(err) != "CACHE_MAINTENANCE_TOKEN_INVALID" {
		t.Fatal(err)
	}
	if err := m.ReleaseProfileMaintenance(cacheToken); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.AcquireUpdateMaintenance(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for range 32 {
		start := make(chan struct{})
		acquired := make(chan string, 1)
		reserved := make(chan func(), 1)
		failures := make(chan error, 2)
		go func() {
			<-start
			token, err := m.AcquireUpdateMaintenance(context.Background())
			acquired <- token
			failures <- err
		}()
		go func() { <-start; release, err := m.ReserveUpdateOperation(); reserved <- release; failures <- err }()
		close(start)
		token := requireConcurrentResult(t, acquired, "update race stalled")
		release := requireConcurrentResult(t, reserved, "operation race stalled")
		if (token != "") == (release != nil) {
			t.Fatal("update and operation admitted together or neither admitted")
		}
		busy := 0
		for range 2 {
			if err := <-failures; ErrorCode(err) == "UPDATE_MAINTENANCE_BUSY" {
				busy++
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if busy != 1 {
			t.Fatal("race did not refuse exactly one participant")
		}
		if release != nil {
			release()
		} else if err := m.ReleaseUpdateMaintenance(token); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpdateRequestAccountingDoesNotPreventNormalBrowserShutdown(t *testing.T) {
	m := newConcurrentManager(t)
	s, ctx := newConcurrentSession("A")
	m.sessions[s.ID] = s
	release, err := m.ReserveUpdateOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	requireConcurrentResult(t, done, "shutdown waited for a request that may need browser closure")
	if ctx.closes.Load() != 1 || len(m.ListSessions()) != 0 {
		t.Fatal("normal shutdown did not close the browser")
	}
}

type updateFailedCloseContext struct{ desktopTestContext }

func (*updateFailedCloseContext) Close(...playwright.BrowserContextCloseOptions) error {
	return errors.New("synthetic context close failure")
}

type updateFailedCloseBrowser struct{ playwright.Browser }

func (*updateFailedCloseBrowser) Close(...playwright.BrowserCloseOptions) error {
	return errors.New("synthetic browser close failure")
}

func TestUpdateAdmissionRefusesUncertainCleanupAfterSessionRecordIsGone(t *testing.T) {
	for _, resource := range []string{"context", "browser"} {
		t.Run(resource, func(t *testing.T) {
			m := newConcurrentManager(t)
			s, _ := newConcurrentSession("A")
			if resource == "context" {
				s.Context = &updateFailedCloseContext{}
			} else {
				s.Browser = &updateFailedCloseBrowser{}
			}
			m.sessions[s.ID] = s
			if err := m.CloseSession(s.ID); err != nil {
				t.Fatal("existing close behavior changed", err)
			}
			if len(m.ListSessions()) != 0 {
				t.Fatal("fixture retained session metadata")
			}
			assertUpdateBusyWithoutWaiting(t, m)
			// A later successful cleanup of an unrelated browser cannot erase uncertainty.
			other, _ := newConcurrentSession("B")
			m.sessions[other.ID] = other
			if err := m.CloseSession(other.ID); err != nil {
				t.Fatal(err)
			}
			assertUpdateBusyWithoutWaiting(t, m)
		})
	}
}
