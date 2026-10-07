package browser

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"browseforge/internal/profile"

	"github.com/mxschmitt/playwright-go"
)

func newConcurrentSession(profileID string) (*Session, *desktopTestContext) {
	page := &desktopTestPage{}
	ctx := &desktopTestContext{pages: []playwright.Page{page}}
	return &Session{ID: "sess_" + profileID, ProfileID: profileID, Context: ctx, Page: page, ConnectURL: "ws://test/" + profileID}, ctx
}

func newConcurrentManager(t *testing.T) *Manager {
	t.Helper()
	mgr := &Manager{
		sessions:            map[string]*Session{},
		bindSessionEndpoint: func(session *Session) (string, error) { return session.ConnectURL, nil },
		endpointHealthCheck: func(string, float64) error { return nil },
	}
	t.Cleanup(mgr.Close)
	return mgr
}

func releaseConcurrentBarrier(t *testing.T, barrier chan struct{}) func() {
	t.Helper()
	var once sync.Once
	release := func() { once.Do(func() { close(barrier) }) }
	t.Cleanup(release)
	return release
}

func awaitConcurrentCondition(t *testing.T, condition func() bool, message string) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}

func requireConcurrentResult[T any](t *testing.T, channel <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
		var zero T
		return zero
	}
}

func TestStalledLaunchDoesNotBlockOtherProfileOperations(t *testing.T) {
	mgr := newConcurrentManager(t)
	existing, ctx := newConcurrentSession("B")
	mgr.sessions[existing.ID] = existing
	mgr.observeSession(existing)
	started, release := make(chan struct{}), make(chan struct{})
	unblock := releaseConcurrentBarrier(t, release)
	defer unblock()
	mgr.launchProfileOverride = func(p *profile.Profile) (*Session, error) {
		if p.ID == "A" {
			close(started)
			<-release
		}
		session, _ := newConcurrentSession(p.ID)
		return session, nil
	}
	launchResult := make(chan error, 1)
	go func() { _, err := mgr.LaunchSession(&profile.Profile{ID: "A"}); launchResult <- err }()
	requireConcurrentResult(t, started, "A launch never started")
	listResult := make(chan int, 1)
	go func() { listResult <- len(mgr.ListSessions()) }()
	if count := requireConcurrentResult(t, listResult, "session list blocked behind A launch"); count != 1 {
		t.Fatalf("running session count=%d", count)
	}
	focusResult := make(chan error, 1)
	go func() { focusResult <- mgr.FocusSession(existing.ID) }()
	if err := requireConcurrentResult(t, focusResult, "B focus blocked behind A launch"); err != nil {
		t.Fatal(err)
	}
	otherLaunch := make(chan error, 1)
	go func() { _, err := mgr.LaunchSession(&profile.Profile{ID: "C"}); otherLaunch <- err }()
	if err := requireConcurrentResult(t, otherLaunch, "another profile launch blocked behind A"); err != nil {
		t.Fatal(err)
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- mgr.CloseSession(existing.ID) }()
	if err := requireConcurrentResult(t, closeResult, "B close blocked behind A launch"); err != nil {
		t.Fatal(err)
	}
	if ctx.closes.Load() != 1 {
		t.Fatalf("B context closed %d times", ctx.closes.Load())
	}
}

func TestDuplicateProfileLaunchIsDeduplicated(t *testing.T) {
	mgr := newConcurrentManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	unblock := releaseConcurrentBarrier(t, release)
	var calls atomic.Int32
	session, _ := newConcurrentSession("A")
	mgr.launchProfileOverride = func(*profile.Profile) (*Session, error) {
		calls.Add(1)
		close(started)
		<-release
		return session, nil
	}
	type result struct {
		session *Session
		err     error
	}
	results := make(chan result, 2)
	launch := func() { s, err := mgr.LaunchSession(&profile.Profile{ID: "A"}); results <- result{s, err} }
	go launch()
	requireConcurrentResult(t, started, "A launch never started")
	go launch()
	awaitConcurrentCondition(t, func() bool {
		mgr.mu.RLock()
		defer mgr.mu.RUnlock()
		return mgr.activeOperations == 2
	}, "duplicate did not reserve the same profile")
	if calls.Load() != 1 {
		t.Fatal("duplicate profile entered browser launcher concurrently")
	}
	unblock()
	for range 2 {
		got := requireConcurrentResult(t, results, "duplicate launch did not complete")
		if got.err != nil || got.session != session {
			t.Fatalf("duplicate result=%v, %v", got.session, got.err)
		}
	}
	if calls.Load() != 1 || len(mgr.ListSessions()) != 1 {
		t.Fatal("duplicate launch created more than one browser session")
	}
}

func TestShutdownWaitsForLaunchAndCleansLateResources(t *testing.T) {
	mgr := newConcurrentManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	unblock := releaseConcurrentBarrier(t, release)
	session, ctx := newConcurrentSession("A")
	mgr.launchProfileOverride = func(*profile.Profile) (*Session, error) {
		close(started)
		<-release
		return session, nil
	}
	launched := make(chan error, 1)
	go func() { _, err := mgr.LaunchSession(&profile.Profile{ID: "A"}); launched <- err }()
	requireConcurrentResult(t, started, "A launch never started")
	closed := make(chan struct{})
	go func() { mgr.Close(); close(closed) }()
	awaitConcurrentCondition(t, func() bool {
		mgr.mu.RLock()
		defer mgr.mu.RUnlock()
		return mgr.closing
	}, "shutdown did not reject new work")
	select {
	case <-closed:
		t.Fatal("shutdown completed while native launch was still in flight")
	default:
	}
	if _, err := mgr.LaunchSession(&profile.Profile{ID: "new"}); !errors.Is(err, ErrManagerClosing) {
		t.Fatalf("new launch during shutdown=%v", err)
	}
	unblock()
	if err := requireConcurrentResult(t, launched, "in-flight launch did not unwind"); !errors.Is(err, ErrManagerClosing) {
		t.Fatalf("late launch during shutdown=%v", err)
	}
	requireConcurrentResult(t, closed, "shutdown did not complete after launch returned")
	if ctx.closes.Load() != 1 || len(mgr.ListSessions()) != 0 {
		t.Fatalf("late resources were not cleaned: closes=%d sessions=%d", ctx.closes.Load(), len(mgr.ListSessions()))
	}
}

func TestFailedLaunchRetryKeepsOtherProfileRunning(t *testing.T) {
	mgr := newConcurrentManager(t)
	existing, ctx := newConcurrentSession("B")
	mgr.sessions[existing.ID] = existing
	var calls atomic.Int32
	mgr.launchProfileOverride = func(*profile.Profile) (*Session, error) {
		if calls.Add(1) == 1 {
			return nil, codedError{code: "BROWSER_BIND_FAILED", err: errors.New("temporary endpoint failure")}
		}
		session, _ := newConcurrentSession("A")
		return session, nil
	}
	if _, err := mgr.LaunchSession(&profile.Profile{ID: "A"}); err != nil {
		t.Fatal(err)
	}
	if got, ok := mgr.GetSession(existing.ID); !ok || got != existing || ctx.closes.Load() != 0 {
		t.Fatal("retrying A stopped B or lost its session")
	}
	if calls.Load() != 2 {
		t.Fatalf("local retry calls=%d", calls.Load())
	}
}

type stalledFocusPage struct {
	desktopTestPage
	started chan struct{}
	release chan struct{}
}

func (p *stalledFocusPage) BringToFront() error {
	close(p.started)
	<-p.release
	return nil
}

func TestShutdownWaitsForNativeFocus(t *testing.T) {
	mgr := newConcurrentManager(t)
	page := &stalledFocusPage{started: make(chan struct{}), release: make(chan struct{})}
	unblock := releaseConcurrentBarrier(t, page.release)
	ctx := &desktopTestContext{pages: []playwright.Page{page}}
	session := &Session{ID: "sess_B", ProfileID: "B", Context: ctx, Page: page}
	mgr.sessions[session.ID] = session
	focused := make(chan error, 1)
	go func() { focused <- mgr.FocusSession(session.ID) }()
	requireConcurrentResult(t, page.started, "native focus never started")
	closed := make(chan struct{})
	go func() { mgr.Close(); close(closed) }()
	awaitConcurrentCondition(t, func() bool {
		mgr.mu.RLock()
		defer mgr.mu.RUnlock()
		return mgr.closing
	}, "shutdown did not start")
	if ctx.closes.Load() != 0 {
		t.Fatal("shutdown closed browser during in-flight native focus")
	}
	if err := mgr.FocusSession(session.ID); !errors.Is(err, ErrManagerClosing) {
		t.Fatalf("new focus during shutdown=%v", err)
	}
	unblock()
	if err := requireConcurrentResult(t, focused, "focus did not finish"); err != nil {
		t.Fatal(err)
	}
	requireConcurrentResult(t, closed, "shutdown did not finish after focus")
	if ctx.closes.Load() != 1 {
		t.Fatal("shutdown did not clean the focused browser")
	}
}
