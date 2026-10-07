package browser

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

type desktopTestContext struct {
	playwright.BrowserContext
	onClose func(playwright.BrowserContext)
	onPage  func(playwright.Page)
	pages   []playwright.Page
	closes  atomic.Int32
}

func (c *desktopTestContext) OnClose(fn func(playwright.BrowserContext)) { c.onClose = fn }
func (c *desktopTestContext) OnPage(fn func(playwright.Page))            { c.onPage = fn }
func (c *desktopTestContext) Close(...playwright.BrowserContextCloseOptions) error {
	c.closes.Add(1)
	if c.onClose != nil {
		c.onClose(c)
	}
	return nil
}
func (c *desktopTestContext) Pages() []playwright.Page { return c.pages }

type desktopTestPage struct {
	playwright.Page
	mu       sync.Mutex
	closed   bool
	onClose  func(playwright.Page)
	focuses  int
	focusErr error
}

func (p *desktopTestPage) IsClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}
func (p *desktopTestPage) OnClose(fn func(playwright.Page)) { p.onClose = fn }
func (p *desktopTestPage) closeExternally() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	if p.onClose != nil {
		p.onClose(p)
	}
}
func (p *desktopTestPage) BringToFront() error {
	p.focuses++
	return p.focusErr
}

func testDesktopSession() (*Manager, *Session, *desktopTestContext) {
	ctx := &desktopTestContext{}
	session := &Session{ID: "desktop", ProfileID: "profile", Context: ctx}
	mgr := &Manager{sessions: map[string]*Session{session.ID: session}}
	mgr.observeSession(session)
	return mgr, session, ctx
}

func awaitDesktopSessionRemoval(t *testing.T, mgr *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, exists := mgr.GetSession(id); !exists {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("closed browser context remained in running sessions")
}

func TestDesktopExternalContextCloseRemovesSessionAndRelay(t *testing.T) {
	mgr, session, ctx := testDesktopSession()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	session.relay = &SOCKS5Relay{ln: listener, done: make(chan struct{})}
	if err := ctx.Close(); err != nil {
		t.Fatal(err)
	}
	awaitDesktopSessionRemoval(t, mgr, session.ID)
	// Cleanup is asynchronous; wait for the listener itself to close as well.
	if tcp, ok := listener.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(time.Second))
	}
	connection, err := listener.Accept()
	if connection != nil {
		connection.Close()
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("relay listener still open after context close: %v", err)
	}
}

func TestDesktopExplicitCloseDoesNotDeadlockOnContextCallback(t *testing.T) {
	for _, closeAll := range []bool{false, true} {
		mgr, session, _ := testDesktopSession()
		finished := make(chan error, 1)
		go func() {
			if closeAll {
				mgr.Close()
				finished <- nil
			} else {
				finished <- mgr.CloseSession(session.ID)
			}
		}()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatalf("manager close deadlocked, closeAll=%v", closeAll)
		}
		awaitDesktopSessionRemoval(t, mgr, session.ID)
	}
}

func TestDesktopOldContextCannotRemoveReplacementSession(t *testing.T) {
	mgr, old, _ := testDesktopSession()
	replacement := &Session{ID: old.ID, ProfileID: old.ProfileID}
	mgr.sessions[old.ID] = replacement
	mgr.removeClosedSession(old)
	if got, ok := mgr.GetSession(old.ID); !ok || got != replacement {
		t.Fatal("stale context callback removed the replacement session")
	}
}

func TestDesktopConcurrentCloseCleansRelayOnlyOnce(t *testing.T) {
	mgr, session, _ := testDesktopSession()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	session.relay = &SOCKS5Relay{ln: listener, done: make(chan struct{})}
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			mgr.removeClosedSession(session)
		}()
	}
	group.Wait()
	awaitDesktopSessionRemoval(t, mgr, session.ID)
}

func TestDesktopFocusUsesExistingPageAndReportsFailure(t *testing.T) {
	mgr, session, ctx := testDesktopSession()
	page := &desktopTestPage{}
	session.Page = page
	if err := mgr.FocusSession(session.ID); err != nil || page.focuses != 1 {
		t.Fatalf("focus error=%v calls=%d", err, page.focuses)
	}
	page.closed = true
	alternative := &desktopTestPage{focusErr: errors.New("native focus failed")}
	ctx.pages = []playwright.Page{page, alternative}
	if err := mgr.FocusSession(session.ID); !errors.Is(err, alternative.focusErr) || alternative.focuses != 1 {
		t.Fatalf("alternative page focus error=%v calls=%d", err, alternative.focuses)
	}
	ctx.pages = nil
	if err := mgr.FocusSession(session.ID); err == nil {
		t.Fatal("focus with no open page reported success")
	}
	if err := mgr.FocusSession("missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing session error = %v", err)
	}
}

func TestDesktopDraftCannotLaunchDisabledRuntime(t *testing.T) {
	cfg := &config.Config{AllowEmptyRuntime: true}
	mgr := &Manager{cfg: cfg, runtimes: bfruntime.NewRegistry(cfg), sessions: map[string]*Session{}}
	if _, err := mgr.LaunchSession(&profile.Profile{ID: "draft", RuntimeID: "cloakbrowser"}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("draft launch error = %v", err)
	}
	if len(mgr.ListSessions()) != 0 {
		t.Fatal("failed launch created a running session")
	}
}

func TestDesktopClosingOneTabRepairsSelectionAndLastTabStopsSession(t *testing.T) {
	initial := &desktopTestPage{}
	other := &desktopTestPage{}
	ctx := &desktopTestContext{pages: []playwright.Page{initial, other}}
	session := &Session{ID: "two-tabs", Context: ctx, Page: initial}
	mgr := &Manager{sessions: map[string]*Session{session.ID: session}}
	mgr.observeSession(session)
	initial.closeExternally()
	if page, err := mgr.SessionPage(session.ID); err != nil || page != other {
		t.Fatalf("remaining tab selection = %v, %v", page, err)
	}
	if err := mgr.FocusSession(session.ID); err != nil || other.focuses != 1 {
		t.Fatalf("remaining tab focus = %v calls=%d", err, other.focuses)
	}
	other.closeExternally()
	awaitDesktopSessionRemoval(t, mgr, session.ID)
}

func TestDesktopNewTabGetsCloseObserver(t *testing.T) {
	mgr, session, ctx := testDesktopSession()
	page := &desktopTestPage{}
	ctx.pages = []playwright.Page{page}
	ctx.onPage(page)
	if err := mgr.SetSessionPage(session.ID, page); err != nil {
		t.Fatal(err)
	}
	page.closeExternally()
	awaitDesktopSessionRemoval(t, mgr, session.ID)
}
