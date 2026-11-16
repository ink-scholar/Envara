package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"browseforge/internal/browser"
	"github.com/playwright-community/playwright-go"
)

type runtimeTestPage struct {
	playwright.Page
	closes   int
	evaluate func(string) (any, error)
	onClose  func()
}

func (p *runtimeTestPage) Close(...playwright.PageCloseOptions) error {
	p.closes++
	if p.onClose != nil {
		p.onClose()
	}
	return nil
}
func (p *runtimeTestPage) IsClosed() bool { return p.closes > 0 }
func (p *runtimeTestPage) Evaluate(expression string, _ ...any) (any, error) {
	return p.evaluate(expression)
}

type runtimeTestContext struct {
	playwright.BrowserContext
	page          *runtimeTestPage
	calls         int
	pages         []playwright.Page
	onCreate      func()
	onTargetClose func()
}

func (c *runtimeTestContext) NewPage() (playwright.Page, error) { c.calls++; return c.page, nil }
func (c *runtimeTestContext) Pages() []playwright.Page          { return c.pages }
func (c *runtimeTestContext) NewCDPSession(page any) (playwright.CDPSession, error) {
	return &runtimeTestCDP{context: c, owned: page == c.page}, nil
}

type runtimeTestCDP struct {
	playwright.CDPSession
	context *runtimeTestContext
	owned   bool
}

func (c *runtimeTestCDP) Detach() error { return nil }
func (c *runtimeTestCDP) Send(method string, params map[string]any) (any, error) {
	switch method {
	case "Target.getTargetInfo":
		id := "existing"
		if c.owned {
			id = "owned"
		}
		return map[string]any{"targetInfo": map[string]any{"targetId": id}}, nil
	case "Target.createTarget":
		if params["background"] != true {
			return nil, errors.New("foreground target refused")
		}
		c.context.calls++
		c.context.pages = append(c.context.pages, c.context.page)
		if c.context.onCreate != nil {
			c.context.onCreate()
		}
		return map[string]any{"targetId": "owned"}, nil
	case "Target.closeTarget":
		if params["targetId"] != "owned" {
			return nil, errors.New("not owned")
		}
		c.context.page.closes++
		if c.context.onTargetClose != nil {
			c.context.onTargetClose()
		}
		return nil, nil
	}
	return nil, errors.New("unexpected method")
}

func awaitRuntimeEvent(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(time.Second):
		t.Fatalf("timed out: %s", label)
	}
}
func awaitRuntimeLeaseRelease(t *testing.T, key runtimeVerificationKey) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if _, busy := runtimeVerificationInFlight.Load(key); !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("owned cleanup did not release lease")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestRuntimeVerificationCreationCancellationReturnsBeforeLateOwnedCleanupAndRetainsLease(t *testing.T) {
	h, s, c, body := runtimeFixture()
	entered, unblock, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c.onCreate = func() { close(entered); <-unblock }
	c.onTargetClose = func() { close(closed) }
	request := linkRequest(body)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	rec, finished := httptest.NewRecorder(), make(chan struct{})
	go func() { h.runtimeVerification(rec, request.WithContext(ctx)); close(finished) }()
	awaitRuntimeEvent(t, entered, "creation")
	cancel()
	awaitRuntimeEvent(t, finished, "cancelled handler")
	if rec.Code != 504 {
		t.Fatalf("cancelled creation returned %d", rec.Code)
	}
	busy := httptest.NewRecorder()
	h.runtimeVerification(busy, linkRequest(body))
	if busy.Code != 409 || !strings.Contains(busy.Body.String(), "RUNTIME_VERIFICATION_BUSY") {
		t.Fatal("cancelled worker lost its lease")
	}
	close(unblock)
	awaitRuntimeEvent(t, closed, "exact late target close")
	awaitRuntimeLeaseRelease(t, runtimeVerificationKey{h.mgr, s.ID, s.InstanceID})
}
func TestRuntimeVerificationCancellationBoundsEvaluationAndCloseWithoutReleasingUnfinishedWorkers(t *testing.T) {
	for _, phase := range []string{"evaluation", "close"} {
		t.Run(phase, func(t *testing.T) {
			h, s, c, body := runtimeFixture()
			entered, unblock := make(chan struct{}), make(chan struct{})
			if phase == "evaluation" {
				c.page.evaluate = func(string) (any, error) { close(entered); <-unblock; return nil, errors.New("cancelled") }
			} else {
				c.page.onClose = func() { close(entered); <-unblock }
			}
			request := linkRequest(body)
			ctx, cancel := context.WithCancel(request.Context())
			defer cancel()
			rec, finished := httptest.NewRecorder(), make(chan struct{})
			go func() { h.runtimeVerification(rec, request.WithContext(ctx)); close(finished) }()
			awaitRuntimeEvent(t, entered, phase)
			cancel()
			awaitRuntimeEvent(t, finished, "cancelled handler")
			if rec.Code != 504 {
				t.Fatalf("cancelled %s returned %d", phase, rec.Code)
			}
			key := runtimeVerificationKey{h.mgr, s.ID, s.InstanceID}
			if _, busy := runtimeVerificationInFlight.Load(key); !busy {
				t.Fatal("unfinished worker lost its lease")
			}
			close(unblock)
			awaitRuntimeLeaseRelease(t, key)
		})
	}
}

func runtimeFixture() (*handler, *browser.Session, *runtimeTestContext, string) {
	h, s, _ := guardedLinkFixture()
	c := &runtimeTestContext{page: &runtimeTestPage{evaluate: func(_ string) (any, error) {
		return map[string]any{"locale": "en-US", "timezone": "America/New_York", "ip": "8.8.8.8", "secret": "excluded"}, nil
	}}}
	s.Context = c
	s.RuntimeID = "cloakbrowser"
	c.pages = []playwright.Page{&guardedLinkPage{}}
	body := `{"instance_id":"` + strings.Repeat("a", 32) + `","route_digest":"` + strings.Repeat("b", 64) + `"}`
	return h, s, c, body
}
func TestRuntimeVerificationUnsupportedEngineIsExplicitAndCreatesNoPage(t *testing.T) {
	h, s, c, body := runtimeFixture()
	s.RuntimeID = "camoufox"
	rec := httptest.NewRecorder()
	h.runtimeVerification(rec, linkRequest(body))
	if rec.Code != 501 || c.calls != 0 || !strings.Contains(rec.Body.String(), "RUNTIME_VERIFICATION_UNSUPPORTED") {
		t.Fatal("unsupported engine did not fail closed")
	}
}
func TestRuntimeVerificationOwnsOnePageAndReturnsOnlyDocumentObservation(t *testing.T) {
	h, s, c, body := runtimeFixture()
	selected := &guardedLinkPage{}
	s.Page = selected
	rec := httptest.NewRecorder()
	h.runtimeVerification(rec, linkRequest(body))
	if rec.Code != 200 || c.calls != 1 || c.page.closes != 1 || s.Page != selected || selected.closed || strings.Contains(rec.Body.String(), "excluded") {
		t.Fatalf("unsafe observation: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
}
func TestRuntimeVerificationRejectsUserURLsAndClosesOnEngineFailure(t *testing.T) {
	h, _, c, body := runtimeFixture()
	rec := httptest.NewRecorder()
	h.runtimeVerification(rec, linkRequest(strings.TrimSuffix(body, "}")+`,"url":"https://elsewhere.test"}`))
	if rec.Code != 400 || c.calls != 0 {
		t.Fatal("caller URL accepted")
	}
	c.page.evaluate = func(string) (any, error) { return nil, errors.New("private engine error") }
	rec = httptest.NewRecorder()
	h.runtimeVerification(rec, linkRequest(body))
	if rec.Code != 502 || c.page.closes != 1 || strings.Contains(rec.Body.String(), "private engine") {
		t.Fatal("failed observation leaked error or retained page")
	}
}
func TestRuntimeVerificationDiscardsObservationFromReplacedInstance(t *testing.T) {
	h, s, c, body := runtimeFixture()
	c.page.evaluate = func(string) (any, error) {
		s.InstanceID = strings.Repeat("c", 32)
		return map[string]any{"ip": "8.8.8.8"}, nil
	}
	rec := httptest.NewRecorder()
	h.runtimeVerification(rec, linkRequest(body))
	if rec.Code != 409 || c.page.closes != 1 || strings.Contains(rec.Body.String(), "8.8.8.8") {
		t.Fatal("stale observation accepted")
	}
}
func TestRuntimeVerificationScriptCannotNavigateOrUseCredentials(t *testing.T) {
	for _, required := range []string{"navigator.language", "Intl.DateTimeFormat()", "https://ipwho.is/", "credentials: 'omit'", "redirect: 'error'", "AbortController", "16384"} {
		if !strings.Contains(runtimeVerificationScript, required) {
			t.Fatalf("missing safeguard %s", required)
		}
	}
	for _, forbidden := range []string{"location.href", "document.cookie", "localStorage", "BringToFront"} {
		if strings.Contains(runtimeVerificationScript, forbidden) {
			t.Fatal("page state mutation")
		}
	}
}
