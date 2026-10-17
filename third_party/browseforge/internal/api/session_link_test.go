package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"browseforge/internal/browser"
	"github.com/go-chi/chi/v5"
	"github.com/mxschmitt/playwright-go"
)

type guardedLinkPage struct {
	playwright.Page
	target     string
	closed     bool
	duringGoto func()
}

func (p *guardedLinkPage) IsClosed() bool { return p.closed }
func (p *guardedLinkPage) Goto(target string, _ ...playwright.PageGotoOptions) (playwright.Response, error) {
	if p.duringGoto != nil {
		p.duringGoto()
	}
	p.target = target
	return nil, nil
}
func (p *guardedLinkPage) Close(...playwright.PageCloseOptions) error { p.closed = true; return nil }
func (p *guardedLinkPage) BringToFront() error                        { return nil }

type guardedLinkContext struct {
	playwright.BrowserContext
	page  *guardedLinkPage
	calls int
}

func (c *guardedLinkContext) NewPage() (playwright.Page, error) { c.calls++; return c.page, nil }

func setGuardedLinkField(target any, name string, value any) {
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}
func linkRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/sessions/sess_fixture/open-link", strings.NewReader(body))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "sess_fixture")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
}
func guardedLinkFixture() (*handler, *browser.Session, *guardedLinkContext) {
	ctx := &guardedLinkContext{page: &guardedLinkPage{}}
	s := &browser.Session{ID: "sess_fixture", InstanceID: strings.Repeat("a", 32), ProfileID: "fixture", Context: ctx}
	setGuardedLinkField(s, "routeDigest", strings.Repeat("b", 64))
	mgr := &browser.Manager{}
	setGuardedLinkField(mgr, "sessions", map[string]*browser.Session{s.ID: s})
	return &handler{mgr: mgr}, s, ctx
}
func TestGuardedLinkUsesCapturedProductionContextWithoutReLookupAtNavigation(t *testing.T) {
	h, s, ctx := guardedLinkFixture()
	replacement := &browser.Session{ID: s.ID, InstanceID: strings.Repeat("c", 32), Context: &guardedLinkContext{page: &guardedLinkPage{}}}
	ctx.page.duringGoto = func() { setGuardedLinkField(h.mgr, "sessions", map[string]*browser.Session{s.ID: replacement}) }
	body, _ := json.Marshal(map[string]string{"url": "https://example.test/path", "instance_id": s.InstanceID, "route_digest": strings.Repeat("b", 64)})
	rec := httptest.NewRecorder()
	h.openSessionLink(rec, linkRequest(string(body)))
	if rec.Code != 200 || ctx.calls != 1 || ctx.page.target != "https://example.test/path" {
		t.Fatalf("guarded navigation failed: %d", rec.Code)
	}
	if replacement.Context.(*guardedLinkContext).calls != 0 {
		t.Fatal("replacement context received pending URL")
	}
}
func TestGuardedLinkRejectsStaleConditionsAndInvalidURLsBeforeCreatingAnyTab(t *testing.T) {
	for _, body := range []string{
		`{"url":"https://example.test","instance_id":"old","route_digest":"wrong"}`,
		`{"url":"file:///private/fixture","instance_id":"` + strings.Repeat("a", 32) + `","route_digest":"` + strings.Repeat("b", 64) + `"}`,
		`{"url":"https://user:pass@example.test"}`, `{"url":"https://example.test","unexpected":true}`, `{} {}`,
	} {
		h, _, ctx := guardedLinkFixture()
		rec := httptest.NewRecorder()
		h.openSessionLink(rec, linkRequest(body))
		if rec.Code < 400 || ctx.calls != 0 {
			t.Fatalf("invalid/stale link reached context: status=%d", rec.Code)
		}
	}
}
func TestSessionRouteIdentityIsNotIncludedInSessionListing(t *testing.T) {
	h, _, _ := guardedLinkFixture()
	rec := httptest.NewRecorder()
	h.listSessions(rec, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "route_digest") || strings.Contains(rec.Body.String(), strings.Repeat("b", 64)) {
		t.Fatal("private actual route escaped into public session listing")
	}
	rec = httptest.NewRecorder()
	h.sessionLinkIdentity(rec, linkRequest(""))
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "route_digest") {
		t.Fatal("private identity endpoint unavailable")
	}
}
