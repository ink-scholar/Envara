package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"browseforge/internal/browser"
	"github.com/playwright-community/playwright-go"
)

type cookieCDP struct {
	playwright.CDPSession
	cookies    []map[string]any
	deletes    []map[string]any
	detached   bool
	failDelete bool
}

func (c *cookieCDP) Detach() error { c.detached = true; return nil }
func (c *cookieCDP) Send(method string, args map[string]any) (any, error) {
	if method == "Network.getAllCookies" {
		return map[string]any{"cookies": c.cookies}, nil
	}
	if method == "Network.deleteCookies" {
		if c.failDelete {
			return nil, errors.New("private backend detail")
		}
		c.deletes = append(c.deletes, args)
		return map[string]any{}, nil
	}
	panic("unexpected CDP operation: " + method)
}

type cookieContext struct {
	playwright.BrowserContext
	cdp    *cookieCDP
	plain  []playwright.Cookie
	opened int
}

func (c *cookieContext) Pages() []playwright.Page { return []playwright.Page{&guardedLinkPage{}} }
func (c *cookieContext) NewCDPSession(any) (playwright.CDPSession, error) {
	c.opened++
	return c.cdp, nil
}
func (c *cookieContext) Cookies(...string) ([]playwright.Cookie, error) { return c.plain, nil }
func cookieFixture(runtime string) (*handler, *cookieContext) {
	h, sess, _ := guardedLinkFixture()
	c := &cookieContext{cdp: &cookieCDP{cookies: []map[string]any{
		{"name": "login", "domain": ".example.test", "path": "/", "value": "secret-not-for-renderer", "expires": float64(-1), "httpOnly": true, "secure": true, "sameSite": "Lax"},
		{"name": "login", "domain": "other.test", "path": "/", "value": "other-secret", "expires": float64(-1), "httpOnly": true, "secure": true, "sameSite": "Lax"},
		{"name": "partition", "domain": ".example.test", "path": "/x", "expires": float64(-1), "httpOnly": true, "secure": true, "sameSite": "None", "partitionKey": map[string]any{"topLevelSite": "https://top.test", "hasCrossSiteAncestor": false}},
	}}}
	sess.RuntimeID, sess.Context = runtime, c
	return h, c
}
func siteRequest(domain string) string {
	args := map[string]string{"instance_id": strings.Repeat("a", 32)}
	if domain != "" {
		args["domain"] = domain
	}
	value, _ := json.Marshal(args)
	return string(value)
}
func TestSiteCookieInventoryRedactsValuesAndPreservesPartitions(t *testing.T) {
	h, ctx := cookieFixture("cloakbrowser")
	r := httptest.NewRecorder()
	h.listSiteCookies(r, linkRequest(siteRequest("")))
	if r.Code != 200 || strings.Contains(r.Body.String(), "secret") || strings.Contains(r.Body.String(), `"value"`) || !strings.Contains(r.Body.String(), `"partitionKey":"https://top.test"`) || !ctx.cdp.detached {
		t.Fatalf("unsafe inventory: %d %s", r.Code, r.Body.String())
	}
	if len(ctx.cdp.deletes) != 0 {
		t.Fatal("inventory mutated cookies")
	}
}
func TestSiteCookieDeleteUsesExactDomainAndFullPartitionIdentity(t *testing.T) {
	h, ctx := cookieFixture("browseforge-chromium")
	r := httptest.NewRecorder()
	h.clearSiteCookies(r, linkRequest(siteRequest(".example.test")))
	if r.Code != 200 || len(ctx.cdp.deletes) != 2 {
		t.Fatalf("unexpected deletion: %d %s", r.Code, r.Body.String())
	}
	for _, item := range ctx.cdp.deletes {
		if item["domain"] != ".example.test" {
			t.Fatal("removed another site's cookie")
		}
	}
	partition := ctx.cdp.deletes[1]["partitionKey"].(map[string]any)
	if partition["hasCrossSiteAncestor"] != false || partition["topLevelSite"] != "https://top.test" {
		t.Fatal("partition key changed")
	}
}
func TestSiteCookieUnsupportedPartitionFailsBeforeAnyMutation(t *testing.T) {
	for _, opaque := range []map[string]any{{"partitionKeyOpaque": true}, {"partitionKey": map[string]any{"topLevelSite": "https://top.test"}}} {
		h, ctx := cookieFixture("cloakbrowser")
		for k, v := range opaque {
			ctx.cdp.cookies[2][k] = v
		}
		r := httptest.NewRecorder()
		h.clearSiteCookies(r, linkRequest(siteRequest(".example.test")))
		if r.Code != 409 || len(ctx.cdp.deletes) > 0 {
			t.Fatal("unsupported partition reached mutation")
		}
	}
}
func TestSiteCookieCamoufoxReadOnlyDoesNotGuessPartitionState(t *testing.T) {
	h, ctx := cookieFixture("camoufox")
	ctx.plain = []playwright.Cookie{{Name: "fixture", Value: "private", Domain: "example.test", Path: "/", Expires: -1}}
	r := httptest.NewRecorder()
	h.listSiteCookies(r, linkRequest(siteRequest("")))
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"canClear":false`) || !strings.Contains(r.Body.String(), `"partitionState":"unavailable"`) || strings.Contains(r.Body.String(), "private") {
		t.Fatal(r.Body.String())
	}
	r = httptest.NewRecorder()
	h.clearSiteCookies(r, linkRequest(siteRequest("example.test")))
	if r.Code != 501 || ctx.opened != 0 {
		t.Fatal("Firefox used unsafe broad fallback")
	}
}
func TestSiteCookieStaleAndInvalidRequestsNeverTouchContext(t *testing.T) {
	for _, body := range []string{`{}`, `{"instance_id":"old","domain":".example.test"}`, siteRequest(".example.test") + `{}`, `{"instance_id":"` + strings.Repeat("a", 32) + `","domain":"example.test","extra":true}`} {
		h, ctx := cookieFixture("cloakbrowser")
		r := httptest.NewRecorder()
		h.clearSiteCookies(r, linkRequest(body))
		if r.Code < 400 || ctx.opened != 0 {
			t.Fatal("invalid request reached context")
		}
	}
	h, ctx := cookieFixture("cloakbrowser")
	setGuardedLinkField(h.mgr, "sessions", map[string]*browser.Session{"sess_fixture": {ID: "sess_fixture", InstanceID: strings.Repeat("c", 32), Context: ctx}})
	r := httptest.NewRecorder()
	h.clearSiteCookies(r, linkRequest(siteRequest(".example.test")))
	if r.Code != 409 || ctx.opened != 0 {
		t.Fatal("stale inventory mutated newer session")
	}
}
func TestSiteCookiePartialFailureReturnsNoRawError(t *testing.T) {
	h, ctx := cookieFixture("cloakbrowser")
	ctx.cdp.failDelete = true
	r := httptest.NewRecorder()
	h.clearSiteCookies(r, linkRequest(siteRequest(".example.test")))
	if r.Code != 503 || !strings.Contains(r.Body.String(), "SITE_DATA_CLEAR_INCOMPLETE") || strings.Contains(r.Body.String(), "private backend") || !ctx.cdp.detached {
		t.Fatal(r.Body.String())
	}
}
