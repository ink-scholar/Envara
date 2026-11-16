package browser

import (
	"errors"
	"testing"

	"github.com/playwright-community/playwright-go"
)

type backgroundTestContext struct {
	*desktopTestContext
	owned         *linkTestPage
	unrelated     *linkTestPage
	onCreate      func()
	created       int
	closedTargets []string
}
type backgroundTestCDP struct {
	playwright.CDPSession
	context  *backgroundTestContext
	targetID string
}

func (c *backgroundTestContext) NewCDPSession(page any) (playwright.CDPSession, error) {
	targetID := "existing"
	if page == c.owned {
		targetID = "owned-target"
	}
	if page == c.unrelated {
		targetID = "user-target"
	}
	return &backgroundTestCDP{context: c, targetID: targetID}, nil
}
func (c *backgroundTestCDP) Detach() error { return nil }
func (c *backgroundTestCDP) Send(method string, params map[string]any) (any, error) {
	switch method {
	case "Target.getTargetInfo":
		return map[string]any{"targetInfo": map[string]any{"targetId": c.targetID, "browserContextId": "owned-context"}}, nil
	case "Target.createTarget":
		if params["background"] != true || params["browserContextId"] != "owned-context" || params["url"] != "about:blank" {
			return nil, errors.New("not a pinned background target")
		}
		c.context.created++
		// A concurrent user tab must not be mistaken for the owned target.
		c.context.pages = append(c.context.pages, c.context.unrelated, c.context.owned)
		if c.context.onCreate != nil {
			c.context.onCreate()
		}
		return map[string]any{"targetId": "owned-target"}, nil
	case "Target.closeTarget":
		c.context.closedTargets = append(c.context.closedTargets, params["targetId"].(string))
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

func TestRuntimeVerificationPageKeepsSelectedPageAndRejectsDirectRoute(t *testing.T) {
	m, s, ctx := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest = "instance", "proxy-route"
	s.RuntimeID = "cloakbrowser"
	selected := &desktopTestPage{}
	s.Page = selected
	owned := &linkTestPage{desktopTestPage: &desktopTestPage{}}
	ctx.pages = []playwright.Page{selected}
	background := &backgroundTestContext{desktopTestContext: ctx, owned: owned, unrelated: &linkTestPage{desktopTestPage: &desktopTestPage{}}}
	s.Context = background
	page, err := m.NewRuntimeVerificationPage(s.ID, s.InstanceID, s.routeDigest)
	if err != nil || page != owned || s.Page != selected || owned.focuses != 0 || selected.focuses != 0 {
		t.Fatal("verification changed the selected page")
	}
	s.routeDigest = SessionRouteDigest(nil)
	if _, err := m.NewRuntimeVerificationPage(s.ID, s.InstanceID, s.routeDigest); !errors.Is(err, ErrSessionLinkChanged) {
		t.Fatal("direct route accepted")
	}
	if background.created != 1 || background.unrelated.closes != 0 {
		t.Fatal("refused request created a page")
	}
}

func TestRuntimeVerificationPageClosesOwnedPageIfLaunchChangesDuringCreation(t *testing.T) {
	m, s, ctx := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest = "instance", "proxy-route"
	s.RuntimeID = "browseforge-chromium"
	owned := &linkTestPage{desktopTestPage: &desktopTestPage{}}
	ctx.pages = []playwright.Page{&desktopTestPage{}}
	background := &backgroundTestContext{desktopTestContext: ctx, owned: owned, unrelated: &linkTestPage{desktopTestPage: &desktopTestPage{}}, onCreate: func() {
		m.mu.Lock()
		m.sessions[s.ID] = &Session{ID: s.ID}
		m.mu.Unlock()
	}}
	s.Context = background
	if _, err := m.NewRuntimeVerificationPage(s.ID, s.InstanceID, s.routeDigest); !errors.Is(err, ErrSessionLinkChanged) || len(background.closedTargets) != 1 || background.closedTargets[0] != "owned-target" || background.unrelated.closes != 0 {
		t.Fatal("stale page retained")
	}
}

func TestRuntimeVerificationDoesNotOpenForegroundTabsForUnsupportedEngines(t *testing.T) {
	m, s, _ := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest, s.RuntimeID = "instance", "proxy-route", "camoufox"
	if _, err := m.NewRuntimeVerificationPage(s.ID, s.InstanceID, s.routeDigest); !errors.Is(err, ErrRuntimeVerificationUnsupported) {
		t.Fatal("unsupported engine accepted")
	}
}
