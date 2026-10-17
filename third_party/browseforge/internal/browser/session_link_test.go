package browser

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"browseforge/internal/profile"
	"github.com/mxschmitt/playwright-go"
)

type linkTestContext struct {
	*desktopTestContext
	newPage func() (playwright.Page, error)
}

func (c *linkTestContext) NewPage() (playwright.Page, error) { return c.newPage() }

type linkTestPage struct {
	*desktopTestPage
	closes int
}

func (p *linkTestPage) Close(...playwright.PageCloseOptions) error { p.closes++; return nil }

func TestSessionRouteDigestUsesExactLaunchCredentialsAndNormalizesHost(t *testing.T) {
	proxy := &profile.ProxyConfig{Type: "HTTP", Host: "[::1]", Port: 18452, Username: "fixture-用户名", Password: "a:<>&\u2028"}
	got := SessionRouteDigest(proxy)
	// Shared UTF-8 vector checked independently by the desktop fixture.
	if got != "d8bb7ea0644b32b8520f0a82447b41a1170edd0782fe47792ea72a97366944f9" {
		t.Fatalf("route contract mismatch: %s", got)
	}
	proxy.Type, proxy.Host = "http", "::1"
	if SessionRouteDigest(proxy) != got {
		t.Fatal("equivalent host/type changed route")
	}
	proxy.Password += "!"
	if SessionRouteDigest(proxy) == got || SessionRouteDigest(nil) == got {
		t.Fatal("different route reused digest")
	}
}

func TestSessionRouteDigestSharedHostVectors(t *testing.T) {
	// Independently calculated fixed hashes are also checked through the desktop's
	// production identity validation. Unicode host spelling must remain exact.
	for _, fixture := range []struct {
		name, host, username, password, otherHost, want string
	}{
		{"unicode-dotted-I", "İ.example", "fixture-user", "fixture-password", "i\u0307.example", "8717aaa6eea033aa60d3b39da990d4988be7004e4ab2e6147fe33e580250f6c1"},
		{"unicode-greek-sigma", "ΟΣ.example", "fixture-user", "fixture-password", "ος.example", "a55ae542bbdebc738c2b55cfa0673ac044de5d232c01f111f90d952777233a31"},
		{"ascii-host", "PrOxY.ExAmPlE", "fixture-user", "fixture-password", "", "7ba9b565cc608c5a4f81de2eea67118c9be06b88011ce600f12b59acd21f3916"},
		{"ipv6-host", "[::1]", "fixture-user", "fixture-password", "", "49d4611f53592b564b206536260bc34acefc60f0dfec2009cec008d4c7ff0496"},
		{"unicode-credentials", "[::1]", "fixture-用户名", "a:<>&\u2028", "", "d8bb7ea0644b32b8520f0a82447b41a1170edd0782fe47792ea72a97366944f9"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			proxy := &profile.ProxyConfig{Type: "HTTP", Host: fixture.host, Port: 18452, Username: fixture.username, Password: fixture.password}
			original := *proxy
			if got := SessionRouteDigest(proxy); got != fixture.want {
				t.Fatalf("route contract mismatch: got %s, want %s", got, fixture.want)
			}
			if *proxy != original {
				t.Fatal("digest calculation changed the actual proxy configuration")
			}
			if fixture.otherHost != "" {
				proxy.Host = fixture.otherHost
				if SessionRouteDigest(proxy) == fixture.want {
					t.Fatal("Unicode case mapping changed the route identity")
				}
			}
		})
	}
}

func TestSessionLinkRejectsChangedRouteAndReusedSessionIDBeforeCreatingPage(t *testing.T) {
	m, s, ctx := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest = "first-launch", "first-route"
	created := 0
	s.Context = &linkTestContext{desktopTestContext: ctx, newPage: func() (playwright.Page, error) {
		created++
		return &linkTestPage{desktopTestPage: &desktopTestPage{}}, nil
	}}
	for _, expected := range [][2]string{{"first-launch", "other-route"}, {"second-launch", "first-route"}, {"", ""}} {
		if _, err := m.NewSessionLinkPage(s.ID, expected[0], expected[1]); !errors.Is(err, ErrSessionLinkChanged) {
			t.Fatalf("changed launch accepted: %v", err)
		}
	}
	if created != 0 {
		t.Fatal("refused condition created a page")
	}
	identity, err := m.LinkIdentity(s.ID)
	if err != nil || identity.InstanceID != s.InstanceID || identity.RouteDigest != s.routeDigest {
		t.Fatal("identity does not describe the actual launch")
	}
}

func TestSessionLinkReplacementDuringPageCreationCannotSelectNewContext(t *testing.T) {
	m, s, ctx := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest = "first-launch", "first-route"
	page := &linkTestPage{desktopTestPage: &desktopTestPage{}}
	replacement := &Session{ID: s.ID, ProfileID: s.ProfileID, InstanceID: "new-launch", routeDigest: "new-route"}
	s.Context = &linkTestContext{desktopTestContext: ctx, newPage: func() (playwright.Page, error) {
		m.mu.Lock()
		m.sessions[s.ID] = replacement
		m.mu.Unlock()
		return page, nil
	}}
	if _, err := m.NewSessionLinkPage(s.ID, s.InstanceID, s.routeDigest); !errors.Is(err, ErrSessionLinkChanged) {
		t.Fatalf("replacement accepted: %v", err)
	}
	if page.closes != 1 || replacement.Page != nil {
		t.Fatal("stale creation changed the replacement context")
	}
}

func TestSessionLinkPageCreationDoesNotHoldRegistryOrPreventStop(t *testing.T) {
	m, s, ctx := testDesktopSession()
	defer m.Close()
	s.InstanceID, s.routeDigest = "first-launch", "first-route"
	started, release := make(chan struct{}), make(chan struct{})
	page := &linkTestPage{desktopTestPage: &desktopTestPage{}}
	s.Context = &linkTestContext{desktopTestContext: ctx, newPage: func() (playwright.Page, error) { close(started); <-release; return page, nil }}
	result := make(chan error, 1)
	go func() { _, err := m.NewSessionLinkPage(s.ID, s.InstanceID, s.routeDigest); result <- err }()
	<-started
	stopped := make(chan error, 1)
	go func() { stopped <- m.CloseSession(s.ID) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Stop blocked behind page creation")
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrSessionLinkChanged) {
		t.Fatalf("closed context accepted: %v", err)
	}
}

func TestSessionInstanceIDIsFreshForEachLaunchAndStableWhenReusing(t *testing.T) {
	m := newConcurrentManager(t)
	m.launchProfileOverride = func(p *profile.Profile) (*Session, error) { s, _ := newConcurrentSession(p.ID); return s, nil }
	p := &profile.Profile{ID: "nonce"}
	first, err := m.LaunchSession(p)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(first.InstanceID) {
		t.Fatal("launch lacks random identity")
	}
	reused, err := m.LaunchSession(p)
	if err != nil || reused.InstanceID != first.InstanceID {
		t.Fatal("healthy reused launch changed identity")
	}
	if err = m.CloseSession(first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := m.LaunchSession(p)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.InstanceID == first.InstanceID {
		t.Fatal("reused deterministic session ID retained the old launch identity")
	}
}
