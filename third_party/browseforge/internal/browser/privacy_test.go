package browser

import (
	"browseforge/internal/profile"
	"sync"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

func TestTrackerHostRulesDoNotBreakLoginOrFirstParty(t *testing.T) {
	for _, raw := range []string{"https://www.google-analytics.com/g/collect", "https://stats.g.doubleclick.net/activity", "https://api.segment.io/v1/track"} {
		if !shouldBlockTracker(raw, "https://claude.ai/", "standard") {
			t.Fatalf("tracker allowed: %s", raw)
		}
	}
	for _, raw := range []string{"https://accounts.google.com/signin", "https://claude.ai/api/organizations", "https://api.anthropic.com/v1/messages", "https://google-analytics.com.evil.example/", "https://example.com/?tracker=google-analytics.com"} {
		if shouldBlockTracker(raw, "https://claude.ai/", "strict") {
			t.Fatalf("normal URL blocked: %s", raw)
		}
	}
	if shouldBlockTracker("https://api.segment.io/v1/track", "https://api.segment.io/settings", "standard") {
		t.Fatal("first party blocked")
	}
	if shouldBlockTracker("https://api.mixpanel.com/track", "https://example.com", "standard") || !shouldBlockTracker("https://api.mixpanel.com/track", "https://example.com", "strict") {
		t.Fatal("mode distinctions lost")
	}
	if shouldBlockTracker("https://api.segment.io/v1/track", "https://example.com", "off") {
		t.Fatal("off mode still intercepts")
	}
}

func TestPrivacyCountersAreAtomicAndSnapshotsDoNotExposeMutableLocation(t *testing.T) {
	state := &PrivacyState{Mode: "standard", Geolocation: &profile.Geolocation{Latitude: 14.6, Longitude: 121, Accuracy: 50000}}
	var work sync.WaitGroup
	for i := 0; i < 20; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			for j := 0; j < 100; j++ {
				state.BlockedRequests.Add(1)
			}
		}()
	}
	work.Wait()
	snapshot := state.Snapshot()
	if snapshot["blockedRequests"] != uint64(2000) {
		t.Fatal("counter lost events")
	}
	snapshot["geolocation"].(*profile.Geolocation).Latitude = 0
	if state.Geolocation.Latitude != 14.6 {
		t.Fatal("snapshot shares mutable geo")
	}
	if firefoxPrivacyPrefs("off", false)["geo.enabled"] != false {
		t.Fatal("off mode reveals real location")
	}
	if firefoxPrivacyPrefs("standard", true)["datareporting.healthreport.uploadEnabled"] != false {
		t.Fatal("telemetry still enabled")
	}
}

func TestTrackerExplicitServiceRootsPermitSiblingAPIs(t *testing.T) {
	permitted := []struct{ target, first, mode string }{
		{"https://api.segment.com/v1/sources", "https://app.segment.com/", "standard"},
		{"https://api.segment.io/v1/track", "https://app.segment.com/", "standard"},
		{"https://cdn.segment.com/script.js", "https://app.segment.io/", "standard"},
		{"https://api.mixpanel.com/query/events", "https://app.mixpanel.com/", "strict"},
		{"https://api.amplitude.com/api", "https://analytics.amplitude.com/", "strict"},
		{"https://sessions.bugsnag.com/", "https://app.bugsnag.com/", "strict"},
		{"https://browser-intake-datadoghq.eu/api", "https://app.datadoghq.eu/", "strict"},
		{"https://ingest.us.sentry.io/api", "https://project.sentry.io/", "strict"},
		{"https://static.hotjar.io/script.js", "https://insights.hotjar.com/", "strict"},
		{"https://stats.google-analytics.com/api", "https://www.google-analytics.com/", "standard"},
	}
	for _, check := range permitted {
		if shouldBlockTracker(check.target, check.first, check.mode) {
			t.Fatalf("same-service API blocked: %s -> %s", check.first, check.target)
		}
		if !shouldBlockTracker(check.target, "https://example.com/", check.mode) {
			t.Fatalf("outside site bypassed tracker rule: %s", check.target)
		}
	}
	for _, first := range []string{"https://app.segment.com.evil.example/", "https://notsegment.com/", "https://app-segment.com/", "https://app.segment.io.evil.example/", "https://segment.com@evil.example/", "https://example.com/?site=segment.com"} {
		if !shouldBlockTracker("https://api.segment.com/v1/sources", first, "standard") {
			t.Fatalf("hostname lookalike bypassed tracker rule: %s", first)
		}
	}
	if !shouldBlockTracker("https://api.mixpanel.com/query/events", "https://app.segment.com/", "strict") {
		t.Fatal("unrelated explicit service bypassed tracker rule")
	}
	if shouldBlockTracker("https://api.segment.com.evil.example/v1", "https://app.segment.com/", "standard") {
		t.Fatal("target hostname suffix confused with a tracker")
	}
}

type privacyFrameStub struct {
	playwright.Frame
	url    string
	parent playwright.Frame
}

func (f *privacyFrameStub) URL() string                   { return f.url }
func (f *privacyFrameStub) ParentFrame() playwright.Frame { return f.parent }

type privacyRequestStub struct {
	playwright.Request
	url        string
	frame      playwright.Frame
	navigation bool
}

func (r *privacyRequestStub) URL() string               { return r.url }
func (r *privacyRequestStub) Frame() playwright.Frame   { return r.frame }
func (r *privacyRequestStub) IsNavigationRequest() bool { return r.navigation }

func TestTrackerRequestPartyUsesTopNavigationDestination(t *testing.T) {
	top := &privacyFrameStub{url: "https://example.com/old-page"}
	child := &privacyFrameStub{url: "https://child.example.net/", parent: top}
	nested := &privacyFrameStub{url: "https://nested.example.net/", parent: child}
	target := "https://api.segment.io/settings"
	for _, check := range []struct {
		name       string
		frame      playwright.Frame
		navigation bool
		party      string
		blocked    bool
	}{
		{"top navigation", top, true, target, false},
		{"fetch", top, false, top.url, true},
		{"child navigation", child, true, top.url, true},
		{"nested navigation", nested, true, top.url, true},
		{"no frame", nil, true, "", true},
	} {
		t.Run(check.name, func(t *testing.T) {
			request := &privacyRequestStub{url: target, frame: check.frame, navigation: check.navigation}
			party := requestFirstParty(request)
			if party != check.party {
				t.Fatalf("first party = %q, want %q", party, check.party)
			}
			if shouldBlockTracker(target, party, "standard") != check.blocked {
				t.Fatalf("blocked should be %t for %s", check.blocked, check.name)
			}
		})
	}
}
