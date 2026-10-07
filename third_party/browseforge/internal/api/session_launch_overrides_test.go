package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"browseforge/internal/browser"
	"browseforge/internal/profile"

	"github.com/mxschmitt/playwright-go"
)

type sessionLaunchPage struct{ playwright.Page }

func (p *sessionLaunchPage) IsClosed() bool { return false }

func newSessionLaunchHandler(t *testing.T, overrides *profile.LaunchOverrides) (*handler, *profile.Profile, **profile.Profile, *int) {
	t.Helper()
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stored := &profile.Profile{
		Name: "Automatic timezone profile", RuntimeID: "cloakbrowser", LaunchOverrides: overrides,
		Identity:        &profile.IdentityConfig{TargetOS: "linux", BrowserMajor: 145},
		Fingerprint:     map[string]any{"timezone": "America/Los_Angeles", "screen.width": 1440, "nested": map[string]any{"keep": "original"}},
		FingerprintSeed: 425179, Tags: []string{"keep"},
		Proxy: &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 1080, Username: "test-user", Password: "test-password"},
	}
	if err := store.Create(stored); err != nil {
		t.Fatal(err)
	}
	mgr := &browser.Manager{}
	var captured *profile.Profile
	calls := 0
	setField := func(name string, value any) {
		field := reflect.ValueOf(mgr).Elem().FieldByName(name)
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
	}
	setField("launchProfileOverride", func(p *profile.Profile) (*browser.Session, error) {
		captured = p
		calls++
		return &browser.Session{ID: "sess_" + p.ID, ProfileID: p.ID, RuntimeID: p.RuntimeID, Page: &sessionLaunchPage{}, ConnectURL: "ws://test/session"}, nil
	})
	setField("bindSessionEndpoint", func(session *browser.Session) (string, error) { return session.ConnectURL, nil })
	setField("endpointHealthCheck", func(string, float64) error { return nil })
	t.Cleanup(mgr.Close)
	return &handler{store: store, mgr: mgr}, stored, &captured, &calls
}

func TestSessionTimezoneIsEphemeralAndPreservesProfileConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name            string
		stored          *profile.LaunchOverrides
		requestTimezone string
	}{
		{"automatic", nil, "Asia/Singapore"},
		{"fixed locale and target OS", &profile.LaunchOverrides{Locale: "zh-CN", TargetOS: "windows"}, "Asia/Tokyo"},
		{"stored manual timezone remains unchanged", &profile.LaunchOverrides{Timezone: "UTC", Locale: "en-US", TargetOS: "macos"}, "Asia/Shanghai"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, stored, captured, calls := newSessionLaunchHandler(t, tc.stored)
			path := filepath.Join(stored.ProfileDir, "profile.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			body := `{"profile_id":"` + stored.ID + `","launch_overrides":{"timezone":"` + tc.requestTimezone + `"}}`
			h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body)))
			if rec.Code != http.StatusCreated || *calls != 1 {
				t.Fatalf("launch=%d calls=%d %s", rec.Code, *calls, rec.Body.String())
			}
			launch := *captured
			if launch == stored || launch.LaunchOverrides == nil || launch.LaunchOverrides.Timezone != tc.requestTimezone {
				t.Fatalf("timezone was not applied to a separate launch profile: %+v", launch)
			}
			if tc.stored != nil && (launch.LaunchOverrides.Locale != tc.stored.Locale || launch.LaunchOverrides.TargetOS != tc.stored.TargetOS) {
				t.Fatalf("launch lost stored locale/OS: %+v", launch.LaunchOverrides)
			}
			if launch.FingerprintSeed != stored.FingerprintSeed || launch.Proxy.Password != stored.Proxy.Password || launch.Identity.BrowserMajor != stored.Identity.BrowserMajor {
				t.Fatal("launch lost fingerprint, proxy, or identity settings")
			}
			// Mutating every nested launch value must not alter stored metadata.
			launch.LaunchOverrides.Timezone = "Europe/London"
			launch.Proxy.Password = "changed"
			launch.Identity.TargetOS = "windows"
			launch.Tags[0] = "changed"
			launch.Fingerprint["nested"].(map[string]any)["keep"] = "changed"
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			inMemory, err := json.MarshalIndent(stored, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !bytes.Equal(before, inMemory) {
				t.Fatal("ephemeral launch changed persisted or in-memory profile configuration")
			}
		})
	}
}

func TestSessionLaunchWithoutOverridesKeepsLegacyBehavior(t *testing.T) {
	h, stored, captured, calls := newSessionLaunchHandler(t, nil)
	rec := httptest.NewRecorder()
	h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`"}`)))
	if rec.Code != http.StatusCreated || *calls != 1 || (*captured).LaunchOverrides != nil || stored.LaunchOverrides != nil {
		t.Fatalf("legacy launch changed automatic values: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSessionLaunchRejectsInvalidTimezoneOrConfigurationInjection(t *testing.T) {
	h, stored, _, calls := newSessionLaunchHandler(t, &profile.LaunchOverrides{Locale: "zh-CN"})
	for _, override := range []string{
		`null`, `{}`, `[]`, `"UTC"`, `{"timezone":""}`, `{"timezone":null}`, `{"timezone":42}`,
		`{"timezone":"Local"}`, `{"timezone":"Mars/Olympus"}`, `{"timezone":" Asia/Shanghai"}`,
		`{"Timezone":"UTC"}`, `{"locale":"en-US"}`, `{"timezone":"UTC","locale":null}`,
		`{"timezone":"UTC","target_os":null}`, `{"timezone":"UTC","proxy":null}`,
	} {
		t.Run(override, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`","launch_overrides":`+override+`}`)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"INVALID_LAUNCH_OVERRIDES"`) || *calls != 0 {
				t.Fatalf("invalid override reached launcher: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
			}
		})
	}
	for _, body := range []string{
		`{"profile_id":"` + stored.ID + `","proxy":null}`,
		`{"profile_id":"` + stored.ID + `","fingerprint":null}`,
		`{"profile_id":"` + stored.ID + `","launch_overrides":{"timezone":"UTC"}} {"proxy":null}`,
	} {
		rec := httptest.NewRecorder()
		h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest || *calls != 0 {
			t.Fatalf("unknown/trailing configuration reached launcher: %d %s", rec.Code, rec.Body.String())
		}
	}
}
