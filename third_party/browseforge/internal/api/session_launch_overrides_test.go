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

func TestSessionNonPersonaOverridesKeepAutomaticLaunchFieldsUnset(t *testing.T) {
	for _, raw := range []string{`{"privacy":{"mode":"strict"}}`, `{"geolocation":{"latitude":14.6,"longitude":121,"accuracy":50000}}`} {
		t.Run(raw, func(t *testing.T) {
			overrides, err := decodeSessionLaunchOverrides(json.RawMessage(raw))
			if err != nil {
				t.Fatal(err)
			}
			stored := &profile.Profile{FingerprintSeed: 425179}
			launch, err := profileForSessionLaunch(stored, overrides)
			if err != nil {
				t.Fatal(err)
			}
			if launch.LaunchOverrides != nil || stored.LaunchOverrides != nil || launch.FingerprintSeed != stored.FingerprintSeed {
				t.Fatal("non-persona override changed automatic launch fields or seed")
			}
			if stored.SessionPrivacy != nil || stored.SessionGeolocation != nil {
				t.Fatal("runtime override changed the stored profile")
			}
		})
	}
}

func TestSessionManagedProxyIsEphemeralAndPreservesStoredProxyAndPersona(t *testing.T) {
	for _, timezone := range []string{"", "Asia/Singapore"} {
		t.Run("timezone="+timezone, func(t *testing.T) {
			h, stored, captured, calls := newSessionLaunchHandler(t, &profile.LaunchOverrides{Timezone: "UTC", Locale: "zh-CN", TargetOS: "windows"})
			if _, err := h.store.Update(stored.ID, map[string]any{"group": "Enforced group"}); err != nil {
				t.Fatal(err)
			}
			stored, _ = h.store.Get(stored.ID)
			path := filepath.Join(stored.ProfileDir, "profile.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			overrides := map[string]any{"proxy": map[string]any{"type": "http", "host": "127.0.0.1", "port": 19427, "username": "managed-user", "password": "managed-password", "region": "us-ca"}}
			if timezone != "" {
				overrides["timezone"] = timezone
			}
			body, err := json.Marshal(map[string]any{"profile_id": stored.ID, "launch_overrides": overrides})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(body)))
			if rec.Code != http.StatusCreated || *calls != 1 {
				t.Fatalf("managed launch=%d calls=%d %s", rec.Code, *calls, rec.Body.String())
			}
			launch := *captured
			if launch == stored || launch.SessionProxy == nil || launch.SessionProxy.Type != "http" || launch.SessionProxy.Host != "127.0.0.1" || launch.SessionProxy.Port != 19427 || launch.SessionProxy.Username != "managed-user" || launch.SessionProxy.Password != "managed-password" || launch.SessionProxy.Region != "us-ca" {
				t.Fatal("managed bridge was not applied to a separate launch profile")
			}
			wantTimezone := "UTC"
			if timezone != "" {
				wantTimezone = timezone
			}
			if launch.Group != stored.Group || launch.LaunchOverrides.Timezone != wantTimezone || launch.LaunchOverrides.Locale != "zh-CN" || launch.LaunchOverrides.TargetOS != "windows" || !reflect.DeepEqual(launch.Proxy, stored.Proxy) || !reflect.DeepEqual(launch.Fingerprint, stored.Fingerprint) {
				t.Fatal("managed proxy replaced stored group, upstream proxy, timezone policy, or persona")
			}
			exported, err := json.Marshal(launch)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(exported, []byte("managed-password")) || bytes.Contains(exported, []byte("19427")) || bytes.Contains(rec.Body.Bytes(), []byte("managed-password")) {
				t.Fatal("transient proxy credentials appeared in profile export or session response")
			}
			launch.SessionProxy.Password = "changed"
			launch.Proxy.Password = "changed"
			launch.LaunchOverrides.Locale = "en-US"
			launch.Fingerprint["nested"].(map[string]any)["keep"] = "changed"
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			inMemory, err := json.MarshalIndent(stored, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if stored.SessionProxy != nil || !bytes.Equal(before, after) || !bytes.Equal(before, inMemory) {
				t.Fatal("managed proxy changed persisted or in-memory profile configuration")
			}
		})
	}
}

func TestSessionManagedProxyRejectsUnsupportedOrUnsafeFields(t *testing.T) {
	h, stored, _, calls := newSessionLaunchHandler(t, nil)
	for _, proxy := range []string{
		`null`, `{}`, `[]`, `"proxy"`,
		`{"type":"anytls","host":"127.0.0.1","port":19427}`,
		`{"type":"socks5","host":"127.0.0.1","port":19427}`,
		`{"type":"https","host":"127.0.0.1","port":19427}`,
		`{"type":"http","host":"localhost","port":19427}`,
		`{"type":"http","host":"::1","port":19427}`,
		`{"type":"http","host":"127.0.0.2","port":19427}`,
		`{"type":"http","host":"proxy.example","port":19427}`,
		`{"type":"http","host":"127.0.0.1","port":null}`,
		`{"type":"http","host":"127.0.0.1","port":0}`,
		`{"type":"http","host":"127.0.0.1","port":65536}`,
		`{"type":"http","host":"127.0.0.1","port":1.5}`,
		`{"type":"http","host":"127.0.0.1","port":"19427"}`,
		`{"type":"http","host":"127.0.0.1"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"username":null}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"password":false}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"password":"secret\r\nInjected: value"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"username":"secret\u0000"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"password":"secret\u007f"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"password":"` + strings.Repeat("x", 4097) + `"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"region":null}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"region":"https://proxy.example/secret"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"region":"` + strings.Repeat("x", 65) + `"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"server_name":"injected.example"}`,
		`{"type":"http","host":"127.0.0.1","port":19427,"Password":"secret"}`,
	} {
		rec := httptest.NewRecorder()
		h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`","launch_overrides":{"proxy":`+proxy+`}}`)))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"INVALID_LAUNCH_OVERRIDES"`) || *calls != 0 {
			t.Fatalf("invalid managed proxy reached launcher: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Fatal("invalid proxy response exposed credentials")
		}
	}
}

func TestSessionManagedProxyCloneDoesNotShareOverrideCredentials(t *testing.T) {
	overrides := &sessionLaunchOverrides{Proxy: &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427, Password: "managed-password"}}
	stored := &profile.Profile{RuntimeID: "cloakbrowser", SessionProxy: &profile.ProxyConfig{Password: "stale-ephemeral-password"}}
	launch, err := profileForSessionLaunch(stored, overrides)
	if err != nil {
		t.Fatal(err)
	}
	launch.SessionProxy.Password = "changed"
	if overrides.Proxy.Password != "managed-password" || stored.SessionProxy.Password != "stale-ephemeral-password" {
		t.Fatal("launch shares transient proxy pointer with request or stored profile")
	}
	legacy, err := profileForSessionLaunch(stored, nil)
	if err != nil || legacy.SessionProxy != nil {
		t.Fatal("legacy launch inherited stale transient state")
	}
}

func TestManagedProxySessionCannotLaunchDirectThroughREST(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(runtimeID, func(t *testing.T) {
			h, stored, captured, calls := newSessionLaunchHandler(t, nil)
			if _, err := h.store.Update(stored.ID, map[string]any{"runtime_id": runtimeID, "proxy": nil, "managed_proxy_required": true}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(stored.ProfileDir, "profile.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, extra := range []string{"", `,"launch_overrides":{"timezone":"Asia/Tokyo"}`} {
				rec := httptest.NewRecorder()
				h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`"`+extra+`}`)))
				if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"code":"MANAGED_PROXY_REQUIRED"`) || *calls != 0 {
					t.Fatalf("raw managed session reached launcher: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
				}
			}
			rec := httptest.NewRecorder()
			h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`","launch_overrides":{"timezone":"Asia/Tokyo","proxy":{"type":"http","host":"127.0.0.1","port":19427,"username":"managed-user","password":"managed-password"}}}`)))
			if rec.Code != http.StatusCreated || *calls != 1 || !(*captured).ManagedProxyRequired || (*captured).SessionProxy == nil {
				t.Fatalf("validated managed bridge failed launch: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !bytes.Contains(after, []byte(`"managed_proxy_required": true`)) || bytes.Contains(after, []byte("managed-password")) || stored.SessionProxy != nil {
				t.Fatal("REST launch changed durable managed flag or persisted transient credentials")
			}
		})
	}
}

func TestRESTProfileCreateAndUpdateAcceptManagedProxyBoolean(t *testing.T) {
	h := newDesktopHandler(t)
	rec := httptest.NewRecorder()
	h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Managed draft","runtime_id":"cloakbrowser","managed_proxy_required":true,"proxy":null}`)))
	if rec.Code != http.StatusCreated || len(h.store.List("", "")) != 1 {
		t.Fatalf("managed profile create=%d %s", rec.Code, rec.Body.String())
	}
	p := h.store.List("", "")[0]
	if !p.ManagedProxyRequired || !strings.Contains(rec.Body.String(), `"managed_proxy_required":true`) {
		t.Fatal("REST create ignored managed proxy boolean")
	}
	for _, want := range []bool{false, true} {
		body, err := json.Marshal(map[string]any{"managed_proxy_required": want})
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		h.updateProfile(rec, requestWithProfileID(http.MethodPut, "/api/profiles/"+p.ID, p.ID, bytes.NewReader(body)))
		if rec.Code != http.StatusOK || p.ManagedProxyRequired != want {
			t.Fatalf("managed profile update(%v)=%d %s", want, rec.Code, rec.Body.String())
		}
	}
}

func TestSessionLaunchRejectsInvalidTimezoneOrConfigurationInjection(t *testing.T) {
	h, stored, _, calls := newSessionLaunchHandler(t, &profile.LaunchOverrides{Locale: "zh-CN"})
	for _, override := range []string{
		`null`, `{}`, `[]`, `"UTC"`, `{"timezone":""}`, `{"timezone":null}`, `{"timezone":42}`,
		`{"timezone":"Local"}`, `{"timezone":"Mars/Olympus"}`, `{"timezone":" Asia/Shanghai"}`,
		`{"Timezone":"UTC"}`, `{"locale":"en_US"}`, `{"timezone":"UTC","locale":null}`,
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
