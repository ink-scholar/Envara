package browser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
	"github.com/playwright-community/playwright-go"
)

type privacyHeadlessType struct {
	playwright.BrowserType
	binary string
}

func (b privacyHeadlessType) LaunchPersistentContext(dir string, options ...playwright.BrowserTypeLaunchPersistentContextOptions) (playwright.BrowserContext, error) {
	// Cocoa's locale shim adds a positional language argument, unsupported by
	// headless Chromium. The fixture uses the same native binary directly; all
	// other production options and privacy installation remain unchanged.
	if strings.HasSuffix(*options[0].ExecutablePath, ".sh") {
		options[0].ExecutablePath = playwright.String(b.binary)
	}
	options[0].Headless = playwright.Bool(true)
	options[0].Timeout = playwright.Float(25000)
	options[0].IgnoreHttpsErrors = playwright.Bool(true)
	return b.BrowserType.LaunchPersistentContext(dir, options...)
}

// Opt-in only. The Node fixture supplies an HTTP proxy that can only answer
// synthetic pages and WS/WSS handshakes on its own loopback listeners.
func TestPrivacyWebSocketLive(t *testing.T) {
	binary := os.Getenv("ENVARA_PRIVACY_GO_TEST_BROWSER")
	if binary == "" {
		t.Skip("local browser and loopback fixture required")
	}
	var fixture struct {
		Proxy string `json:"proxy"`
		WS    string `json:"ws"`
		WSS   string `json:"wss"`
	}
	if err := json.Unmarshal([]byte(os.Getenv("ENVARA_PRIVACY_WS_FIXTURE")), &fixture); err != nil {
		t.Fatal(err)
	}
	engine := os.Getenv("ENVARA_PRIVACY_GO_TEST_ENGINE")
	if engine != "cloakbrowser" && engine != "camoufox" && engine != "browseforge-chromium" {
		t.Fatal("explicit provider required")
	}
	pw, err := playwright.Run(&playwright.RunOptions{DriverDirectory: os.Getenv("ENVARA_PRIVACY_GO_DRIVER"), SkipInstallBrowsers: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Stop()
	pw.Firefox = privacyHeadlessType{pw.Firefox, binary}
	pw.Chromium = privacyHeadlessType{pw.Chromium, binary}
	parsed, err := url.Parse(fixture.Proxy)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(parsed.Port(), "%d", &port)
	for _, mode := range []string{"standard", "strict", "off"} {
		t.Run(mode, func(t *testing.T) {
			enabled := true
			cfg := &config.Config{NoSandbox: true, Runtimes: map[string]config.RuntimeConfig{engine: {BinaryPath: binary, Enabled: &enabled}}}
			manager := &Manager{cfg: cfg, runtimes: bfruntime.NewRegistry(cfg), pw: pw}
			p := &profile.Profile{ID: "owned-websocket-fixture-" + mode, Name: "Owned WebSocket fixture", RuntimeID: engine, ProfileDir: t.TempDir(), FingerprintSeed: 170042,
				Identity: &profile.IdentityConfig{TargetOS: "macos"}, Fingerprint: map[string]any{"screen.width": 1440, "screen.height": 900},
				LaunchOverrides:    &profile.LaunchOverrides{TargetOS: "macos", Timezone: "America/New_York", Locale: "en-US"},
				SessionCountryCode: "US", SessionPrivacy: &profile.PrivacyConfig{Mode: mode}, SessionGeolocation: &profile.Geolocation{Latitude: 0, Longitude: 0, Accuracy: 50000},
				SessionProxy: &profile.ProxyConfig{Type: "http", Host: parsed.Hostname(), Port: port, Region: "us-ny"}}
			var session *Session
			if engine == "camoufox" {
				session, err = manager.launchFirefox(p)
			} else {
				session, err = manager.launchChromium(p)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.closeSessionResources(session, "owned WebSocket fixture complete") })
			read := func(page playwright.Page) string {
				handle, err := page.WaitForFunction(`() => document.documentElement.dataset.wsResult`, nil, playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(5000)})
				if err != nil {
					t.Fatal(err)
				}
				defer handle.Dispose()
				result, err := handle.JSONValue()
				if err != nil {
					t.Fatal(err)
				}
				value, _ := result.(string)
				return value
			}
			blockedResult := "closed"
			if engine == "cloakbrowser" {
				blockedResult = "SecurityError"
			}
			if engine == "camoufox" {
				blockedResult = "error"
			}
			for _, scheme := range []string{"ws", "wss"} {
				base := fixture.WS
				if scheme == "wss" {
					base = fixture.WSS
				}
				for _, check := range []struct {
					host, first string
					blocked     bool
				}{
					{"api.segment.io", "example.test", mode != "off"}, {"api.segment.io", "app.segment.com", false}, {"api.mixpanel.com", "example.test", mode == "strict"}, {"chat.example.test", "example.test", false},
				} {
					name := fmt.Sprintf("go-%s-%s-%s-%s-%s", engine, mode, scheme, check.host, check.first)
					target := strings.Replace(base, "HOST", check.host, 1) + "/" + name
					if _, err := session.Page.Goto("http://" + check.first + "/?socket=" + url.QueryEscape(target)); err != nil {
						t.Fatal(err)
					}
					want := "hello"
					if check.blocked {
						want = blockedResult
					}
					if got := read(session.Page); got != want {
						t.Fatalf("%s: got %q want %q", name, got, want)
					}
				}
				for _, frameHost := range []string{"example.test", "chat.example.test"} {
					name := fmt.Sprintf("go-%s-%s-%s-frame-%s", engine, mode, scheme, frameHost)
					target := strings.Replace(base, "HOST", "api.segment.io", 1) + "/" + name
					frameURL := "http://" + frameHost + "/?socket=" + url.QueryEscape(target)
					if _, err := session.Page.Goto("http://example.test/?frame=" + url.QueryEscape(frameURL)); err != nil {
						t.Fatal(err)
					}
					var child playwright.Frame
					for _, frame := range session.Page.Frames() {
						if frame.URL() == frameURL {
							child = frame
							break
						}
					}
					if child == nil {
						t.Fatal("fixture frame missing")
					}
					handle, err := child.WaitForFunction(`() => document.documentElement.dataset.wsResult`, nil, playwright.FrameWaitForFunctionOptions{Timeout: playwright.Float(5000)})
					if err != nil {
						t.Fatal(err)
					}
					got, err := handle.JSONValue()
					handle.Dispose()
					if err != nil {
						t.Fatal(err)
					}
					want := blockedResult
					if mode == "off" {
						want = "hello"
					}
					if got != want {
						t.Fatalf("%s: got %q want %q", name, got, want)
					}
				}
				nameNative := fmt.Sprintf("go-%s-%s-%s-native", engine, mode, scheme)
				nativeURL := strings.Replace(base, "HOST", "chat.example.test", 1) + "/" + nameNative
				if _, err := session.Page.Goto("http://example.test/?native=" + url.QueryEscape(nativeURL)); err != nil {
					t.Fatal(err)
				}
				var proof map[string]any
				if err := json.Unmarshal([]byte(read(session.Page)), &proof); err != nil {
					t.Fatal(err)
				}
				if proof["instance"] != true || proof["prototype"] != true || proof["constructor"] != true || proof["binaryType"] != "arraybuffer" || proof["protocol"] != "fixture-echo" || proof["code"] != float64(1000) {
					t.Fatalf("%s: native socket API altered: %+v", nameNative, proof)
				}
				events, _ := json.Marshal(proof["events"])
				constants, _ := json.Marshal(proof["constants"])
				if string(events) != `["open","hello","ping","close"]` || string(constants) != `[0,1,2,3]` {
					t.Fatalf("%s: native events/constants altered: %+v", nameNative, proof)
				}
				// Inline first-party popup socket: no registration race may turn
				// an exempt service connection into an unknown-party refusal.
				name := fmt.Sprintf("go-%s-%s-%s-popup-first", engine, mode, scheme)
				target := strings.Replace(base, "HOST", "api.segment.io", 1) + "/" + name
				popupURL := "http://app.segment.com/?socket=" + url.QueryEscape(target)
				if _, err := session.Page.Goto("http://example.test/?popup=" + url.QueryEscape(popupURL)); err != nil {
					t.Fatal(err)
				}
				popup, err := session.Page.ExpectPopup(func() error { return session.Page.Locator("#popup").Click() })
				if err != nil {
					t.Fatal(err)
				}
				if got := read(popup); got != "hello" {
					t.Fatalf("%s: %s", name, got)
				}
				popup.Close()
				// Chromium resolves relative URLs against document.baseURI. The
				// pinned Firefox resolves them against the document URL;
				// preserve that native behavior, which targets example.test.
				// Its allowed result is not evidence of tracker blocking.
				name = fmt.Sprintf("go-%s-%s-%s-base", engine, mode, scheme)
				baseURL := strings.Replace(base, "HOST", "api.segment.io", 1)
				if _, err := session.Page.Goto("http://example.test/?base=" + url.QueryEscape(baseURL+"/") + "&socket=" + url.QueryEscape("/"+name)); err != nil {
					t.Fatal(err)
				}
				want := blockedResult
				if mode == "off" || engine == "camoufox" {
					want = "hello"
				}
				if got := read(session.Page); got != want {
					t.Fatalf("%s: got %q want %q", name, got, want)
				}
			}
			addonPath := ""
			if session.privacyAddon != nil {
				addonPath = session.privacyAddon.directory
			}
			manager.closeSessionResources(session, "owned WebSocket fixture complete")
			if addonPath != "" {
				if _, err := os.Stat(addonPath); !os.IsNotExist(err) {
					t.Fatal("owned addon was not removed")
				}
			}

		})
	}
}
