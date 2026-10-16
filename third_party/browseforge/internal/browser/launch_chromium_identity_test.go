package browser

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

const staleMacChromiumUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.101 Safari/537.36"

func TestChromiumBrowserIdentityOwnershipIsProviderSpecific(t *testing.T) {
	t.Setenv("BROWSEFORGE_DOCKER_GPU_MODE", "native")
	p := &profile.Profile{
		ID: "provider-identity-boundary",
		Fingerprint: map[string]any{
			"navigator.userAgent":           staleMacChromiumUA,
			"navigator.hardwareConcurrency": 8,
			"navigator.deviceMemory":        8,
			"screen.width":                  1440,
			"screen.height":                 900,
		},
	}
	for _, id := range []bfruntime.ID{bfruntime.CloakBrowser, bfruntime.BrowseForgeChromium} {
		t.Run(string(id), func(t *testing.T) {
			persona, err := buildChromiumLaunchPersona(p, id, "MacIntel", "Asia/Manila", "en-US", "", "arm64", nil)
			if err != nil {
				t.Fatal(err)
			}
			browser := persona.Native.Browser
			if browser.Family != "chromium" {
				t.Fatalf("browser family=%q, want chromium", browser.Family)
			}
			if id == bfruntime.CloakBrowser {
				want := browseForgeNativeBrowserIdentity{Family: "chromium"}
				if !reflect.DeepEqual(browser, want) {
					t.Fatalf("Cloak's actual engine must own UA, version and hints; generated identity=%+v", browser)
				}
			} else {
				if browser.UserAgent != staleMacChromiumUA || browser.FullVersion != "150.0.7871.101" || browser.Major != 150 || len(browser.BrandVersions) == 0 || len(browser.FullVersionList) == 0 {
					t.Fatalf("BrowseForge's explicit native contract was dropped: %+v", browser)
				}
				if err := validateBrowseForgePersonaContract(persona.Native); err != nil {
					t.Fatalf("BrowseForge contract became incoherent: %v", err)
				}
			}
			if persona.Native.Locale.Timezone != "Asia/Manila" || persona.Native.Locale.Locale != "en-US" || persona.Native.Platform.OS != "macos" || persona.Native.Screen.Width != 1440 || persona.Native.Screen.Height != 900 {
				t.Fatalf("native identity ownership changed the selected context or screen: %+v", persona.Native)
			}
		})
	}
}

func TestCloakHTTPHeadersNeverOverrideNativeIdentityEvenForAStalePersona(t *testing.T) {
	persona, err := buildChromiumLaunchPersona(&profile.Profile{ID: "stale-hints"}, bfruntime.BrowseForgeChromium, "MacIntel", "UTC", "en-US", "", "arm64", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately keep populated UA/UA-CH fields while changing the provider:
	// old cached/generated values must not leak through the shared header helper.
	persona.Native.RuntimeID = string(bfruntime.CloakBrowser)
	headers := browseForgeChromiumHTTPHeaders(persona)
	want := map[string]string{"Accept-Language": persona.Native.Locale.AcceptLanguage}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("Cloak must retain native UA and Client Hints: headers=%#v, want %#v", headers, want)
	}
	persona.Native.RuntimeID = string(bfruntime.BrowseForgeChromium)
	headers = browseForgeChromiumHTTPHeaders(persona)
	for key, want := range map[string]string{
		"User-Agent":                  persona.Native.Browser.UserAgent,
		"Sec-CH-UA":                   persona.Native.Browser.ClientHints.SecCHUA,
		"Sec-CH-UA-Full-Version-List": persona.Native.Browser.ClientHints.SecCHUAFullVersion,
	} {
		if want == "" || headers[key] != want {
			t.Fatalf("BrowseForge contract header %s=%q, want nonempty %q", key, headers[key], want)
		}
	}
}

func TestCloakLaunchDoesNotForceStaleVersionAndPreservesSelectedNetworkAndDevice(t *testing.T) {
	for _, savedUA := range []string{staleMacChromiumUA, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36"} {
		t.Run(savedUA, func(t *testing.T) {
			enabled := true
			launchErr := errors.New("captured native identity launch")
			browserType := &capturingBrowserType{t: t, launchErr: launchErr}
			cfg := &config.Config{Runtimes: map[string]config.RuntimeConfig{
				"cloakbrowser": {BinaryPath: filepath.Join(t.TempDir(), "cloakbrowser"), Enabled: &enabled,
					Settings: &config.CloakBrowserConfig{FingerprintPlatform: "macos", TargetPlatformPolicy: "allow", ExtraArgs: []string{
						"--user-agent=" + savedUA,
						"--fingerprint-brand-version=150.0.7871.101",
						"--fingerprint-platform-version=99.0.0",
						"--disable-features=Translate",
					}}},
			}}
			manager := &Manager{cfg: cfg, runtimes: bfruntime.NewRegistry(cfg), pw: &playwright.Playwright{Chromium: browserType}, sessions: make(map[string]*Session)}
			p := &profile.Profile{
				ID: "cloak-native-identity", RuntimeID: "cloakbrowser", ProfileDir: t.TempDir(), FingerprintSeed: 42,
				LaunchOverrides: &profile.LaunchOverrides{Timezone: "Asia/Manila", Locale: "en-US", TargetOS: "macos"},
				Proxy:           &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 1080, Username: "fixture-user", Password: "fixture-password"},
				Fingerprint: map[string]any{
					"navigator.userAgent": savedUA, "navigator.languages": []any{"en-US", "en"},
					"navigator.hardwareConcurrency": 8, "navigator.deviceMemory": 8,
					"screen.width": 1440, "screen.height": 900, "screen.availWidth": 1440, "screen.availHeight": 860, "screen.devicePixelRatio": 2,
					"canvas:seed": 1234, "audio:seed": 5678,
				},
			}
			before, err := json.Marshal(p.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.launchChromium(p)
			if !errors.Is(err, launchErr) || browserType.calls != 1 {
				t.Fatalf("captured launch calls=%d, error=%v; want exactly the intercepted launch", browserType.calls, err)
			}
			opts := browserType.options
			for _, arg := range opts.Args {
				for _, prefix := range []string{"--user-agent=", "--fingerprint-user-agent=", "--fingerprint-ua-", "--fingerprint-sec-ch-", "--fingerprint-brand-version", "--fingerprint-platform-version"} {
					if strings.HasPrefix(arg, prefix) {
						t.Errorf("Cloak's native UA/Client Hints were overridden by %q", arg)
					}
				}
			}
			if opts.UserAgent != nil {
				t.Errorf("Playwright must not override native UserAgent: %q", *opts.UserAgent)
			}
			for name := range opts.ExtraHttpHeaders {
				key := strings.ToLower(name)
				if key == "user-agent" || strings.HasPrefix(key, "sec-ch-") {
					t.Errorf("Cloak must send its own native header %s, got %q", name, opts.ExtraHttpHeaders[name])
				}
			}
			wantLanguages := "en-US,en"
			if runtime.GOOS == "darwin" {
				wantLanguages = "en-US"
			}
			if opts.ExtraHttpHeaders["Accept-Language"] != wantLanguages {
				t.Errorf("selected Accept-Language lost: %#v", opts.ExtraHttpHeaders)
			}
			for _, expected := range []string{
				chromiumWebRTCIPHandlingArg, "--fingerprint=42", "--fingerprint-webrtc-ip=auto", "--disable-features=Translate",
				"--fingerprint-timezone=Asia/Manila", "--fingerprint-locale=en-US", "--fingerprint-platform=macos",
				"--fingerprint-accept-language=" + wantLanguages, "--accept-lang=" + wantLanguages,
				"--fingerprint-hardware-concurrency=8", "--fingerprint-device-memory=8",
				"--fingerprint-screen-width=1440", "--fingerprint-screen-height=900", "--fingerprint-screen-avail-width=1440", "--fingerprint-screen-avail-height=860",
				"--force-device-scale-factor=2", "--fingerprint-screen-device-scale-factor=2",
				"--window-position=0,0", "--window-size=1440,773",
				"--fingerprint-canvas-noise=1234", "--fingerprint-audio-noise=5678",
			} {
				if !containsArg(opts.Args, expected) {
					t.Errorf("selected context/device argument lost: %q; args=%v", expected, opts.Args)
				}
			}
			if opts.Proxy == nil || opts.Proxy.Server != "http://127.0.0.1:1080" || opts.Proxy.Username == nil || *opts.Proxy.Username != "fixture-user" || opts.Proxy.Password == nil || *opts.Proxy.Password != "fixture-password" {
				t.Errorf("selected authenticated route was changed: %#v", opts.Proxy)
			}
			if opts.Env["TZ"] != "Asia/Manila" || opts.Env["LANG"] != "en_US.UTF-8" || opts.Env["LC_ALL"] != "en_US.UTF-8" {
				t.Errorf("selected timezone/UTF-8 locale was changed: %#v", opts.Env)
			}
			if runtime.GOOS == "darwin" {
				if opts.Locale == nil || *opts.Locale != "en-US" {
					t.Errorf("regional ICU locale was lost: %#v", opts.Locale)
				}
				launcher, err := os.ReadFile(*opts.ExecutablePath)
				if err != nil || !strings.Contains(string(launcher), "-AppleLanguages '(en-US)'") {
					t.Errorf("native macOS locale launcher was lost: %v", err)
				}
			}
			after, err := json.Marshal(p.Fingerprint)
			if err != nil || string(before) != string(after) {
				t.Errorf("launch changed persisted profile fingerprint: %s -> %s (%v)", before, after, err)
			}
		})
	}
}

func TestChromiumExtraArgsCannotReintroduceAManagedUserAgentOrVersion(t *testing.T) {
	got := sanitizeExtraChromiumArgs([]string{
		"--user-agent=" + staleMacChromiumUA,
		"--user-agent",
		"--fingerprint-brand-version=150.0.7871.101",
		"--fingerprint-brand-version",
		"--fingerprint-platform-version=99.0.0",
		"--fingerprint-platform-version",
		"--disable-features=Translate",
	})
	want := []string{"--disable-features=Translate"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extra arguments can override the managed native identity: %#v, want %#v", got, want)
	}
}
