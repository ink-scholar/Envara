package browser

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

func TestManagerEffectiveProxyUsesGroupStore(t *testing.T) {
	store, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080}, groups.ProxyModeEnforced); err != nil {
		t.Fatal(err)
	}
	m := &Manager{groupStore: store}

	effective := m.effectiveProxy(&profile.Profile{
		Group: "Client A",
		Proxy: &profile.ProxyConfig{Type: "http", Host: "profile.proxy", Port: 8080},
	})
	if effective.Source != "group" || effective.Proxy.Host != "group.proxy" {
		t.Fatalf("effective proxy = %+v", effective)
	}
}

func TestManagerManagedSessionProxyWinsEnforcedGroupWithoutChangingStoredPolicy(t *testing.T) {
	store, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080, Password: "group-password"}, groups.ProxyModeEnforced); err != nil {
		t.Fatal(err)
	}
	stored := &profile.Profile{Group: "Client A", Proxy: &profile.ProxyConfig{Type: "http", Host: "profile.proxy", Port: 8080}}
	before, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	launch := *stored
	launch.SessionProxy = &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427, Username: "managed-user", Password: "managed-password", Region: "us-ca"}
	manager := &Manager{groupStore: store}
	effective := manager.effectiveProxy(&launch)
	if effective.Source != "session" || effective.Proxy != launch.SessionProxy {
		t.Fatalf("managed session bypassed by stored group policy: source=%s", effective.Source)
	}
	groupEffective := manager.effectiveProxy(stored)
	if groupEffective.Source != "group" || groupEffective.Proxy.Host != "group.proxy" || groupEffective.Proxy.Password != "group-password" {
		t.Fatal("managed launch changed subsequent ordinary group policy")
	}
	after, err := json.Marshal(&launch)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SessionProxy != nil || !bytes.Equal(before, after) {
		t.Fatal("managed session proxy appeared in saved profile schema")
	}
	withoutGroups := (&Manager{}).effectiveProxy(&launch)
	if withoutGroups.Source != "session" || withoutGroups.Proxy.Host != "127.0.0.1" {
		t.Fatal("managed session proxy was ignored without a group store")
	}
}

func TestAllBrowserLaunchBuildersUseManagedSessionProxyAndPreserveStoredProfile(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(runtimeID, func(t *testing.T) {
			groupStore, err := groups.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := groupStore.Upsert("Enforced", &profile.ProxyConfig{Type: "http", Host: "group.invalid", Port: 8080, Password: "stored-group-password"}, groups.ProxyModeEnforced); err != nil {
				t.Fatal(err)
			}
			profileStore, err := profile.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			stored := &profile.Profile{Name: "Managed launch", RuntimeID: runtimeID, Group: "Enforced", ManagedProxyRequired: true, Proxy: &profile.ProxyConfig{Type: "socks5", Host: "profile.invalid", Port: 1080}, LaunchOverrides: &profile.LaunchOverrides{Timezone: "Asia/Tokyo", Locale: "ja-JP"}}
			if err := profileStore.Create(stored); err != nil {
				t.Fatal(err)
			}
			profilePath := filepath.Join(stored.ProfileDir, "profile.json")
			before, err := os.ReadFile(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			var launch profile.Profile
			if err := json.Unmarshal(before, &launch); err != nil {
				t.Fatal(err)
			}
			launch.SessionProxy = &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427, Username: "managed-user", Password: "managed-password", Region: "jp-tokyo"}
			launch.SessionCountryCode = "JP"
			binaryPath := filepath.Join(t.TempDir(), "test-browser")
			if err := os.WriteFile(binaryPath, nil, 0700); err != nil {
				t.Fatal(err)
			}
			enabled := true
			cfg := &config.Config{Runtimes: map[string]config.RuntimeConfig{runtimeID: {BinaryPath: binaryPath, Enabled: &enabled, Settings: &config.CloakBrowserConfig{TargetPlatformPolicy: "allow"}}}}
			capturedError := errors.New("captured runtime launch options")
			browserType := &capturingBrowserType{t: t, launchErr: capturedError}
			manager := &Manager{cfg: cfg, groupStore: groupStore, runtimes: bfruntime.NewRegistry(cfg), pw: &playwright.Playwright{Chromium: browserType, Firefox: browserType}}
			if _, err := manager.launchProfile(&launch); !errors.Is(err, capturedError) {
				t.Fatalf("builder failed before proxy options were captured: %v", err)
			}
			proxy := browserType.options.Proxy
			if browserType.calls != 1 || proxy == nil || proxy.Server != "http://127.0.0.1:19427" || proxy.Username == nil || *proxy.Username != "managed-user" || proxy.Password == nil || *proxy.Password != "managed-password" {
				t.Fatal("runtime builder passed stored group proxy instead of authenticated managed bridge")
			}
			after, err := os.ReadFile(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			inMemory, err := json.MarshalIndent(stored, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if stored.SessionProxy != nil || !bytes.Equal(before, after) || !bytes.Equal(before, inMemory) {
				t.Fatal("runtime builder changed stored profile or persisted managed credentials")
			}
		})
	}
}

func TestManagedProxyRequirementRejectsRawLaunchBeforeAnyRuntimeOrExistingSession(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(runtimeID, func(t *testing.T) {
			calls := 0
			manager := &Manager{
				sessions:              map[string]*Session{"existing": {ID: "existing", ProfileID: "managed", ConnectURL: "ws://test/existing"}},
				launchProfileOverride: func(*profile.Profile) (*Session, error) { calls++; return nil, errors.New("unexpected launcher") },
				endpointHealthCheck:   func(string, float64) error { calls++; return nil },
			}
			p := &profile.Profile{ID: "managed", RuntimeID: runtimeID, ManagedProxyRequired: true}
			if _, err := manager.LaunchSession(p); ErrorCode(err) != "MANAGED_PROXY_REQUIRED" {
				t.Fatalf("raw launch did not fail closed: %v", err)
			}
			if calls != 0 || manager.profileLocks != nil || manager.activeOperations != 0 {
				t.Fatal("raw launch reached session lookup, reservation, or runtime before managed guard")
			}
			// The lower-level dispatcher must also reject without resolving an
			// installed runtime or reading any browser executable.
			if _, err := manager.launchProfile(p); ErrorCode(err) != "MANAGED_PROXY_REQUIRED" {
				t.Fatalf("runtime dispatcher did not fail closed: %v", err)
			}
			p.SessionProxy = &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427}
			if err := validateManagedProxyLaunch(p); err != nil {
				t.Fatalf("managed bridge was rejected: %v", err)
			}
		})
	}
}
