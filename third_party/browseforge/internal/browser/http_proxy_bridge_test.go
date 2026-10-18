package browser

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
)

func authenticatedHTTPBridge() *profile.ProxyConfig {
	return &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427, Username: "fixture-user", Password: "fixture-password"}
}

func TestDesktopHTTPProxyBridgeRejectsRawLaunchBeforeReuseOrRuntime(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		for _, proxyType := range []string{"http", "https"} {
			t.Run(runtimeID+"/"+proxyType, func(t *testing.T) {
				calls := 0
				manager := &Manager{
					cfg:                 &config.Config{EnforceHTTPProxyBridge: true},
					sessions:            map[string]*Session{"existing": {ID: "existing", ProfileID: "fixture", ConnectURL: "ws://test/existing"}},
					endpointHealthCheck: func(string, float64) error { calls++; return nil },
				}
				p := &profile.Profile{ID: "fixture", RuntimeID: runtimeID, Proxy: &profile.ProxyConfig{Type: proxyType, Host: "upstream.invalid", Port: 8443, Password: "fixture-upstream-secret"}}
				before, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				for _, launch := range []func(*profile.Profile) (*Session, error){manager.LaunchSession, manager.launchProfile} {
					_, err := launch(p)
					if ErrorCode(err) != "MANAGED_PROXY_REQUIRED" || !strings.Contains(err.Error(), "start it through Envara") {
						t.Fatalf("unbridged desktop launch was not refused: %v", err)
					}
					if strings.Contains(err.Error(), p.Proxy.Host) || strings.Contains(err.Error(), p.Proxy.Password) {
						t.Fatal("refusal disclosed stored proxy configuration")
					}
				}
				if calls != 0 || manager.profileLocks != nil || manager.activeOperations != 0 {
					t.Fatal("unbridged launch reached session health, reservation, or runtime")
				}
				p.SessionProxy = authenticatedHTTPBridge()
				if err := manager.validateManagedProxyLaunch(p); err != nil {
					t.Fatalf("authenticated bridge was refused: %v", err)
				}
				after, err := json.Marshal(p)
				if err != nil || !bytes.Equal(before, after) || p.ManagedProxyRequired {
					t.Fatal("runtime enforcement changed saved profile policy or exposed bridge credentials")
				}
			})
		}
	}
}

func TestDesktopHTTPProxyBridgeUsesStoredGroupPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, mode, groupType, ownType string
		requireBridge                  bool
	}{
		{"default inherited HTTP", groups.ProxyModeDefault, "http", "", true},
		{"enforced HTTP overrides SOCKS", groups.ProxyModeEnforced, "http", "socks5", true},
		{"default own HTTPS overrides SOCKS", groups.ProxyModeDefault, "socks5", "https", true},
		{"default own SOCKS overrides HTTP", groups.ProxyModeDefault, "http", "socks5", false},
		{"enforced SOCKS overrides HTTP", groups.ProxyModeEnforced, "socks5", "http", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := groups.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Upsert("Fixture", &profile.ProxyConfig{Type: tc.groupType, Host: "group.invalid", Port: 8080}, tc.mode); err != nil {
				t.Fatal(err)
			}
			p := &profile.Profile{ID: "fixture", Group: "Fixture"}
			if tc.ownType != "" {
				p.Proxy = &profile.ProxyConfig{Type: tc.ownType, Host: "profile.invalid", Port: 8080}
			}
			manager := &Manager{cfg: &config.Config{EnforceHTTPProxyBridge: true}, groupStore: store}
			if err := manager.validateManagedProxyLaunch(p); (ErrorCode(err) == "MANAGED_PROXY_REQUIRED") != tc.requireBridge {
				t.Fatalf("stored effective policy bridge requirement=%v: %v", tc.requireBridge, err)
			}
			p.SessionProxy = authenticatedHTTPBridge()
			if err := manager.validateManagedProxyLaunch(p); err != nil {
				t.Fatalf("managed group route was refused: %v", err)
			}
		})
	}
}

func TestDesktopHTTPProxyBridgeRequiresAuthenticatedLiteralLoopback(t *testing.T) {
	manager := &Manager{cfg: &config.Config{EnforceHTTPProxyBridge: true}}
	for _, tc := range []struct {
		name   string
		mutate func(*profile.ProxyConfig)
	}{
		{"missing username", func(p *profile.ProxyConfig) { p.Username = "" }},
		{"missing password", func(p *profile.ProxyConfig) { p.Password = "" }},
		{"hostname", func(p *profile.ProxyConfig) { p.Host = "localhost" }},
		{"remote", func(p *profile.ProxyConfig) { p.Host = "192.0.2.1" }},
		{"HTTPS listener", func(p *profile.ProxyConfig) { p.Type = "https" }},
		{"SOCKS listener", func(p *profile.ProxyConfig) { p.Type = "socks5" }},
		{"zero port", func(p *profile.ProxyConfig) { p.Port = 0 }},
		{"large port", func(p *profile.ProxyConfig) { p.Port = 65536 }},
		{"control username", func(p *profile.ProxyConfig) { p.Username = "fixture\r\nuser" }},
		{"Unicode control password", func(p *profile.ProxyConfig) { p.Password = "fixture\u0085password" }},
		{"oversized password", func(p *profile.ProxyConfig) { p.Password = strings.Repeat("p", 4097) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bridge := authenticatedHTTPBridge()
			tc.mutate(bridge)
			p := &profile.Profile{Proxy: &profile.ProxyConfig{Type: "http", Host: "upstream.invalid", Port: 8080}, SessionProxy: bridge}
			if err := manager.validateManagedProxyLaunch(p); ErrorCode(err) != "MANAGED_PROXY_REQUIRED" {
				t.Fatalf("invalid bridge was accepted: %v", err)
			}
		})
	}
}

func TestDesktopHTTPProxyBridgeLeavesStandaloneAndOtherRoutesUnchanged(t *testing.T) {
	for _, cfg := range []*config.Config{nil, {EnforceHTTPProxyBridge: false}} {
		manager := &Manager{cfg: cfg}
		for _, proxyType := range []string{"http", "https"} {
			if err := manager.validateManagedProxyLaunch(&profile.Profile{Proxy: &profile.ProxyConfig{Type: proxyType, Host: "upstream.invalid", Port: 8080}}); err != nil {
				t.Fatalf("standalone behavior changed: %v", err)
			}
		}
	}
	manager := &Manager{cfg: &config.Config{EnforceHTTPProxyBridge: true}}
	for _, proxy := range []*profile.ProxyConfig{nil, {Type: "socks5", Host: "upstream.invalid", Port: 1080}} {
		if err := manager.validateManagedProxyLaunch(&profile.Profile{Proxy: proxy}); err != nil {
			t.Fatalf("unrelated route behavior changed: %v", err)
		}
	}
	managed := &profile.Profile{ManagedProxyRequired: true}
	if err := manager.validateManagedProxyLaunch(managed); ErrorCode(err) != "MANAGED_PROXY_REQUIRED" {
		t.Fatal("existing AnyTLS requirement was removed")
	}
	managed.SessionProxy = &profile.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427}
	if err := manager.validateManagedProxyLaunch(managed); err != nil {
		t.Fatalf("existing AnyTLS bridge contract changed: %v", err)
	}
}
