package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPProxyBridgeEnforcementIsRuntimeOnly(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"enforce_http_proxy_bridge":true}`,
		`{"EnforceHTTPProxyBridge":true}`,
		`{"enforceHTTPProxyBridge":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(filename, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(filename)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.EnforceHTTPProxyBridge {
				t.Fatal("saved JSON must not enable the process-only HTTP bridge guard")
			}
			cfg.EnforceHTTPProxyBridge = true
			encoded, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]any
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"enforce_http_proxy_bridge", "EnforceHTTPProxyBridge", "enforceHTTPProxyBridge"} {
				if _, exists := saved[key]; exists {
					t.Fatalf("runtime flag persisted as %q", key)
				}
			}
			var reloaded Config
			if err := json.Unmarshal(encoded, &reloaded); err != nil {
				t.Fatal(err)
			}
			if reloaded.EnforceHTTPProxyBridge {
				t.Fatal("runtime guard survived a JSON round trip")
			}
		})
	}
}

func TestLoadEmptyRuntimeRequiresExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{name: "missing config"},
		{name: "existing config", body: `{}`},
		{name: "desktop opt in", body: `{"allow_empty_runtime":true}`, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if tc.body != "" {
				if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AllowEmptyRuntime != tc.want {
				t.Fatalf("AllowEmptyRuntime = %v, want %v", cfg.AllowEmptyRuntime, tc.want)
			}
		})
	}
}
