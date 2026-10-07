package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
