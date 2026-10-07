package config

import (
	"os"
	"testing"
)

func TestLoadAppliesPublicBaseURLEnvWhenConfigMissing(t *testing.T) {
	t.Setenv("BROWSEFORGE_PUBLIC_BASE_URL", "https://bf.example.com/root/")
	cfg, err := Load(t.TempDir() + "/missing.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "https://bf.example.com/root" {
		t.Fatalf("PublicBaseURL = %q", cfg.PublicBaseURL)
	}
}

func TestLoadTrimsPublicBaseURLFromConfig(t *testing.T) {
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, []byte(`{"public_base_url":" https://bf.example.com/root/ "}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "https://bf.example.com/root" {
		t.Fatalf("PublicBaseURL = %q", cfg.PublicBaseURL)
	}
}
