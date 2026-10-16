package mcp

import (
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
)

func TestMCPProfileCreationPersistsGeneratedProviderIdentity(t *testing.T) {
	for _, provider := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(provider, func(t *testing.T) {
			enabled := true
			dir := t.TempDir()
			store, err := profile.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			server := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{provider: {Enabled: &enabled}}}), humanize.Config{}, nil, "", "test")
			if _, err := server.toolCreateProfile(map[string]any{"name": "Owned MCP identity", "runtime_id": provider}); err != nil {
				t.Fatal(err)
			}
			profiles := store.List("", "")
			if len(profiles) != 1 || profiles[0].FingerprintGeneration == nil || profiles[0].FingerprintGeneration.Provider != provider || len(profiles[0].Fingerprint) == 0 {
				t.Fatal("MCP skipped the canonical identity generator")
			}
			p := profiles[0]
			if provider != "camoufox" && p.FingerprintSeed == 0 {
				t.Fatal("MCP stored a seed provider without a saved seed")
			}
			if provider == "camoufox" && p.FingerprintSeed != 0 {
				t.Fatal("Camoufox acquired an unsupported Chromium seed")
			}
			reloaded, err := profile.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := reloaded.Get(p.ID)
			if err != nil || loaded.FingerprintSeed != p.FingerprintSeed || loaded.FingerprintGeneration.TupleID != p.FingerprintGeneration.TupleID {
				t.Fatal("MCP identity changed on store reload")
			}
		})
	}
}

func TestMCPDefaultProfileKeepsGeneratedIdentityOnReuse(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := &SessionPool{
		mgr:   testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{"browseforge-chromium": {Enabled: &enabled}}}),
		store: store, pools: map[string]*ProfileSessionPool{},
	}
	id, err := pool.GetOrCreateDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.Get(id)
	if err != nil || p.FingerprintSeed == 0 || p.FingerprintGeneration == nil {
		t.Fatal("default MCP browser lacks a generated identity")
	}
	seed, tuple := p.FingerprintSeed, p.FingerprintGeneration.TupleID
	again, err := pool.GetOrCreateDefaultProfile()
	if err != nil || again != id || p.FingerprintSeed != seed || p.FingerprintGeneration.TupleID != tuple {
		t.Fatal("reusing the MCP default changed its identity")
	}
}
