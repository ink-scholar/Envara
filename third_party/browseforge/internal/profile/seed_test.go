package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRandomFingerprintSeedRejectsZeroAndSourceSeed(t *testing.T) {
	var input bytes.Buffer
	for _, seed := range []uint32{0, 42, 7} {
		if err := binary.Write(&input, binary.BigEndian, seed); err != nil {
			t.Fatal(err)
		}
	}
	seed, err := randomFingerprintSeed(&input, 42)
	if err != nil || seed != 7 {
		t.Fatalf("seed = %d, error = %v; want 7", seed, err)
	}
	if seed, err := randomFingerprintSeed(bytes.NewReader([]byte{1}), 0); seed != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("entropy failure = %d, %v", seed, err)
	}
}

func TestCreatePersistsProviderSeedAndPreservesExplicitSeeds(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		for _, explicit := range []uint32{0, 1, ^uint32(0)} {
			t.Run(runtimeID+"/seed="+strconv.FormatUint(uint64(explicit), 10), func(t *testing.T) {
				dir := t.TempDir()
				store, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				p := &Profile{Name: "Owned identity", RuntimeID: runtimeID, FingerprintSeed: explicit}
				if err := store.Create(p); err != nil {
					t.Fatal(err)
				}
				if explicit != 0 && p.FingerprintSeed != explicit {
					t.Fatal("creation changed an explicit/imported seed")
				}
				if explicit == 0 && usesFingerprintSeed(runtimeID) && p.FingerprintSeed == 0 {
					t.Fatal("seed provider was stored without an identity seed")
				}
				if explicit == 0 && runtimeID == "camoufox" && p.FingerprintSeed != 0 {
					t.Fatal("structured provider acquired an unsupported seed")
				}
				reloaded, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := reloaded.Get(p.ID)
				if err != nil || loaded.FingerprintSeed != p.FingerprintSeed {
					t.Fatal("stored seed was not preserved on reload")
				}
			})
		}
	}
}

func TestLoadingLegacyZeroSeedDoesNotMigrateIdentity(t *testing.T) {
	dir := t.TempDir()
	namespace := filepath.Join(dir, "legacy-zero")
	if err := os.MkdirAll(filepath.Join(namespace, "browser-data"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &Profile{ID: "legacy-zero", Name: "Existing identity", RuntimeID: "cloakbrowser", ProfileDir: namespace,
		Fingerprint: map[string]any{"canvas:seed": 17, "navigator.hardwareConcurrency": 4}}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(namespace, "profile.json")
	if err := os.WriteFile(filename, before, 0o600); err != nil {
		t.Fatal(err)
	}
	cookies := filepath.Join(namespace, "browser-data", "Cookies")
	if err := os.WriteFile(cookies, []byte("owned login marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("loading an existing profile wrote an implicit migration")
	}
	updated, err := store.Update(p.ID, map[string]any{"name": "Edited label"})
	if err != nil || updated.FingerprintSeed != 0 || updated.Fingerprint["canvas:seed"] != float64(17) {
		t.Fatal("an unrelated edit changed an existing identity")
	}
	marker, err := os.ReadFile(cookies)
	if err != nil || string(marker) != "owned login marker" {
		t.Fatal("profile metadata edit changed browser login data")
	}
}

func TestDuplicateReseedsWithoutChangingSourceOrExplicitSettings(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium"} {
		t.Run(runtimeID, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			source := &Profile{Name: "Original", RuntimeID: runtimeID, FingerprintSeed: 42, ManagedProxyRequired: true,
				Identity: &IdentityConfig{TargetOS: "macos"}, LaunchOverrides: &LaunchOverrides{Locale: "en-US", Timezone: "Etc/UTC"},
				Fingerprint: map[string]any{"canvas:seed": 23, "screen.width": 1440, "nested": map[string]any{"keep": "original"}},
				Tags:        []string{"owned"}, Proxy: &ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427},
				SessionProxy: &ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19428}, SessionPrivacy: &PrivacyConfig{Mode: "strict"}, SessionCountryCode: "MY"}
			if err := store.Create(source); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(source.ProfileDir, "profile.json")
			before, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source.ProfileDir, "browser-data", "Cookies"), []byte("owned login marker"), 0o600); err != nil {
				t.Fatal(err)
			}
			duplicate, err := store.Duplicate(source.ID)
			if err != nil {
				t.Fatal(err)
			}
			if duplicate.FingerprintSeed == 0 || duplicate.FingerprintSeed == source.FingerprintSeed || source.FingerprintSeed != 42 {
				t.Fatal("duplicate did not receive a separate nonzero seed")
			}
			if !duplicate.ManagedProxyRequired || duplicate.SessionProxy != nil || duplicate.SessionPrivacy != nil || duplicate.SessionGeolocation != nil || duplicate.SessionCountryCode != "" {
				t.Fatal("duplicate lost its managed guard or copied transient authority")
			}
			if _, copiedNoise := duplicate.Fingerprint["canvas:seed"]; copiedNoise {
				t.Fatal("duplicate retained per-identity noise")
			}
			if duplicate.Fingerprint["screen.width"] != float64(1440) || duplicate.Identity.TargetOS != "macos" || duplicate.LaunchOverrides.Locale != "en-US" || duplicate.Proxy.Port != 19427 {
				t.Fatal("duplicate changed explicit settings")
			}
			entries, err := os.ReadDir(filepath.Join(duplicate.ProfileDir, "browser-data"))
			if err != nil || len(entries) != 0 {
				t.Fatal("duplicate copied existing browser data")
			}
			duplicate.Fingerprint["nested"].(map[string]any)["keep"] = "duplicate"
			duplicate.Identity.TargetOS = "windows"
			duplicate.Tags[0] = "duplicate"
			if source.Fingerprint["nested"].(map[string]any)["keep"] != "original" || source.Identity.TargetOS != "macos" || source.Tags[0] != "owned" {
				t.Fatal("duplicate shares mutable configuration with source")
			}
			after, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("duplicate changed the source profile on disk")
			}
		})
	}
}
