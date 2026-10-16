package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestChromiumFreshIdentityGeneratesAndPersistsDeviceTuple(t *testing.T) {
	for _, provider := range []string{"cloakbrowser", "browseforge-chromium"} {
		for _, targetOS := range []string{"macos", "windows", "linux"} {
			t.Run(provider+"/"+targetOS, func(t *testing.T) {
				dir := t.TempDir()
				store, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				first := &Profile{Name: "Fresh A", RuntimeID: provider, FingerprintSeed: 1, Identity: &IdentityConfig{TargetOS: targetOS}}
				second := &Profile{Name: "Fresh B", RuntimeID: provider, FingerprintSeed: 2, Identity: &IdentityConfig{TargetOS: targetOS}}
				for _, p := range []*Profile{first, second} {
					if err := store.Create(p); err != nil {
						t.Fatal(err)
					}
					generation := p.FingerprintGeneration
					if generation == nil || generation.Provider != provider || generation.Version != 1 || generation.TupleID == "" || len(generation.GeneratedFields) != 5 || len(p.Fingerprint) != 5 {
						t.Fatal("fresh identity lacks a versioned device tuple")
					}
					for _, key := range []string{"screen.width", "screen.height", "screen.devicePixelRatio", "navigator.hardwareConcurrency", "navigator.deviceMemory"} {
						if _, ok := p.Fingerprint[key]; !ok {
							t.Fatalf("missing device parameter %s", key)
						}
					}
				}
				if reflect.DeepEqual(first.Fingerprint, second.Fingerprint) {
					t.Fatal("different generator selections only changed the seed, not the device tuple")
				}
				before, err := os.ReadFile(filepath.Join(first.ProfileDir, "profile.json"))
				if err != nil {
					t.Fatal(err)
				}
				reloaded, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := reloaded.Get(first.ID)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := json.MarshalIndent(loaded, "", "  ")
				if err != nil || string(actual) != string(before) {
					t.Fatal("reload changed the saved identity or generation record")
				}
			})
		}
	}
}

func TestFreshIdentityPreservesExplicitFieldsAndCloneKeepsManualChanges(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Custom", RuntimeID: "cloakbrowser", FingerprintSeed: 1, Identity: &IdentityConfig{TargetOS: "macos"},
		Fingerprint: map[string]any{"screen.width": 1712, "navigator.hardwareConcurrency": 12, "webGl:vendor": "Owned GPU constraint", "fonts": []string{"Arial"}, "canvas:seed": 23, "audio:seed": 24, "fonts:spacing_seed": 25}}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint["screen.width"] != 1712 || p.Fingerprint["navigator.hardwareConcurrency"] != 12 || len(p.FingerprintGeneration.GeneratedFields) != 3 {
		t.Fatal("fresh generation changed explicit fields or recorded them as generated")
	}
	changed := make(map[string]any)
	for key, value := range p.Fingerprint {
		changed[key] = value
	}
	changed["screen.height"] = 777
	if _, err := store.Update(p.ID, map[string]any{"fingerprint": changed}); err != nil {
		t.Fatal(err)
	}
	if p.FingerprintGeneration == nil || len(p.FingerprintGeneration.GeneratedFields) != 0 {
		t.Fatal("explicit edits lost the versioned identity marker or retained generator ownership")
	}
	duplicate, err := store.Duplicate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Fingerprint["screen.width"] != float64(1712) || duplicate.Fingerprint["screen.height"] != float64(777) || duplicate.Fingerprint["navigator.hardwareConcurrency"] != float64(12) || duplicate.Fingerprint["webGl:vendor"] != "Owned GPU constraint" {
		t.Fatal("cloning discarded explicit hardware or a changed generated field")
	}
	for _, key := range []string{"screen.width", "screen.height", "navigator.hardwareConcurrency", "webGl:vendor", "fonts"} {
		if duplicate.FingerprintGeneration != nil {
			if _, regenerated := duplicate.FingerprintGeneration.GeneratedFields[key]; regenerated {
				t.Fatalf("manual field %s was claimed by the clone generator", key)
			}
		}
	}
	for _, key := range []string{"canvas:seed", "audio:seed", "fonts:spacing_seed"} {
		if _, retained := duplicate.Fingerprint[key]; retained {
			t.Fatalf("clone retained old noise input %s", key)
		}
	}
}

func TestExplicitSameValueEditTakesOwnershipButNotesKeepGeneration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Generated", RuntimeID: "cloakbrowser", FingerprintSeed: 1}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(p.FingerprintGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(p.ID, map[string]any{"tags": []string{"noted"}}); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(p.FingerprintGeneration)
	if err != nil || string(before) != string(after) {
		t.Fatal("unrelated edits discarded generation ownership")
	}
	width := p.Fingerprint["screen.width"]
	if _, err := store.Update(p.ID, map[string]any{"fingerprint": map[string]any{"screen.width": width}}); err != nil {
		t.Fatal(err)
	}
	if _, generated := p.FingerprintGeneration.GeneratedFields["screen.width"]; generated {
		t.Fatal("an explicit same-value edit remained generator-owned")
	}
	clone, err := store.Duplicate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(width)
	got, _ := json.Marshal(clone.Fingerprint["screen.width"])
	if string(got) != string(want) {
		t.Fatal("clone replaced an explicit same-value hardware constraint")
	}
	if _, generated := clone.FingerprintGeneration.GeneratedFields["screen.width"]; generated {
		t.Fatal("clone claimed ownership of an explicit hardware constraint")
	}
}

func TestUpdateRespectsSuppliedGenerationMetadata(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Generated", RuntimeID: "cloakbrowser", FingerprintSeed: 1}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	generation, err := json.Marshal(p.FingerprintGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(p.ID, map[string]any{"fingerprint": p.Fingerprint, "fingerprint_generation": p.FingerprintGeneration}); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(p.FingerprintGeneration)
	if err != nil || string(got) != string(generation) {
		t.Fatal("explicit generation metadata was not respected")
	}
}

func TestPreservingIdentitySkipsGenerationAndReseeding(t *testing.T) {
	for _, provider := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(provider, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, seed := range []uint32{0, 425179} {
				p := &Profile{Name: "Imported", RuntimeID: provider, FingerprintSeed: seed}
				if err := store.CreatePreservingIdentity(p); err != nil {
					t.Fatal(err)
				}
				if p.FingerprintSeed != seed || p.Fingerprint != nil || p.FingerprintGeneration != nil || p.Identity != nil {
					t.Fatal("import preservation silently generated a different identity")
				}
			}
		})
	}
}

func TestFreshGenerationPinsItsOSWithoutChangingRestoredAutomaticIdentity(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Fresh automatic OS", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	want, err := fingerprintTargetOS(&Profile{}, runtime.GOOS)
	if err != nil || p.Identity == nil || p.Identity.TargetOS != want {
		t.Fatal("generated device tuple did not retain its chosen OS")
	}
	legacy := &Profile{Name: "Imported automatic OS", RuntimeID: "cloakbrowser", FingerprintSeed: 42}
	if err := store.CreatePreservingIdentity(legacy); err != nil || legacy.Identity != nil {
		t.Fatal("restoring a legacy automatic profile silently fixed its OS")
	}
}

func TestCloneOfLegacyIdentityPreservesHardwareAndReplacesNoise(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Legacy explicit", RuntimeID: "cloakbrowser", FingerprintSeed: 42,
		Fingerprint: map[string]any{"screen.width": 1600, "screen.height": 900, "screen.devicePixelRatio": 1, "navigator.hardwareConcurrency": 8, "navigator.deviceMemory": 8, "canvas:seed": 11}}
	if err := store.CreatePreservingIdentity(p); err != nil {
		t.Fatal(err)
	}
	clone, err := store.Duplicate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if clone.FingerprintGeneration == nil || len(clone.FingerprintGeneration.GeneratedFields) != 0 || len(clone.Fingerprint) != 5 || clone.Fingerprint["screen.width"] != float64(1600) || clone.FingerprintSeed == p.FingerprintSeed {
		t.Fatal("legacy clone lost explicit hardware or retained its old seed")
	}
}
