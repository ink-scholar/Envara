package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFixedLaunchOverridesPersistWithoutChangingFingerprintPool(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Fixed", RuntimeID: "cloakbrowser", Fingerprint: map[string]any{"timezone": "America/Los_Angeles", "navigator.language": "en-US"}, LaunchOverrides: &LaunchOverrides{Timezone: "Asia/Shanghai", Locale: "zh-CN", TargetOS: "macos"}}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint, err := json.Marshal(p.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	gotFingerprint, err := json.Marshal(got.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.LaunchOverrides, p.LaunchOverrides) || string(wantFingerprint) != string(gotFingerprint) || got.Fingerprint["timezone"] != "America/Los_Angeles" || got.Fingerprint["navigator.language"] != "en-US" {
		t.Fatalf("fixed overrides or generated pool changed after reload: %+v", got)
	}
	data, err := json.Marshal(&Profile{RuntimeID: "camoufox"})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if _, present := document["launch_overrides"]; present {
		t.Fatal("an automatic profile acquired launch overrides")
	}
}

func TestLaunchOverridesRejectInvalidFixedSelections(t *testing.T) {
	for name, overrides := range map[string]*LaunchOverrides{
		"missing": nil, "auto": {}, "fixed": {Timezone: "Asia/Shanghai", Locale: "zh-Hant-TW", TargetOS: "linux"}, "UTC": {Timezone: "UTC"}, "language only": {Locale: "en"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateLaunchOverrides(overrides); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, overrides := range map[string]*LaunchOverrides{
		"unknown zone": {Timezone: "Mars/Olympus"}, "local is not fixed": {Timezone: "Local"}, "zone padding": {Timezone: " UTC"}, "shell locale": {Locale: "en-US;touch /tmp/ignored"}, "underscore locale": {Locale: "en_US"}, "unknown platform": {TargetOS: "android"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateLaunchOverrides(overrides); err == nil {
				t.Fatalf("invalid override accepted: %+v", overrides)
			}
		})
	}
}

func TestInvalidOverrideUpdatePreservesMemoryAndSavedProfile(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Original", RuntimeID: "camoufox", LaunchOverrides: &LaunchOverrides{Timezone: "Asia/Tokyo", Locale: "ja-JP"}}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(p.ProfileDir, "profile.json")
	before, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(p.ID, map[string]any{"name": "Invalid", "launch_overrides": map[string]any{"timezone": "Mars/Olympus"}}); err == nil {
		t.Fatal("invalid override update succeeded")
	}
	if p.Name != "Original" || p.LaunchOverrides.Timezone != "Asia/Tokyo" {
		t.Fatalf("failed update mutated in-memory profile: %+v", p)
	}
	after, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed update changed the saved profile")
	}
	updated, err := store.Update(p.ID, map[string]any{"launch_overrides": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.LaunchOverrides == nil || *updated.LaunchOverrides != (LaunchOverrides{}) {
		t.Fatal("clearing fixed selections did not restore automatic mode")
	}
}
