package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileCRUD(t *testing.T) {
	dir, _ := os.MkdirTemp("", "browseforge-test-*")
	defer os.RemoveAll(dir)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Create
	p := &Profile{Name: "Test", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	if p.ID == "" {
		t.Fatal("ID not generated")
	}
	t.Logf("Created: %s", p.ID)

	// Read
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Test" {
		t.Errorf("name = %s, want Test", got.Name)
	}

	// List
	all := store.List("", "")
	if len(all) != 1 {
		t.Errorf("list = %d, want 1", len(all))
	}

	// Update
	updated, err := store.Update(p.ID, map[string]any{"name": "Updated"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" {
		t.Errorf("name = %s, want Updated", updated.Name)
	}

	// Duplicate
	dup, err := store.Duplicate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dup.ID == p.ID {
		t.Error("duplicate has same ID")
	}

	// Delete
	if err := store.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(p.ID); err == nil {
		t.Error("deleted profile still found")
	}

	t.Log("✅ Profile CRUD all pass")
}

func TestStoreRejectsV1EngineOnlyProfile(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "legacy-firefox")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("mkdir legacy profile: %v", err)
	}
	raw := map[string]any{
		"id":     "legacy-firefox",
		"name":   "Legacy Firefox",
		"engine": "firefox",
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal legacy profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "profile.json"), data, 0644); err != nil {
		t.Fatalf("write legacy profile: %v", err)
	}

	_, err = NewStore(dir)
	if err == nil {
		t.Fatal("expected v1 profile load to fail")
	}
	if want := "runtime_id is required; run BrowseForge migrate profiles --from v1 --to v2"; !strings.Contains(err.Error(), want) {
		t.Fatalf("load error = %q, want migration guidance containing %q", err.Error(), want)
	}
}

func TestStoreCreatesRuntimeIDOnlyCloakBrowserProfile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &Profile{Name: "Cloaked", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	got, err := reloaded.Get(p.ID)
	if err != nil {
		t.Fatalf("Get reloaded profile: %v", err)
	}
	if got.RuntimeID != "cloakbrowser" {
		t.Fatalf("reloaded profile runtime_id = %q, want cloakbrowser", got.RuntimeID)
	}
}

func TestStoreDropsLegacyIdentityBrowserFamilyOnOutput(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "legacy-runtime-profile")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("mkdir legacy profile: %v", err)
	}
	raw := map[string]any{
		"id":         "legacy-runtime-profile",
		"name":       "Legacy Runtime Profile",
		"runtime_id": "camoufox",
		"identity": map[string]any{
			"browser_family": "firefox",
			"target_os":      "windows",
		},
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal legacy profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "profile.json"), data, 0644); err != nil {
		t.Fatalf("write legacy profile: %v", err)
	}

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	got, err := store.Get("legacy-runtime-profile")
	if err != nil {
		t.Fatalf("Get legacy profile: %v", err)
	}
	output, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal store output: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(output, &body); err != nil {
		t.Fatalf("decode store output: %v", err)
	}
	identity, ok := body["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity missing from store output: %s", output)
	}
	if _, ok := identity["browser_family"]; ok {
		t.Fatalf("store output preserved legacy identity.browser_family: %s", output)
	}
	if got.RuntimeID != "camoufox" {
		t.Fatalf("runtime_id = %q, want camoufox", got.RuntimeID)
	}
	if got.Identity == nil || got.Identity.TargetOS != "windows" {
		t.Fatalf("identity target_os = %+v, want windows", got.Identity)
	}
}
