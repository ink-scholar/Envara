package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedProxyRequirementPersistsReloadsAndDuplicatesWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "Managed node", RuntimeID: "cloakbrowser", ManagedProxyRequired: true, SessionProxy: &ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 19427, Password: "ephemeral-secret"}}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(p.ProfileDir, "profile.json"))
	if err != nil || !strings.Contains(string(data), `"managed_proxy_required": true`) || strings.Contains(string(data), "ephemeral-secret") {
		t.Fatalf("invalid durable managed marker: %v", err)
	}
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reloaded.Get(p.ID)
	if err != nil || !loaded.ManagedProxyRequired || loaded.SessionProxy != nil {
		t.Fatal("reload lost managed marker or loaded transient credentials")
	}
	duplicate, err := reloaded.Duplicate(p.ID)
	if err != nil || !duplicate.ManagedProxyRequired || duplicate.SessionProxy != nil {
		t.Fatal("duplicate lost managed marker or copied transient credentials")
	}
	updated, err := reloaded.Update(p.ID, map[string]any{"name": "Keep managed"})
	if err != nil || !updated.ManagedProxyRequired {
		t.Fatal("unrelated profile edit removed managed marker")
	}
	updated, err = reloaded.Update(p.ID, map[string]any{"managed_proxy_required": false})
	if err != nil || updated.ManagedProxyRequired {
		t.Fatal("explicit false could not clear managed marker")
	}
	data, err = json.Marshal(updated)
	if err != nil || strings.Contains(string(data), "managed_proxy_required") {
		t.Fatal("normal proxy profile kept managed marker")
	}
}
