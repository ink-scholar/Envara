package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/browser"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
)

func TestMCPProfileMutationsCannotBypassMaintenanceStoreGuard(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{Name: "fixture", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(p.ProfileDir, "browser-data", "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	mgr := &browser.Manager{}
	srv := NewServer(store, mgr, humanize.Config{}, nil, "", "test")
	token, err := mgr.AcquireProfileMaintenance(context.Background(), []string{p.ID})
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := srv.toolUpdateProfile(map[string]any{"profile_id": p.ID, "name": "changed"})
	_, deleteErr := srv.toolDeleteProfile(map[string]any{"profile_id": p.ID})
	for _, err := range []*mcpError{updateErr, deleteErr} {
		if err == nil || !strings.Contains(err.Message, "under maintenance") {
			t.Fatalf("MCP mutation bypassed profile lock: %v", err)
		}
	}
	if raw, err := os.ReadFile(keep); err != nil || string(raw) != "keep" || p.Name != "fixture" {
		t.Fatal("refused MCP mutation changed profile storage")
	}
	if err := mgr.ReleaseProfileMaintenance(token); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.toolUpdateProfile(map[string]any{"profile_id": p.ID, "name": "after"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.toolDeleteProfile(map[string]any{"profile_id": p.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestMCPUpdateAdmissionBlocksToolsAndAllowsReadOnlyInventory(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{Name: "keep", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	mgr := &browser.Manager{}
	srv := NewServer(store, mgr, humanize.Config{}, nil, "", "test")
	token, err := mgr.AcquireUpdateMaintenance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	call := func(name string, args map[string]any) *mcpError {
		params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
		if err != nil {
			t.Fatal(err)
		}
		_, failure := srv.handleToolsCall(params, nil)
		return failure
	}
	for _, name := range []string{"create_profile", "update_profile", "delete_profile", "open_browser", "create_session", "new_tab", "switch_tab", "run_workflow", "delete_download", "update_group_proxy"} {
		if err := call(name, map[string]any{"profile_id": p.ID}); err == nil || !strings.Contains(err.Message, "reserved for update") {
			t.Fatalf("MCP tool bypassed update: %s %v", name, err)
		}
	}
	for _, name := range []string{"list_profiles", "list_proxy_regions", "doctor_profile", "list_downloads"} {
		if err := call(name, map[string]any{"profile_id": p.ID}); err != nil {
			t.Fatalf("read blocked: %s %v", name, err)
		}
	}
	if _, err := srv.toolUpdateProfile(map[string]any{"profile_id": p.ID, "name": "changed"}); err == nil {
		t.Fatal("direct tool bypassed Store guard")
	}
	if len(store.List("", "")) != 1 || p.Name != "keep" {
		t.Fatal("refused tool changed profile")
	}
	if err := mgr.ReleaseUpdateMaintenance(token); err != nil {
		t.Fatal(err)
	}
	if err := call("update_profile", map[string]any{"profile_id": p.ID, "name": "after"}); err != nil || p.Name != "after" {
		t.Fatalf("released tool stayed locked: %v", err)
	}
	token, err = mgr.AcquireUpdateMaintenance(context.Background())
	if err != nil {
		t.Fatal("MCP request leaked reservation", err)
	}
	if err := mgr.ReleaseUpdateMaintenance(token); err != nil {
		t.Fatal(err)
	}
}
