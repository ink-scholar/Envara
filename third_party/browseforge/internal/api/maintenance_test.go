package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/profile"
)

func TestMaintenanceRoutesProtectProfileStorageAndRequirePrivateTokens(t *testing.T) {
	t.Setenv("BROWSEFORGE_TOKEN", "maintenance-fixture-api-token")
	h := newDesktopHandler(t)
	h.cfg.DataDir = t.TempDir()
	p := &profile.Profile{Name: "fixture", RuntimeID: "cloakbrowser"}
	if err := h.store.Create(p); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(p.ProfileDir, "browser-data", "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(h.cfg, h.store, h.mgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, route, body string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, route, strings.NewReader(body))
		if authorized {
			r.Header.Set("Authorization", "Bearer maintenance-fixture-api-token")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	body := `{"profile_ids":["` + p.ID + `"]}`
	if got := request("POST", "/api/maintenance/acquire", body, false); got.Code != 401 {
		t.Fatal("unauthorized maintenance was admitted")
	}
	for _, invalid := range []string{`{}`, body + `{}`, `{"profile_ids":[],"path":"/private/fixture"}`, `{"profile_ids":["` + p.ID + `","` + p.ID + `"]}`} {
		if got := request("POST", "/api/maintenance/acquire", invalid, true); got.Code != 400 {
			t.Fatalf("invalid admission: %d %s", got.Code, got.Body.String())
		}
	}
	got := request("POST", "/api/maintenance/acquire", body, true)
	var lease struct{ Data struct{ Token string } }
	if got.Code != 200 || got.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(got.Body.Bytes(), &lease) != nil || len(lease.Data.Token) != 64 {
		t.Fatalf("private lease response: %d", got.Code)
	}
	for _, operation := range []struct{ method, route, body string }{
		{"POST", "/api/sessions", `{"profile_id":"` + p.ID + `"}`},
		{"PUT", "/api/profiles/" + p.ID, `{"name":"changed"}`},
		{"DELETE", "/api/profiles/" + p.ID, ``},
	} {
		got := request(operation.method, operation.route, operation.body, true)
		if got.Code != 409 || !strings.Contains(got.Body.String(), "CACHE_MAINTENANCE_BUSY") {
			t.Fatalf("operation bypassed maintenance: %s %d %s", operation.method, got.Code, got.Body.String())
		}
	}
	if got := request("POST", "/api/profiles", `{"id":"`+p.ID+`","name":"replace","runtime_id":"cloakbrowser"}`, true); got.Code < 400 {
		t.Fatal("create with an existing ID overwrote maintenance storage")
	}
	if got := request("POST", "/api/maintenance/release", `{"token":"`+strings.Repeat("0", 64)+`"}`, true); got.Code != 409 {
		t.Fatal("foreign token released the lease")
	}
	if raw, err := os.ReadFile(keep); err != nil || string(raw) != "keep" || p.Name != "fixture" {
		t.Fatal("refused REST operation changed profile files")
	}
	for _, route := range []string{"/api/profiles", "/api/sessions"} {
		if strings.Contains(request("GET", route, ``, true).Body.String(), lease.Data.Token) {
			t.Fatal("private token escaped into ordinary inventory")
		}
	}
	if got := request("POST", "/api/maintenance/release", `{"token":"`+lease.Data.Token+`"}`, true); got.Code != 200 {
		t.Fatal("owner could not release maintenance")
	}
	if got := request("DELETE", "/api/profiles/"+p.ID, ``, true); got.Code != 200 {
		t.Fatalf("released profile remained locked: %d", got.Code)
	}
}
