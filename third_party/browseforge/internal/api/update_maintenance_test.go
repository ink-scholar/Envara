package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"browseforge/internal/browser"
	"browseforge/internal/profile"
)

func TestUpdateMaintenanceRoutesKeepReadsAndFenceMutationsUntilExactRelease(t *testing.T) {
	t.Setenv("BROWSEFORGE_TOKEN", "update-fixture-api-token")
	h := newDesktopHandler(t)
	h.cfg.DataDir = t.TempDir()
	p := &profile.Profile{Name: "keep", RuntimeID: "cloakbrowser"}
	if err := h.store.Create(p); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(h.cfg, h.store, h.mgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, route, body string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, route, strings.NewReader(body))
		if authorized {
			r.Header.Set("Authorization", "Bearer update-fixture-api-token")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if got := request("POST", "/api/maintenance/update-acquire", `{}`, false); got.Code != 401 {
		t.Fatal("unauthorized update admitted")
	}
	for _, body := range []string{``, `null`, `[]`, `{} {}`, `{"profile_ids":[]}`, `{"token":"ignored"}`} {
		if got := request("POST", "/api/maintenance/update-acquire", body, true); got.Code != 400 || !strings.Contains(got.Body.String(), "UPDATE_MAINTENANCE_INVALID") {
			t.Fatalf("invalid body admitted: %s %d", body, got.Code)
		}
	}
	got := request("POST", "/api/maintenance/update-acquire", `{}`, true)
	var lease struct{ Data struct{ Token string } }
	if got.Code != 200 || got.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(got.Body.Bytes(), &lease) != nil || len(lease.Data.Token) != 64 {
		t.Fatalf("acquire: %d %s", got.Code, got.Body.String())
	}
	for _, operation := range []struct{ method, route, body string }{
		{"POST", "/api/sessions", `{"profile_id":"` + p.ID + `"}`},
		{"POST", "/api/profiles", `{"name":"new","runtime_id":"cloakbrowser"}`},
		{"PUT", "/api/profiles/" + p.ID, `{"name":"changed"}`},
		{"DELETE", "/api/profiles/" + p.ID, ``},
		{"POST", "/api/profiles/" + p.ID + "/duplicate", `{}`},
		{"PUT", "/api/groups/new", `{}`},
		{"POST", "/api/restore", `{}`},
		{"POST", "/api/sessions/missing/eval", `{}`},
		{"POST", "/api/maintenance/acquire", `{"profile_ids":["` + p.ID + `"]}`},
		{"POST", "/api/maintenance/update-acquire", `{}`},
	} {
		got := request(operation.method, operation.route, operation.body, true)
		if got.Code != 409 || !strings.Contains(got.Body.String(), "UPDATE_MAINTENANCE_BUSY") {
			t.Fatalf("bypassed update: %s %s %d %s", operation.method, operation.route, got.Code, got.Body.String())
		}
	}
	for _, route := range []string{"/api/status", "/api/health", "/api/profiles", "/api/sessions", "/api/runtimes"} {
		got := request("GET", route, ``, true)
		if got.Code != 200 || strings.Contains(got.Body.String(), lease.Data.Token) {
			t.Fatalf("read unavailable or exposed token: %s %d", route, got.Code)
		}
	}
	if len(h.store.List("", "")) != 1 || p.Name != "keep" {
		t.Fatal("refused mutation changed profiles")
	}
	for _, route := range []string{"/api/maintenance/release", "/api/maintenance/update-release"} {
		token := lease.Data.Token
		if strings.HasSuffix(route, "update-release") {
			token = strings.Repeat("0", 64)
		}
		if got := request("POST", route, `{"token":"`+token+`"}`, true); got.Code != 409 {
			t.Fatal("wrong release freed update")
		}
	}
	if got := request("POST", "/api/maintenance/update-release", `{"token":"`+lease.Data.Token+`"}`, false); got.Code != 401 {
		t.Fatal("unauthorized release admitted")
	}
	if got := request("POST", "/api/maintenance/update-release", `{"token":"`+lease.Data.Token+`"}`, true); got.Code != 200 {
		t.Fatal("exact release failed")
	}
	if got := request("PUT", "/api/profiles/"+p.ID, `{"name":"after"}`, true); got.Code != 200 || p.Name != "after" {
		t.Fatalf("released profile stayed locked: %d %s", got.Code, got.Body.String())
	}
	if got := request("POST", "/api/maintenance/update-acquire", `{}`, true); got.Code != 200 {
		t.Fatalf("handler leaked operation count: %d", got.Code)
	}
}

func TestUpdateAdmissionRefusesAnInFlightRESTHandlerWithNoSessions(t *testing.T) {
	h := newDesktopHandler(t)
	entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	handler := h.updateAdmissionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-proceed }))
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/restore", nil))
		close(done)
	}()
	<-entered
	result := make(chan error, 1)
	go func() { _, err := h.mgr.AcquireUpdateMaintenance(context.Background()); result <- err }()
	select {
	case err := <-result:
		if browser.ErrorCode(err) != "UPDATE_MAINTENANCE_BUSY" {
			close(proceed)
			<-done
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(proceed)
		<-done
		t.Fatal("update waited for REST handler")
	}
	close(proceed)
	<-done
	token, err := h.mgr.AcquireUpdateMaintenance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.ReleaseUpdateMaintenance(token); err != nil {
		t.Fatal(err)
	}
}
