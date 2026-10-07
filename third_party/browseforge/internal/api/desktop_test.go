package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func newDesktopHandler(t *testing.T) *handler {
	t.Helper()
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AllowEmptyRuntime: true}
	return &handler{cfg: cfg, store: store, mgr: testManagerWithRuntimeConfig(t, cfg)}
}

func TestDesktopCanManageDraftsBeforeInstallingRuntime(t *testing.T) {
	for _, runtimeID := range []string{"camoufox", "cloakbrowser", "browseforge-chromium"} {
		t.Run(runtimeID, func(t *testing.T) {
			h := newDesktopHandler(t)
			rec := httptest.NewRecorder()
			h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Draft","runtime_id":"`+runtimeID+`"}`)))
			desc, _ := h.mgr.RuntimeRegistry().Get(bfruntime.ID(runtimeID))
			if !desc.PlatformSupported {
				if rec.Code != http.StatusBadRequest || len(h.store.List("", "")) != 0 {
					t.Fatalf("unsupported provider draft = %d %s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusCreated {
				t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
			}
			var result struct {
				Data profile.Profile `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			h.updateProfile(rec, requestWithProfileID(http.MethodPut, "/api/profiles/"+result.Data.ID, result.Data.ID, strings.NewReader(`{"name":"Edited draft","runtime_id":"`+runtimeID+`"}`)))
			if rec.Code != http.StatusOK {
				t.Fatalf("edit = %d %s", rec.Code, rec.Body.String())
			}
			rec = httptest.NewRecorder()
			h.duplicateProfile(rec, requestWithProfileID(http.MethodPost, "/api/profiles/"+result.Data.ID+"/duplicate", result.Data.ID, nil))
			if rec.Code != http.StatusCreated || len(h.store.List("", "")) != 2 {
				t.Fatalf("duplicate = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDesktopStillRejectsUnknownProvider(t *testing.T) {
	h := newDesktopHandler(t)
	rec := httptest.NewRecorder()
	h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Bad draft","runtime_id":"unknown"}`)))
	if rec.Code != http.StatusBadRequest || len(h.store.List("", "")) != 0 {
		t.Fatalf("unknown provider = %d %s", rec.Code, rec.Body.String())
	}
}

func TestDesktopImportAndRestoreDraftProfiles(t *testing.T) {
	h := newDesktopHandler(t)
	body, contentType := multipartZipUpload(t, map[string][]byte{
		"profile.json": []byte(`{"name":"Imported draft","runtime_id":"camoufox"}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/profiles/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.importProfile(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import = %d %s", rec.Code, rec.Body.String())
	}
	body, contentType = multipartZipUpload(t, map[string][]byte{
		"cloak/profile.json": []byte(`{"name":"Restored draft","runtime_id":"cloakbrowser"}`),
	})
	req = httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec = httptest.NewRecorder()
	h.restore(rec, req)
	if rec.Code != http.StatusOK || len(h.store.List("", "")) != 2 {
		t.Fatalf("restore = %d %s", rec.Code, rec.Body.String())
	}
}

func TestDesktopEmptyCatalogKeepsAllProviders(t *testing.T) {
	h := newDesktopHandler(t)
	rec := httptest.NewRecorder()
	h.listRuntimes(rec, httptest.NewRequest(http.MethodGet, "/api/runtimes", nil))
	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Enabled    bool   `json:"enabled"`
			BinaryPath string `json:"binary_path"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 3 {
		t.Fatalf("missing runtime descriptors: %s", rec.Body.String())
	}
	for _, desc := range result.Data {
		if desc.Enabled || desc.BinaryPath != "" {
			t.Fatalf("missing runtime advertised as installed: %+v", desc)
		}
	}
}

func TestDesktopFocusRouteRequiresTokenAndRejectsMissingSession(t *testing.T) {
	t.Setenv("BROWSEFORGE_TOKEN", "desktop-test-token")
	h := newDesktopHandler(t)
	h.cfg.DataDir = t.TempDir()
	router, err := NewRouter(h.cfg, h.store, h.mgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token string
		want  int
	}{
		{want: http.StatusUnauthorized},
		{token: "desktop-test-token", want: http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/sessions/missing/focus", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("focus route = %d want %d; %s", rec.Code, tc.want, rec.Body.String())
		}
		if tc.token != "" && !strings.Contains(rec.Body.String(), `"code":"NOT_FOUND"`) {
			t.Fatalf("missing session had no structured error: %s", rec.Body.String())
		}
	}
}
