package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/config"
)

func TestDesktopHTTPSessionRequiresTransientBridgeThroughREST(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		for _, proxyType := range []string{"http", "https"} {
			t.Run(runtimeID+"/"+proxyType, func(t *testing.T) {
				h, stored, captured, calls := newSessionLaunchHandler(t, nil)
				setGuardedLinkField(h.mgr, "cfg", &config.Config{EnforceHTTPProxyBridge: true})
				if _, err := h.store.Update(stored.ID, map[string]any{"runtime_id": runtimeID, "proxy": map[string]any{"type": proxyType, "host": "upstream.invalid", "port": 8443}}); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(stored.ProfileDir, "profile.json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, extra := range []string{"", `,"launch_overrides":{"timezone":"Asia/Tokyo"}`, `,"launch_overrides":{"proxy":{"type":"http","host":"127.0.0.1","port":19427}}`} {
					rec := httptest.NewRecorder()
					h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`"`+extra+`}`)))
					if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"code":"MANAGED_PROXY_REQUIRED"`) || *calls != 0 {
						t.Fatalf("unbridged REST launch was not rejected: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
					}
				}
				rec := httptest.NewRecorder()
				h.createSession(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"profile_id":"`+stored.ID+`","launch_overrides":{"proxy":{"type":"http","host":"127.0.0.1","port":19427,"username":"fixture-user","password":"fixture-password"}}}`)))
				if rec.Code != http.StatusCreated || *calls != 1 || (*captured).SessionProxy == nil || (*captured).ManagedProxyRequired {
					t.Fatalf("bridged REST launch changed the profile contract: %d calls=%d %s", rec.Code, *calls, rec.Body.String())
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("desktop bridge enforcement changed the stored profile")
				}
			})
		}
	}
}
