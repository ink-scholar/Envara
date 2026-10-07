package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"browseforge/internal/browser"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
)

func TestMCPOpenBrowserRejectsManagedProxyProfileWithoutDesktopBridge(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(runtimeID, func(t *testing.T) {
			store, err := profile.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			p := &profile.Profile{Name: "Managed node", RuntimeID: runtimeID, ManagedProxyRequired: true}
			if err := store.Create(p); err != nil {
				t.Fatal(err)
			}
			// An empty manager makes any attempt to resolve or launch a browser
			// fail the test instead of reaching an executable or a network call.
			srv := NewServer(store, &browser.Manager{}, humanize.Config{}, nil, "", "test")
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_browser","arguments":{"profile_id":"`+p.ID+`"}}}`))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, request)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "requires an Envara-managed proxy") || !strings.Contains(rec.Body.String(), "start it through Envara") {
				t.Fatalf("MCP managed profile did not reject direct launch: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}
