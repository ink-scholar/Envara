package mcp

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
)

func TestMCPOpenBrowserRejectsDesktopHTTPProxyWithoutBridge(t *testing.T) {
	for _, runtimeID := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		for _, proxyType := range []string{"http", "https"} {
			t.Run(runtimeID+"/"+proxyType, func(t *testing.T) {
				store, err := profile.NewStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				p := &profile.Profile{Name: "Fixture", RuntimeID: runtimeID, Proxy: &profile.ProxyConfig{Type: proxyType, Host: "upstream.invalid", Port: 8443}}
				if err := store.Create(p); err != nil {
					t.Fatal(err)
				}
				manager := &browser.Manager{}
				field := reflect.ValueOf(manager).Elem().FieldByName("cfg")
				reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(&config.Config{EnforceHTTPProxyBridge: true}))
				srv := NewServer(store, manager, humanize.Config{}, nil, "", "test")
				request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_browser","arguments":{"profile_id":"`+p.ID+`"}}}`))
				rec := httptest.NewRecorder()
				srv.ServeHTTP(rec, request)
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "requires an authenticated Envara-managed loopback proxy") || !strings.Contains(rec.Body.String(), "start it through Envara") {
					t.Fatalf("unbridged MCP launch was not rejected: %d %s", rec.Code, rec.Body.String())
				}
				if p.ManagedProxyRequired || p.SessionProxy != nil {
					t.Fatal("MCP refusal changed the stored profile")
				}
			})
		}
	}
}
