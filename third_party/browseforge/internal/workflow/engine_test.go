package workflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCreateProfileForwardsRuntimeIDGroupAndProxy(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/profiles" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "prof_test"}})
	}))
	defer server.Close()

	engine := NewEngine(server.URL, "token")
	vars := map[string]string{}
	out, err := engine.executeStep("create_profile", "", map[string]any{
		"name":       "Profile A",
		"runtime_id": "cloakbrowser",
		"group":      "Client A",
		"proxy":      map[string]any{"type": "socks5", "host": "proxy.example.com", "port": 1080},
		"var":        "created",
	}, vars)
	if err != nil {
		t.Fatal(err)
	}
	if out != "created: prof_test" || vars["created"] != "prof_test" {
		t.Fatalf("out=%q vars=%v", out, vars)
	}
	if body["runtime_id"] != "cloakbrowser" {
		t.Fatalf("runtime_id not forwarded: %#v", body)
	}
	if _, ok := body["engine"]; ok {
		t.Fatalf("deprecated engine forwarded: %#v", body)
	}
	if body["group"] != "Client A" {
		t.Fatalf("group not forwarded: %#v", body)
	}
	proxy, ok := body["proxy"].(map[string]any)
	if !ok || proxy["host"] != "proxy.example.com" {
		t.Fatalf("proxy not forwarded: %#v", body)
	}
}

func TestCreateProfileRejectsLegacyEngineWithoutRuntimeID(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "prof_test"}})
	}))
	defer server.Close()

	engine := NewEngine(server.URL, "token")
	_, err := engine.executeStep("create_profile", "", map[string]any{
		"name":   "Legacy Profile",
		"engine": "chromium",
	}, map[string]string{})
	if err == nil {
		t.Fatal("create_profile with legacy engine and no runtime_id succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"engine", "runtime_id", "v2"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
	if called.Load() {
		t.Fatal("create_profile called API after legacy engine migration error")
	}
}
