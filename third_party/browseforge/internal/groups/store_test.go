package groups

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"browseforge/internal/profile"
)

func TestEffectiveProxyDefaultModeUsesProfileOverride(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080}, ProxyModeDefault); err != nil {
		t.Fatal(err)
	}

	p := &profile.Profile{
		Group: "Client A",
		Proxy: &profile.ProxyConfig{Type: "http", Host: "profile.proxy", Port: 8080},
	}
	effective := store.EffectiveProxy(p)
	if effective.Source != "profile" || effective.Proxy.Host != "profile.proxy" || effective.Mode != ProxyModeDefault {
		t.Fatalf("effective proxy = %+v", effective)
	}
}

func TestEffectiveProxyEnforcedModeUsesGroupOverride(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080, Region: "  us-ny  "}, ProxyModeEnforced); err != nil {
		t.Fatal(err)
	}

	p := &profile.Profile{
		Group: "Client A",
		Proxy: &profile.ProxyConfig{Type: "http", Host: "profile.proxy", Port: 8080},
	}
	effective := store.EffectiveProxy(p)
	if effective.Source != "group" || effective.Proxy.Host != "group.proxy" || effective.Proxy.Region != "us-ny" || effective.Mode != ProxyModeEnforced {
		t.Fatalf("effective proxy = %+v", effective)
	}
}

func TestGroupStorePersistsAndImports(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	upserted, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080, Username: "u", Password: "p", Region: "  us-ny  "}, "")
	if err != nil {
		t.Fatal(err)
	}
	if upserted.Proxy.Region != "us-ny" {
		t.Fatalf("upserted proxy region = %q", upserted.Proxy.Region)
	}
	if _, err := os.Stat(filepath.Join(dir, "groups.json")); err != nil {
		t.Fatalf("groups.json not written: %v", err)
	}

	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := reloaded.Get("Client A")
	if !ok || g.Proxy == nil || g.Proxy.Host != "group.proxy" || g.Proxy.Region != "us-ny" || g.ProxyMode != ProxyModeDefault {
		t.Fatalf("reloaded group = %+v ok=%v", g, ok)
	}

	data, err := reloaded.Export()
	if err != nil {
		t.Fatal(err)
	}
	var exported groupFile
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Groups) != 1 || exported.Groups[0].Proxy == nil || exported.Groups[0].Proxy.Region != "us-ny" {
		t.Fatalf("exported groups = %+v", exported.Groups)
	}
	imported, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n, err := imported.Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("imported = %d", n)
	}
	if g, ok := imported.Get("Client A"); !ok || g.Proxy == nil || g.Proxy.Host != "group.proxy" || g.Proxy.Region != "us-ny" {
		t.Fatalf("imported group = %+v ok=%v", g, ok)
	}

	n, err = imported.Import([]byte(`{"groups":[{"name":"Imported Region","proxy_mode":"default","proxy":{"type":"http","host":"import.proxy","port":8080,"region":"  ca-on  "}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("imported region policies = %d", n)
	}
	if g, ok := imported.Get("Imported Region"); !ok || g.Proxy == nil || g.Proxy.Region != "ca-on" {
		t.Fatalf("imported region group = %+v ok=%v", g, ok)
	}

	n, err = imported.Import([]byte(`{"groups":[{"name":"Empty","proxy_mode":"default"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("imported empty policies = %d", n)
	}
	if g, ok := imported.Get("Empty"); ok {
		t.Fatalf("empty policy should be skipped: %+v", g)
	}
}

func TestGroupStoreRejectsInvalidProxy(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", nil, ProxyModeDefault); err == nil {
		t.Fatal("expected missing proxy error")
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "ftp", Host: "proxy", Port: 1080}, ProxyModeDefault); err == nil {
		t.Fatal("expected invalid proxy type error")
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "proxy", Port: 70000}, ProxyModeDefault); err == nil {
		t.Fatal("expected invalid proxy port error")
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "proxy", Port: 1080}, "strict"); err == nil {
		t.Fatal("expected invalid proxy mode error")
	}
}

func TestClearProxyRemovesStoredPolicy(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "proxy", Port: 1080}, ProxyModeDefault); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClearProxy("Client A"); err != nil {
		t.Fatal(err)
	}
	if g, ok := store.Get("Client A"); ok {
		t.Fatalf("cleared group still exists = %+v", g)
	}
}
