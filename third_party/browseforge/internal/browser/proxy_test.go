package browser

import (
	"testing"

	"browseforge/internal/groups"
	"browseforge/internal/profile"
)

func TestManagerEffectiveProxyUsesGroupStore(t *testing.T) {
	store, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "group.proxy", Port: 1080}, groups.ProxyModeEnforced); err != nil {
		t.Fatal(err)
	}
	m := &Manager{groupStore: store}

	effective := m.effectiveProxy(&profile.Profile{
		Group: "Client A",
		Proxy: &profile.ProxyConfig{Type: "http", Host: "profile.proxy", Port: 8080},
	})
	if effective.Source != "group" || effective.Proxy.Host != "group.proxy" {
		t.Fatalf("effective proxy = %+v", effective)
	}
}
