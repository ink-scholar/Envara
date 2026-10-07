package runtime

import (
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
)

func TestNewRegistryLoadsBrowseForgeChromiumFromDefaultConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config.default.json"))
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}

	reg := NewRegistry(cfg)
	desc, ok := reg.Get(BrowseForgeChromium)
	if !ok {
		t.Fatal("BrowseForge Chromium runtime missing")
	}
	if desc.DisplayName != "BrowseForge Chromium" || desc.Family != FamilyChromium || desc.Capabilities.Family != FamilyChromium {
		t.Fatalf("BrowseForge Chromium metadata = %+v", desc)
	}
	if desc.BinaryPath != "browsers/browseforge-chromium/chrome" || !desc.Enabled {
		t.Fatalf("BrowseForge Chromium binary/enabled = %q/%v, want Docker/GHCR browser path and enabled", desc.BinaryPath, desc.Enabled)
	}
}

func TestRegistryResolvesExplicitRuntimeID(t *testing.T) {
	reg := NewRegistry(&config.Config{})

	tests := []struct {
		name      string
		runtimeID string
		wantID    ID
	}{
		{name: "camoufox runtime", runtimeID: "camoufox", wantID: Camoufox},
		{name: "cloakbrowser runtime", runtimeID: "cloakbrowser", wantID: CloakBrowser},
		{name: "browseforge chromium runtime", runtimeID: "browseforge-chromium", wantID: BrowseForgeChromium},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &profile.Profile{RuntimeID: tc.runtimeID}

			desc, err := reg.ApplyProfileDefaults(p)
			if err != nil {
				t.Fatalf("ApplyProfileDefaults: %v", err)
			}
			if desc.ID != tc.wantID {
				t.Fatalf("runtime ID = %q, want %q", desc.ID, tc.wantID)
			}
			if p.RuntimeID != string(tc.wantID) {
				t.Fatalf("profile runtime_id = %q, want %q", p.RuntimeID, tc.wantID)
			}
		})
	}
}

func TestRegistryRequiresExplicitRuntimeID(t *testing.T) {
	reg := NewRegistry(&config.Config{})
	p := &profile.Profile{}

	if _, err := reg.ApplyProfileDefaults(p); err == nil || !strings.Contains(err.Error(), "runtime_id is required") {
		t.Fatalf("missing runtime_id err = %v", err)
	}
}

func TestRegistryResolvesRuntimeID(t *testing.T) {
	reg := NewRegistry(&config.Config{})

	got, err := reg.ResolveID("browseforge-chromium")
	if err != nil {
		t.Fatalf("ResolveID: %v", err)
	}
	if got != BrowseForgeChromium {
		t.Fatalf("runtime ID = %q, want %q", got, BrowseForgeChromium)
	}
}

func TestRegistryRejectsUnsupportedRuntimeSelectors(t *testing.T) {
	reg := NewRegistry(&config.Config{})

	if _, err := reg.ResolveID("opera"); err == nil || !strings.Contains(err.Error(), `unsupported runtime_id "opera"`) {
		t.Fatalf("unsupported runtime_id err = %v", err)
	}
	if _, err := reg.ResolveID(""); err == nil || !strings.Contains(err.Error(), "runtime_id is required") {
		t.Fatalf("empty runtime_id err = %v", err)
	}
}

func TestRegistryListReturnsStableRuntimeMetadata(t *testing.T) {
	reg := NewRegistry(&config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox":             {BinaryPath: "/opt/camoufox"},
		"browseforge-chromium": {BinaryPath: "/opt/browseforge-chromium"},
		"cloakbrowser":         {BinaryPath: "/opt/cloakbrowser"},
	}})

	got := reg.List()
	if len(got) != 3 {
		t.Fatalf("runtime count = %d, want 3: %#v", len(got), got)
	}
	if got[0].ID != BrowseForgeChromium || got[1].ID != Camoufox || got[2].ID != CloakBrowser {
		t.Fatalf("runtime order = [%q %q %q], want [%q %q %q]", got[0].ID, got[1].ID, got[2].ID, BrowseForgeChromium, Camoufox, CloakBrowser)
	}

	browseforge := got[0]
	if browseforge.DisplayName != "BrowseForge Chromium" || browseforge.Family != FamilyChromium {
		t.Fatalf("BrowseForge Chromium metadata = %+v", browseforge)
	}
	if browseforge.BinaryPath != "/opt/browseforge-chromium" || !browseforge.Enabled {
		t.Fatalf("BrowseForge Chromium binary/enabled = %q/%v", browseforge.BinaryPath, browseforge.Enabled)
	}
	if !browseforge.Capabilities.SupportsAgentWebSessions || !browseforge.Capabilities.SupportsSeedFingerprint || !browseforge.Capabilities.SupportsPlaywrightBind {
		t.Fatalf("BrowseForge Chromium capabilities = %+v", browseforge.Capabilities)
	}

	camoufox := got[1]
	if camoufox.DisplayName != "Camoufox" || camoufox.Family != FamilyFirefox {
		t.Fatalf("Camoufox metadata = %+v", camoufox)
	}
	if camoufox.BinaryPath != "/opt/camoufox" || !camoufox.Enabled {
		t.Fatalf("Camoufox binary/enabled = %q/%v", camoufox.BinaryPath, camoufox.Enabled)
	}
	if camoufox.FingerprintPoolKey != "firefox" {
		t.Fatalf("Camoufox fingerprint pool = %q, want firefox", camoufox.FingerprintPoolKey)
	}
	if !camoufox.Capabilities.SupportsPersistentContext || !camoufox.Capabilities.SupportsPlaywrightBind || camoufox.Capabilities.SupportsAgentWebSessions {
		t.Fatalf("Camoufox capabilities = %+v", camoufox.Capabilities)
	}

	cloak := got[2]
	if cloak.DisplayName != "CloakBrowser" || cloak.Family != FamilyChromium {
		t.Fatalf("CloakBrowser metadata = %+v", cloak)
	}
	if cloak.BinaryPath != "/opt/cloakbrowser" || !cloak.Enabled {
		t.Fatalf("CloakBrowser binary/enabled = %q/%v", cloak.BinaryPath, cloak.Enabled)
	}
	if !cloak.Capabilities.SupportsAgentWebSessions || !cloak.Capabilities.SupportsSeedFingerprint || !cloak.Capabilities.SupportsPlaywrightBind {
		t.Fatalf("CloakBrowser capabilities = %+v", cloak.Capabilities)
	}
}

func TestPlatformSupportUsesRuntimeArtifactSource(t *testing.T) {
	tests := []struct {
		id     ID
		goos   string
		goarch string
		wantOK bool
	}{
		{id: Camoufox, goos: "darwin", goarch: "amd64", wantOK: true},
		{id: Camoufox, goos: "darwin", goarch: "arm64", wantOK: true},
		{id: Camoufox, goos: "linux", goarch: "amd64", wantOK: true},
		{id: Camoufox, goos: "linux", goarch: "arm64", wantOK: true},
		{id: Camoufox, goos: "windows", goarch: "amd64", wantOK: true},
		{id: Camoufox, goos: "windows", goarch: "arm64", wantOK: false},
		{id: CloakBrowser, goos: "darwin", goarch: "amd64", wantOK: true},
		{id: CloakBrowser, goos: "darwin", goarch: "arm64", wantOK: true},
		{id: CloakBrowser, goos: "linux", goarch: "amd64", wantOK: true},
		{id: CloakBrowser, goos: "linux", goarch: "arm64", wantOK: true},
		{id: CloakBrowser, goos: "windows", goarch: "amd64", wantOK: true},
		{id: CloakBrowser, goos: "windows", goarch: "arm64", wantOK: false},
		{id: BrowseForgeChromium, goos: "darwin", goarch: "amd64", wantOK: true},
		{id: BrowseForgeChromium, goos: "darwin", goarch: "arm64", wantOK: true},
		{id: BrowseForgeChromium, goos: "linux", goarch: "amd64", wantOK: true},
		{id: BrowseForgeChromium, goos: "linux", goarch: "arm64", wantOK: true},
		{id: BrowseForgeChromium, goos: "windows", goarch: "amd64", wantOK: true},
		{id: BrowseForgeChromium, goos: "linux", goarch: "386", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(string(tc.id)+"_"+tc.goos+"_"+tc.goarch, func(t *testing.T) {
			ok, reason := platformSupported(tc.id, tc.goos, tc.goarch)
			support := RuntimeSupportFor(string(tc.id), tc.goos, tc.goarch)
			if ok != support.PlatformSupported || reason != support.UnsupportedReason {
				t.Fatalf("platformSupported() = %v/%q, RuntimeSupportFor() = %v/%q", ok, reason, support.PlatformSupported, support.UnsupportedReason)
			}
			if ok != tc.wantOK {
				t.Fatalf("platform support = %v, want %v; reason = %q", ok, tc.wantOK, reason)
			}
			if !ok && (reason == "" || !strings.Contains(reason, tc.goos+"/"+tc.goarch)) {
				t.Fatalf("unsupported reason = %q", reason)
			}
		})
	}
}

func TestRegistryAppliesRuntimeConfigOverrides(t *testing.T) {
	disabled := false
	enabled := true
	reg := NewRegistry(&config.Config{
		Runtimes: map[string]config.RuntimeConfig{
			"camoufox": {
				DisplayName: "Camoufox ESR",
				BinaryPath:  "/custom/camoufox",
				Enabled:     &disabled,
			},
			"cloakbrowser": {
				DisplayName: "CloakBrowser QA",
				BinaryPath:  "/custom/cloakbrowser",
				Family:      "chromium",
				Enabled:     &enabled,
			},
		},
	})

	camoufox, ok := reg.Get(Camoufox)
	if !ok {
		t.Fatal("Camoufox runtime missing")
	}
	if camoufox.DisplayName != "Camoufox ESR" || camoufox.BinaryPath != "/custom/camoufox" || camoufox.Enabled {
		t.Fatalf("Camoufox override = %+v", camoufox)
	}

	cloak, ok := reg.Get(CloakBrowser)
	if !ok {
		t.Fatal("CloakBrowser runtime missing")
	}
	if cloak.DisplayName != "CloakBrowser QA" || cloak.BinaryPath != "/custom/cloakbrowser" || !cloak.Enabled {
		t.Fatalf("CloakBrowser override = %+v", cloak)
	}
	if cloak.Family != FamilyChromium || cloak.Capabilities.Family != FamilyChromium {
		t.Fatalf("CloakBrowser family override = descriptor %q capabilities %q", cloak.Family, cloak.Capabilities.Family)
	}
}
