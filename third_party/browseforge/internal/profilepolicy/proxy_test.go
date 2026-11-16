package profilepolicy

import (
	"strings"
	"testing"

	"browseforge/internal/browser"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func TestProxyRegionCompatibilityDecisionsAndExactErrors(t *testing.T) {
	required := "browseforge-chromium proxy_region is required when a proxy is configured; use a redacted geographic label such as " + browser.BrowseForgeProxyRegionExamples
	preset := "browseforge-chromium proxy_region must be one of the supported presets: " + browser.BrowseForgeProxyRegionExamples
	for _, test := range []struct {
		name    string
		runtime bfruntime.ID
		region  string
		want    string
		error   string
	}{
		{"Cloak keeps region", bfruntime.CloakBrowser, " Unknown/Value ", " Unknown/Value ", ""},
		{"Camoufox keeps region", bfruntime.Camoufox, "", "", ""},
		{"accepted normalization", bfruntime.BrowseForgeChromium, " US-NY ", "us-ny", ""},
		{"missing", bfruntime.BrowseForgeChromium, "", "", required},
		{"blank refusal does not normalize", bfruntime.BrowseForgeChromium, "  ", "  ", required},
		{"unknown preset", bfruntime.BrowseForgeChromium, "zz", "zz", preset},
		{"punctuation", bfruntime.BrowseForgeChromium, "us/ny", "us/ny", "browseforge-chromium proxy_region must contain only letters, digits, hyphen, or underscore"},
		{"invalid edges", bfruntime.BrowseForgeChromium, "-us", "-us", "browseforge-chromium proxy_region must start and end with a letter or digit"},
		{"bounded label", bfruntime.BrowseForgeChromium, strings.Repeat("a", 65), strings.Repeat("a", 65), "browseforge-chromium proxy_region must be a redacted region label of at most 64 characters"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := &profile.ProxyConfig{Type: "http", Host: "fixture.invalid", Port: 8080, Region: test.region}
			err := ValidateProxyRegion(test.runtime, proxy)
			actual := ""
			if err != nil {
				actual = err.Error()
			}
			if actual != test.error || proxy.Region != test.want {
				t.Fatalf("region=%q error=%q; want region=%q error=%q", proxy.Region, actual, test.want, test.error)
			}
		})
	}
	if err := ValidateProxyRegion(bfruntime.BrowseForgeChromium, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProfilePolicyPreservesResolutionOrderAndInheritedConfiguration(t *testing.T) {
	groupProxy := &profile.ProxyConfig{Region: " GB-LONDON "}
	p := &profile.Profile{Proxy: &profile.ProxyConfig{Region: " US-NY "}}
	resolved := 0
	err := ValidateProfileProxy(bfruntime.BrowseForgeChromium, p, func(actual *profile.Profile) groups.EffectiveProxy {
		resolved++
		if actual != p || actual.Proxy.Region != "us-ny" {
			t.Fatal("group resolution ran before explicit proxy normalization")
		}
		return groups.EffectiveProxy{Proxy: groupProxy, Source: "group", Mode: groups.ProxyModeEnforced}
	})
	if err != nil || resolved != 1 || groupProxy.Region != " GB-LONDON " {
		t.Fatalf("inherited configuration changed: region=%q resolutions=%d error=%v", groupProxy.Region, resolved, err)
	}
	// An invalid explicit proxy is still refused before consulting an enforced
	// group. Refactoring must not make that previously rejected profile pass.
	p.Proxy.Region = ""
	if err := ValidateProfileProxy(bfruntime.BrowseForgeChromium, p, func(*profile.Profile) groups.EffectiveProxy {
		t.Fatal("refused explicit proxy reached group resolution")
		return groups.EffectiveProxy{}
	}); err == nil {
		t.Fatal("missing explicit region was accepted")
	}
	for _, runtimeID := range []bfruntime.ID{bfruntime.CloakBrowser, bfruntime.Camoufox} {
		if err := ValidateProfileProxy(runtimeID, p, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateProfileProxy(bfruntime.BrowseForgeChromium, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProfilePolicyPreservesEffectiveSourceRules(t *testing.T) {
	for _, source := range []string{"none", "profile", "group"} {
		t.Run(source, func(t *testing.T) {
			proxy := &profile.ProxyConfig{Region: ""}
			err := ValidateProfileProxy(bfruntime.BrowseForgeChromium, &profile.Profile{}, func(*profile.Profile) groups.EffectiveProxy {
				if source == "none" {
					return groups.EffectiveProxy{Source: source}
				}
				return groups.EffectiveProxy{Source: source, Proxy: proxy}
			})
			if (err != nil) != (source == "group") || proxy.Region != "" {
				t.Fatalf("source=%s changed previous decision: %v", source, err)
			}
		})
	}
}

func TestMissingGroupServicesKeepTheirNoopBehavior(t *testing.T) {
	if err := ValidateGroupProxyRegion("fixture", &profile.ProxyConfig{}, nil, &browser.Manager{}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGroupProxyRegion("fixture", &profile.ProxyConfig{}, &profile.Store{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGroupProxyRegion("fixture", nil, &profile.Store{}, &browser.Manager{}); err != nil {
		t.Fatal(err)
	}
	if got := ActiveSessionsForGroup("fixture", nil, &browser.Manager{}); got != 0 {
		t.Fatal(got)
	}
	if got := ActiveSessionsForGroup("fixture", &profile.Store{}, nil); got != 0 {
		t.Fatal(got)
	}
	if got := ActiveSessionsForGroup("  ", &profile.Store{}, &browser.Manager{}); got != 0 {
		t.Fatal(got)
	}
}
