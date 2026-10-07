package browser

import (
	"reflect"
	"strings"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func TestLaunchGeoOverridesPreserveAutoAndPartialValues(t *testing.T) {
	for _, test := range []struct {
		name               string
		overrides          *profile.LaunchOverrides
		wantTZ, wantLocale string
		wantGeo            bool
	}{
		{"old pool stays automatic", nil, "America/Los_Angeles", "en-US", true},
		{"empty stays automatic", &profile.LaunchOverrides{}, "America/Los_Angeles", "en-US", true},
		{"timezone fixed language auto", &profile.LaunchOverrides{Timezone: "Asia/Shanghai"}, "Asia/Shanghai", "en-US", true},
		{"language fixed timezone auto", &profile.LaunchOverrides{Locale: "zh-CN"}, "America/Los_Angeles", "zh-CN", true},
		{"both fixed skip network GeoIP", &profile.LaunchOverrides{Timezone: "Asia/Shanghai", Locale: "zh-CN"}, "Asia/Shanghai", "zh-CN", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := &profile.Profile{Fingerprint: map[string]any{"timezone": "Asia/Tokyo", "navigator.language": "ja-JP"}, LaunchOverrides: test.overrides}
			tz, locale, err := launchGeoOverrides(p, "America/Los_Angeles", "en-US")
			if err != nil || tz != test.wantTZ || locale != test.wantLocale || requiresLaunchGeo(p) != test.wantGeo {
				t.Fatalf("got tz=%q locale=%q geo=%v error=%v", tz, locale, requiresLaunchGeo(p), err)
			}
		})
	}
}

func TestPerProfilePlatformPolicyDoesNotChangeSharedRuntimeSettings(t *testing.T) {
	shared := &config.CloakBrowserConfig{FingerprintPlatform: "macos", SafeGPU: true}
	windows := &profile.Profile{Identity: &profile.IdentityConfig{TargetOS: "linux"}, LaunchOverrides: &profile.LaunchOverrides{TargetOS: "windows"}}
	policy, err := chromiumLaunchPolicyForProfile(windows, shared)
	if err != nil {
		t.Fatal(err)
	}
	if policy.FingerprintPlatform != "windows" || !policy.SafeGPU || shared.FingerprintPlatform != "macos" {
		t.Fatalf("per-profile override leaked into shared runtime settings: %+v shared=%+v", policy, shared)
	}
	identityPolicy, err := chromiumLaunchPolicyForProfile(&profile.Profile{Identity: &profile.IdentityConfig{TargetOS: "linux"}}, shared)
	if err != nil || identityPolicy.FingerprintPlatform != "linux" {
		t.Fatalf("explicit identity fallback lost: %+v %v", identityPolicy, err)
	}
	autoPolicy, err := chromiumLaunchPolicyForProfile(&profile.Profile{}, shared)
	if err != nil || autoPolicy != shared {
		t.Fatal("automatic profile changed the upstream runtime policy")
	}
	for _, runtimeID := range []bfruntime.ID{bfruntime.CloakBrowser, bfruntime.BrowseForgeChromium} {
		platform, err := resolveChromiumFingerprintPlatform(policy, "darwin", "arm64")
		if err != nil {
			t.Fatal(err)
		}
		persona, err := buildChromiumLaunchPersona(windows, runtimeID, platform, "Asia/Shanghai", "zh-CN", "", "arm64", policy)
		if err != nil || persona.Native.Platform.OS != "windows" || persona.NavigatorPlatform != "Win32" || !strings.Contains(persona.Native.Browser.UserAgent, "Windows NT") {
			t.Fatalf("native persona did not follow fixed platform: %+v %v", persona.Native.Platform, err)
		}
	}
}

func TestCamoufoxFixedOverridesUseNativeConfigAndPreserveOtherFingerprintData(t *testing.T) {
	camouConfig := map[string]any{"timezone": "America/Los_Angeles", "locale:language": "en", "locale:region": "US", "navigator.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0", "screen.width": 1440, "webGl:parameters": "owned profile parameters"}
	p := &profile.Profile{LaunchOverrides: &profile.LaunchOverrides{Timezone: "Asia/Taipei", Locale: "zh-Hant-TW", TargetOS: "macos"}}
	if err := applyCamoufoxLaunchOverrides(camouConfig, p, "arm64"); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{"timezone": "Asia/Taipei", "locale:language": "zh", "locale:script": "Hant", "locale:region": "TW", "locale:all": "zh-Hant-TW", "navigator.language": "zh-Hant-TW", "navigator.platform": "MacIntel", "navigator.oscpu": "Intel Mac OS X 10.15", "navigator.languages": []string{"zh-Hant-TW", "zh"}, "headers.Accept-Language": "zh-Hant-TW,zh;q=0.9", "screen.width": 1440, "webGl:parameters": "owned profile parameters"} {
		if !reflect.DeepEqual(camouConfig[key], want) {
			t.Errorf("native config %s=%#v, want %#v", key, camouConfig[key], want)
		}
	}
	if ua, ok := camouConfig["navigator.userAgent"].(string); !ok || !strings.Contains(ua, "Macintosh") || !strings.Contains(ua, "Firefox/135.0") || strings.Contains(ua, "Windows") {
		t.Fatalf("UA and platform diverged: %v", camouConfig["navigator.userAgent"])
	}
	automatic := map[string]any{"timezone": "America/New_York", "navigator.platform": "Win32"}
	if err := applyCamoufoxLaunchOverrides(automatic, &profile.Profile{}, "arm64"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(automatic, map[string]any{"timezone": "America/New_York", "navigator.platform": "Win32"}) {
		t.Fatal("automatic Camoufox profile had its generated values changed")
	}
}

func TestCloakNativePlatformSwitchUsesOSNameInsteadOfNavigatorValue(t *testing.T) {
	for _, test := range []struct {
		os, navigator string
	}{
		{"windows", "Win32"}, {"macos", "MacIntel"}, {"linux", "Linux x86_64"},
	} {
		t.Run(test.os, func(t *testing.T) {
			persona, err := buildChromiumLaunchPersona(&profile.Profile{}, bfruntime.CloakBrowser, test.navigator, "Asia/Shanghai", "zh-CN", "", "amd64", nil)
			if err != nil {
				t.Fatal(err)
			}
			args := cloakBrowserNativeIdentityArgs(persona)
			want := "--fingerprint-platform=" + test.os
			if args[len(args)-1] != want || persona.NavigatorPlatform != test.navigator {
				t.Fatalf("native CLI/web persona confused: args=%v navigator=%q", args, persona.NavigatorPlatform)
			}
		})
	}
}
