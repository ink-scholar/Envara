package browser

import (
	"browseforge/internal/config"
	"browseforge/internal/fingerprint"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
	"reflect"
	"strings"
	"testing"
)

func TestBrowseForgeRegionRequiresCurrentCountryEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, region, session, detected, status string
		wantError                               bool
	}{
		{"verified matching", "us-ny", "US", "", "", false},
		{"same continent is insufficient", "us-ny", "CA", "", "", true},
		{"provider matching", "my-kuala-lumpur", "", "MY", "detected", false},
		{"provider mismatch", "us-ny", "", "CA", "detected", true},
		{"fallback has no country", "us-ny", "", "", "geo_provider_unavailable", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := fingerprint.GeoDetectionResult{CountryCode: tc.detected, Status: tc.status, Timezone: "America/Toronto"}
			err := validateBrowseForgeProxyCountry(tc.region, tc.session, result)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestBrowseForgeGeneratedCanvasUsesNativeFlagAndStableSavedSeed(t *testing.T) {
	build := func(seed uint32, generated bool, fp map[string]any, policy *config.CloakBrowserConfig) chromiumLaunchPersona {
		t.Helper()
		p := &profile.Profile{ID: "native-generation", FingerprintSeed: seed, Fingerprint: fp}
		if generated {
			p.FingerprintGeneration = &profile.FingerprintGeneration{Provider: "browseforge-chromium", Version: 1}
		}
		persona, err := buildChromiumLaunchPersona(p, bfruntime.BrowseForgeChromium, "MacIntel", "Asia/Kuala_Lumpur", "ms-MY", "my-kuala-lumpur", "arm64", policy)
		if err != nil {
			t.Fatal(err)
		}
		return persona
	}
	first := build(4242, true, map[string]any{"screen.width": 1920, "screen.height": 1080}, nil)
	same := build(4242, true, map[string]any{"screen.width": 1920, "screen.height": 1080}, nil)
	other := build(4243, true, nil, nil)
	if !first.HasCanvasNoise || first.CanvasNoise <= 0 || first.CanvasNoise == other.CanvasNoise || !reflect.DeepEqual(first, same) {
		t.Fatal("generated native canvas is not stable per identity")
	}
	if first.Native.Canvas.Seed != first.CanvasNoise || first.Native.Screen.AvailWidth != 1920 || first.Native.Screen.AvailHeight != 1047 {
		t.Fatal("generated native metadata is incoherent")
	}
	args := appendChromiumLaunchPersonaArgs(nil, first)
	found := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "--fingerprint-canvas-noise=") {
			found = true
		}
	}
	if !found || first.HasAudioNoise {
		t.Fatal("native canvas switch missing or unverified audio noise enabled")
	}
	for _, policy := range []*config.CloakBrowserConfig{nil, {NativeMode: "strict"}} {
		legacy := build(4242, false, nil, policy)
		if legacy.HasCanvasNoise || legacy.HasAudioNoise {
			t.Fatal("legacy identity gained active noise")
		}
	}
	strict := build(4242, true, nil, &config.CloakBrowserConfig{NativeMode: "strict"})
	if strict.HasCanvasNoise {
		t.Fatal("strict upstream mode gained active noise")
	}
	explicit := build(4242, true, map[string]any{"canvas:seed": 177, "audio:seed": 227, "screen.availWidth": 1200}, nil)
	if explicit.CanvasNoise != 177 || explicit.AudioNoise != 227 || explicit.Native.Screen.AvailWidth != 1200 {
		t.Fatal("explicit native configuration was replaced")
	}
}
