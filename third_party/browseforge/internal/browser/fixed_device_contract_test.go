package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/playwright-community/playwright-go"
)

func TestFixedDeviceCamoufoxNativeSchemaAndLaunchPipeline(t *testing.T) {
	want := map[string]any{
		"screen.width": 1440, "screen.height": 900,
		"screen.availWidth": 1440, "screen.availHeight": 900,
		"screen.availTop": 0, "screen.availLeft": 0,
		"window.outerWidth": 1440, "window.outerHeight": 900,
		"window.screenX": 0, "window.screenY": 0,
		"window.devicePixelRatio": 2, "navigator.hardwareConcurrency": 8,
	}
	propertiesData, err := os.ReadFile("../profile/camoufox-data/native-properties.json")
	if err != nil {
		t.Fatal(err)
	}
	var properties []struct{ Property, Type string }
	if err := json.Unmarshal(propertiesData, &properties); err != nil {
		t.Fatal(err)
	}
	types := make(map[string]string)
	for _, property := range properties {
		types[property.Property] = property.Type
	}
	for key := range want {
		if kind := types[key]; kind != "uint" && kind != "int" && kind != "double" {
			t.Errorf("fixed device field %s is not a supported native number: %q", key, kind)
		}
	}
	if types["navigator.deviceMemory"] != "" || types["screen.devicePixelRatio"] != "" {
		t.Fatal("Camoufox native device schema changed; review the provider mapping")
	}

	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := make(map[string]any, len(want))
	for key, value := range want {
		fingerprint[key] = value
	}
	p := &profile.Profile{Name: "Fixed native device", RuntimeID: "camoufox", Fingerprint: fingerprint,
		LaunchOverrides: &profile.LaunchOverrides{TargetOS: "macos", Timezone: "UTC", Locale: "en-US"}}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(p.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "camoufox-fixture")
	if err := os.WriteFile(binary, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg := &config.Config{Runtimes: map[string]config.RuntimeConfig{"camoufox": {BinaryPath: binary, Enabled: &enabled}}}
	launchErr := errors.New("captured fixed device launch")
	browserType := &capturingBrowserType{t: t, launchErr: launchErr}
	manager := &Manager{cfg: cfg, runtimes: bfruntime.NewRegistry(cfg), pw: &playwright.Playwright{Firefox: browserType}}
	if _, err := manager.launchFirefox(p); !errors.Is(err, launchErr) || browserType.calls != 1 {
		t.Fatalf("captured launch calls=%d, error=%v", browserType.calls, err)
	}
	opts := browserType.options
	if opts.NoViewport == nil || !*opts.NoViewport || opts.Viewport != nil || opts.DeviceScaleFactor != nil {
		t.Fatal("Playwright overrode the native Camoufox viewport or DPR")
	}
	configText := opts.Env["CAMOU_CONFIG"]
	if configText == "" {
		for chunk := 1; ; chunk++ {
			part := opts.Env[fmt.Sprintf("CAMOU_CONFIG_%d", chunk)]
			if part == "" {
				break
			}
			configText += part
		}
	}
	var native map[string]any
	if err := json.Unmarshal([]byte(configText), &native); err != nil {
		t.Fatal(err)
	}
	for key, value := range want {
		got, _ := json.Marshal(native[key])
		expected, _ := json.Marshal(value)
		if string(got) != string(expected) {
			t.Errorf("native CAMOU_CONFIG changed %s", key)
		}
	}
	for _, key := range []string{"screen.devicePixelRatio", "navigator.deviceMemory", "window.innerWidth", "window.innerHeight"} {
		if _, exists := native[key]; exists {
			t.Errorf("native launch gained unsupported or provider-owned field %s", key)
		}
	}
	if !hasCompleteCamouWebGLProfile(native) || !hasCompleteCamouWebGL2Profile(native) {
		t.Fatal("fixed device launch dropped a complete provider WebGL family")
	}
	after, err := json.Marshal(p.Fingerprint)
	if err != nil || string(after) != string(before) {
		t.Fatal("launch rewrote the saved fixed device fingerprint")
	}
}

func TestFixedDeviceBrowseForgeNativePersonaAndArguments(t *testing.T) {
	t.Setenv("BROWSEFORGE_DOCKER_GPU_MODE", "native")
	for _, spec := range []struct {
		os, platform  string
		width, height int
		dpr           int
	}{{"macos", "MacIntel", 1440, 900, 2}, {"windows", "Win32", 1920, 1080, 1}, {"linux", "Linux x86_64", 1920, 1080, 1}} {
		t.Run(spec.os, func(t *testing.T) {
			store, err := profile.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			p := &profile.Profile{Name: "Fixed native Chromium device", RuntimeID: "browseforge-chromium", FingerprintSeed: 42,
				Identity: &profile.IdentityConfig{TargetOS: spec.os}, Fingerprint: map[string]any{
					"screen.width": spec.width, "screen.height": spec.height, "screen.devicePixelRatio": spec.dpr,
					"navigator.hardwareConcurrency": 8, "navigator.deviceMemory": 8,
				}}
			if err := store.Create(p); err != nil {
				t.Fatal(err)
			}
			if p.FingerprintGeneration == nil || len(p.FingerprintGeneration.GeneratedFields) != 0 || p.FingerprintSeed != 42 {
				t.Fatal("fixed Chromium fields became generated or lost the versioned identity marker")
			}
			persona, err := buildChromiumLaunchPersona(p, bfruntime.BrowseForgeChromium, spec.platform, "UTC", "en-US", "", "amd64", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateBrowseForgePersonaContract(persona.Native); err != nil {
				t.Fatal(err)
			}
			screen := persona.Native.Screen
			if screen.Width != spec.width || screen.Height != spec.height || screen.DPR != float64(spec.dpr) || persona.Native.Hardware.HardwareConcurrency != 8 || persona.Native.Hardware.DeviceMemoryGB != 8 {
				t.Fatalf("fixed native device was replaced: %+v %+v", screen, persona.Native.Hardware)
			}
			if screen.AvailWidth != screen.Width || screen.AvailHeight > screen.Height || screen.OuterWidth != screen.AvailWidth || screen.OuterHeight != screen.AvailHeight || screen.InnerWidth > screen.OuterWidth || screen.InnerHeight >= screen.OuterHeight || screen.ViewportWidth != screen.InnerWidth || screen.ViewportHeight != screen.InnerHeight {
				t.Fatalf("native window and viewport disagree with fixed screen: %+v", screen)
			}
			args := appendChromiumLaunchPersonaArgs(nil, persona)
			args = append(args, browseForgeChromiumWindowArgs(persona)...)
			for _, want := range []string{
				fmt.Sprintf("--fingerprint-screen-width=%d", spec.width), fmt.Sprintf("--fingerprint-screen-height=%d", spec.height),
				"--fingerprint-hardware-concurrency=8", "--fingerprint-device-memory=8",
				fmt.Sprintf("--force-device-scale-factor=%d", spec.dpr), fmt.Sprintf("--fingerprint-screen-device-scale-factor=%d", spec.dpr),
				fmt.Sprintf("--fingerprint-screen-avail-width=%d", screen.AvailWidth), fmt.Sprintf("--fingerprint-screen-avail-height=%d", screen.AvailHeight),
				fmt.Sprintf("--window-size=%d,%d", screen.OuterWidth, screen.OuterHeight),
			} {
				if !containsArg(args, want) {
					t.Errorf("fixed device launch argument missing: %s", want)
				}
			}
		})
	}
}
