package profile

import (
	"encoding/json"
	"testing"
)

func fixedCamoufoxDeviceContract(width, height int, dpr float64) map[string]any {
	return map[string]any{
		"screen.width": width, "screen.height": height,
		"screen.availWidth": width, "screen.availHeight": height,
		"screen.availTop": 0, "screen.availLeft": 0,
		"window.outerWidth": width, "window.outerHeight": height,
		"window.screenX": 0, "window.screenY": 0,
		"window.devicePixelRatio": dpr, "navigator.hardwareConcurrency": 8,
	}
}

func fixedDeviceJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertFixedCamoufoxDeviceContract(t *testing.T, p *Profile, expected map[string]any) {
	t.Helper()
	for key, want := range expected {
		if fixedDeviceJSON(t, p.Fingerprint[key]) != fixedDeviceJSON(t, want) {
			t.Errorf("fixed field %s=%v, want %v", key, p.Fingerprint[key], want)
		}
		if p.FingerprintGeneration != nil {
			if _, generated := p.FingerprintGeneration.GeneratedFields[key]; generated {
				t.Errorf("explicit fixed field %s became generator-owned", key)
			}
		}
	}
	for _, key := range []string{"screen.devicePixelRatio", "navigator.deviceMemory", "window.innerWidth", "window.innerHeight"} {
		if _, exists := p.Fingerprint[key]; exists {
			t.Errorf("fixed Camoufox device unexpectedly gained %s", key)
		}
	}
	for _, key := range []string{"fonts", "navigator.userAgent", "navigator.platform", "webGl:vendor", "webGl:renderer", "webGl:supportedExtensions", "webGl:parameters", "webGl:shaderPrecisionFormats", "webGl:contextAttributes", "webGl2:supportedExtensions", "webGl2:parameters", "webGl2:shaderPrecisionFormats", "webGl2:contextAttributes", "fonts:spacing_seed", "canvas:aaOffset", "canvas:aaCapOffset"} {
		if p.Fingerprint[key] == nil || p.FingerprintGeneration == nil || p.FingerprintGeneration.GeneratedFields[key] == nil {
			t.Errorf("fixed geometry lost provider-owned field %s", key)
		}
	}
}

func TestFixedDeviceCamoufoxGeometrySurvivesGenerationReloadCloneAndImport(t *testing.T) {
	for _, spec := range []struct {
		os            string
		width, height int
		dpr           float64
	}{{"macos", 1440, 900, 2}, {"windows", 1920, 1080, 1}, {"linux", 1920, 1080, 1}} {
		t.Run(spec.os, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := fixedCamoufoxDeviceContract(spec.width, spec.height, spec.dpr)
			p := &Profile{Name: "Fixed device", RuntimeID: "camoufox", Identity: &IdentityConfig{TargetOS: spec.os}, Fingerprint: fixedCamoufoxDeviceContract(spec.width, spec.height, spec.dpr)}
			if err := store.Create(p); err != nil {
				t.Fatal(err)
			}
			assertFixedCamoufoxDeviceContract(t, p, want)
			before := fixedDeviceJSON(t, p.Fingerprint)
			generation := fixedDeviceJSON(t, p.FingerprintGeneration)

			reloaded, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := reloaded.Get(p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if fixedDeviceJSON(t, loaded.Fingerprint) != before || fixedDeviceJSON(t, loaded.FingerprintGeneration) != generation {
				t.Fatal("reload changed the fixed device or generator provenance")
			}
			if _, err := reloaded.Update(p.ID, map[string]any{"name": "Renamed fixed device"}); err != nil {
				t.Fatal(err)
			}
			if fixedDeviceJSON(t, loaded.Fingerprint) != before || fixedDeviceJSON(t, loaded.FingerprintGeneration) != generation {
				t.Fatal("unrelated edit changed the fixed device or generator provenance")
			}

			clone, err := reloaded.Duplicate(p.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertFixedCamoufoxDeviceContract(t, clone, want)
			if clone.ID == p.ID || clone.FingerprintSeed != 0 || fixedDeviceJSON(t, clone.Fingerprint) == before {
				t.Fatal("clone did not create a fresh structured provider identity")
			}
			sourceNoise := []any{loaded.Fingerprint["fonts:spacing_seed"], loaded.Fingerprint["canvas:aaOffset"]}
			cloneNoise := []any{clone.Fingerprint["fonts:spacing_seed"], clone.Fingerprint["canvas:aaOffset"]}
			if fixedDeviceJSON(t, sourceNoise) == fixedDeviceJSON(t, cloneNoise) {
				t.Fatal("clone reused the source identity's generated noise")
			}
			if fixedDeviceJSON(t, loaded.Fingerprint) != before || fixedDeviceJSON(t, loaded.FingerprintGeneration) != generation {
				t.Fatal("cloning changed the original fingerprint or provenance")
			}

			var imported Profile
			if err := json.Unmarshal([]byte(fixedDeviceJSON(t, loaded)), &imported); err != nil {
				t.Fatal(err)
			}
			imported.ID = ""
			if err := reloaded.CreatePreservingIdentity(&imported); err != nil {
				t.Fatal(err)
			}
			if fixedDeviceJSON(t, imported.Fingerprint) != before || fixedDeviceJSON(t, imported.FingerprintGeneration) != generation || imported.FingerprintSeed != 0 {
				t.Fatal("import changed the exact saved fixed device identity")
			}
		})
	}
}
