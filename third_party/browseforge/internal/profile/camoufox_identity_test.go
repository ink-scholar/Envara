package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCamoufoxCatalogNativeSchemaOSAndCompleteWebGL(t *testing.T) {
	propertiesData, err := os.ReadFile("camoufox-data/native-properties.json")
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
	catalog, err := loadCamoufoxIdentityCatalog()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, targetOS := range []string{"macos", "windows", "linux"} {
		if len(catalog[targetOS]) != 8 {
			t.Fatalf("%s catalog has %d tuples", targetOS, len(catalog[targetOS]))
		}
		for _, tuple := range catalog[targetOS] {
			if seen[tuple.ID] {
				t.Fatalf("duplicate tuple ID %q", tuple.ID)
			}
			seen[tuple.ID] = true
			fp := tuple.Fingerprint
			for key, value := range fp {
				if !camoufoxNativeValueMatchesType(value, types[key]) {
					t.Errorf("%s: %s has unsupported native value %T", tuple.ID, key, value)
				}
				if strings.HasPrefix(key, "locale:") || strings.HasPrefix(key, "geolocation:") || strings.HasPrefix(key, "webrtc:") || key == "timezone" || key == "navigator.language" || key == "navigator.languages" || key == "headers.Accept-Language" {
					t.Errorf("%s: network-dependent field %q must remain a session value", tuple.ID, key)
				}
			}
			ua := fp["navigator.userAgent"].(string)
			if !strings.Contains(ua, "Firefox/135.") || strings.Contains(ua, "Chrome/") {
				t.Errorf("%s: wrong browser family or pinned major", tuple.ID)
			}
			platform := fp["navigator.platform"].(string)
			if (targetOS == "macos" && (platform != "MacIntel" || !strings.Contains(ua, "Macintosh"))) ||
				(targetOS == "windows" && (platform != "Win32" || !strings.Contains(ua, "Windows NT"))) ||
				(targetOS == "linux" && (!strings.HasPrefix(platform, "Linux") || !strings.Contains(ua, "Linux"))) {
				t.Errorf("%s: OS, UA and platform disagree", tuple.ID)
			}
			for _, key := range []string{"webGl:vendor", "webGl:renderer", "webGl:supportedExtensions", "webGl:parameters", "webGl:shaderPrecisionFormats", "webGl:contextAttributes", "webGl2:supportedExtensions", "webGl2:parameters", "webGl2:shaderPrecisionFormats", "webGl2:contextAttributes"} {
				if fp[key] == nil {
					t.Errorf("%s: partial WebGL family lacks %s", tuple.ID, key)
				}
			}
			width, height := fp["screen.width"].(float64), fp["screen.height"].(float64)
			if width < 1024 || width > 2560 || height < 720 || height > 1800 || fp["screen.availWidth"].(float64) > width || fp["screen.availHeight"].(float64) > height {
				t.Errorf("%s: inconsistent desktop geometry", tuple.ID)
			}
			if cpu := fp["navigator.hardwareConcurrency"].(float64); cpu < 1 || cpu > 256 {
				t.Errorf("%s: invalid desktop CPU parameter", tuple.ID)
			}
			if fonts, ok := fp["fonts"].([]any); !ok || len(fonts) == 0 {
				t.Errorf("%s: target OS fonts are absent", tuple.ID)
			}
		}
	}
}

func camoufoxNativeValueMatchesType(value any, kind string) bool {
	switch kind {
	case "str":
		_, ok := value.(string)
		return ok
	case "bool":
		_, ok := value.(bool)
		return ok
	case "int", "uint", "double":
		number, ok := value.(float64)
		return ok && !math.IsNaN(number) && !math.IsInf(number, 0) && (kind == "double" || math.Trunc(number) == number) && (kind != "uint" || number >= 0)
	case "array":
		_, ok := value.([]any)
		return ok
	case "dict":
		_, ok := value.(map[string]any)
		return ok
	default:
		return false
	}
}

func TestCamoufoxIdentityCatalogHashMatchesProvenance(t *testing.T) {
	data, err := os.ReadFile("camoufox-data/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		CatalogSHA256          string `json:"catalogSHA256"`
		NativePropertiesSHA256 string `json:"nativePropertiesSHA256"`
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	properties, err := os.ReadFile("camoufox-data/native-properties.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		data []byte
		hash string
	}{{camoufoxIdentityCatalog, provenance.CatalogSHA256}, {properties, provenance.NativePropertiesSHA256}} {
		digest := sha256.Sum256(entry.data)
		if hex.EncodeToString(digest[:]) != entry.hash {
			t.Fatal("Camoufox catalog/native schema changed without updating its provenance")
		}
	}
}

func TestCamoufoxIdentityReturnsIndependentWholeTuplesAndSupportedNoise(t *testing.T) {
	zeroes := func() *bytes.Reader { return bytes.NewReader(make([]byte, 128)) }
	id, first, err := newCamoufoxIdentity(zeroes(), "macos")
	if err != nil {
		t.Fatal(err)
	}
	if id != "macos-01" || first["fonts:spacing_seed"] != int64(0) || first["canvas:aaOffset"] != int64(-50) || first["canvas:aaCapOffset"] != true {
		t.Fatal("deterministic entropy did not preserve the official parameter ranges")
	}
	_, second, err := newCamoufoxIdentity(zeroes(), "macos")
	if err != nil {
		t.Fatal(err)
	}
	first["fonts"].([]any)[0] = "test-only mutation"
	first["webGl:parameters"].(map[string]any)["test-only mutation"] = true
	_, third, err := newCamoufoxIdentity(zeroes(), "macos")
	if err != nil || !reflect.DeepEqual(second, third) {
		t.Fatal("a profile mutation changed another identity or the embedded catalog")
	}
	for _, key := range []string{"audio:seed", "canvas:seed", "_meta", "profile_dir"} {
		if _, present := second[key]; present {
			t.Errorf("unsupported or private generated field %q", key)
		}
	}
}

func TestCamoufoxNewIdentitiesUseFreshEntropyWithoutChangingTuples(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		id, fp, err := NewCamoufoxIdentity("windows")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "windows-") || fp["navigator.platform"] != "Win32" {
			t.Fatal("identity did not retain the selected complete OS tuple")
		}
		spacing, aliasing := fp["fonts:spacing_seed"].(int64), fp["canvas:aaOffset"].(int64)
		if spacing < 0 || spacing >= 1<<30 || aliasing < -50 || aliasing > 50 {
			t.Fatal("generated noise is outside official bounds")
		}
		encoded, _ := json.Marshal([]any{id, spacing, aliasing})
		if seen[string(encoded)] {
			t.Fatal("fresh identities unexpectedly reused the same tuple and noise")
		}
		seen[string(encoded)] = true
	}
}

func TestCamoufoxIdentityRefusesUnknownOSAndEntropyFailure(t *testing.T) {
	if _, _, err := NewCamoufoxIdentity("unknown"); err == nil {
		t.Fatal("unknown OS silently selected another device family")
	}
	if _, _, err := newCamoufoxIdentity(bytes.NewReader(nil), "linux"); err == nil {
		t.Fatal("entropy failure silently produced a predictable profile")
	}
}
