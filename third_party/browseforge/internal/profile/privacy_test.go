package profile

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestPrivacyValuesAreValidatedAndEphemeral(t *testing.T) {
	privacy, err := NormalizePrivacy(nil)
	if err != nil || privacy.Mode != "standard" {
		t.Fatal("missing privacy does not default to standard")
	}
	if _, err := NormalizePrivacy(&PrivacyConfig{Mode: "unknown"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	geo := &Geolocation{Latitude: 14.6, Longitude: 121, Accuracy: 50000}
	if err := ValidateGeolocation(geo); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*Geolocation{{Latitude: 91, Accuracy: 50000}, {Longitude: math.Inf(1), Accuracy: 50000}, {Accuracy: 10}} {
		if ValidateGeolocation(bad) == nil {
			t.Fatalf("invalid geo accepted: %#v", bad)
		}
	}
	value, err := json.Marshal(&Profile{ID: "fixture", SessionPrivacy: &PrivacyConfig{Mode: "strict"}, SessionGeolocation: geo})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(value), "strict") || strings.Contains(string(value), "latitude") || strings.Contains(string(value), "50000") {
		t.Fatal("ephemeral privacy values leaked into profile export")
	}
}
