package api

import (
	"browseforge/internal/profile"
	"encoding/json"
	"testing"
)

func TestSessionPrivacyLocaleAndRegionalGeoAreRuntimeOnly(t *testing.T) {
	overrides, err := decodeSessionLaunchOverrides(json.RawMessage(`{"timezone":"Asia/Manila","locale":"en-PH","geolocation":{"latitude":14.6,"longitude":121,"accuracy":50000},"privacy":{"mode":"strict"}}`))
	if err != nil {
		t.Fatal(err)
	}
	stored := &profile.Profile{ID: "fixture", LaunchOverrides: &profile.LaunchOverrides{Locale: "zh-CN"}}
	launch, err := profileForSessionLaunch(stored, overrides)
	if err != nil {
		t.Fatal(err)
	}
	if launch.LaunchOverrides.Locale != "en-PH" || launch.SessionPrivacy.Mode != "strict" || launch.SessionGeolocation.Latitude != 14.6 {
		t.Fatal("runtime context was not applied")
	}
	launch.SessionPrivacy.Mode = "off"
	launch.SessionGeolocation.Latitude = 0
	if overrides.Privacy.Mode != "strict" || overrides.Geolocation.Latitude != 14.6 || stored.SessionPrivacy != nil || stored.SessionGeolocation != nil || stored.LaunchOverrides.Locale != "zh-CN" {
		t.Fatal("runtime launch mutated stored or caller values")
	}
	export, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(export, &document); err != nil {
		t.Fatal(err)
	}
	if document["privacy"] != nil || document["geolocation"] != nil {
		t.Fatal("ephemeral values leaked")
	}
	defaultLaunch, err := profileForSessionLaunch(stored, nil)
	if err != nil || defaultLaunch.SessionPrivacy.Mode != "standard" || defaultLaunch.SessionGeolocation != nil {
		t.Fatal("raw REST default privacy is not protected")
	}
}

func TestSessionPrivacyRejectsUnboundedOrUnknownValues(t *testing.T) {
	for _, raw := range []string{
		`{"privacy":{"mode":"unknown"}}`, `{"privacy":{"mode":"off","bypass":true}}`, `{"privacy":null}`,
		`{"geolocation":{"latitude":91,"longitude":0,"accuracy":50000}}`, `{"geolocation":{"latitude":0,"longitude":0,"accuracy":10}}`,
		`{"geolocation":{"latitude":0,"longitude":0}}`, `{"geolocation":{"latitude":0,"longitude":0,"accuracy":50000,"address":"street"}}`,
		`{"geolocation":{"latitude":null,"longitude":0,"accuracy":50000}}`, `{"locale":"en_US"}`,
	} {
		if _, err := decodeSessionLaunchOverrides(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid override accepted: %s", raw)
		}
	}
	if value, err := decodeSessionLaunchOverrides(json.RawMessage(`{"geolocation":null}`)); err != nil || value.Geolocation != nil {
		t.Fatal("explicit location denial rejected")
	}
}
