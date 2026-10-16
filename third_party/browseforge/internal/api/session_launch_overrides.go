package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode"

	"browseforge/internal/profile"
)

// Session overrides contain already-resolved runtime values. A managed local
// proxy is never part of the stored profile or its exported configuration.
type sessionLaunchOverrides struct {
	Timezone    string
	CountryCode string
	Locale      string
	Proxy       *profile.ProxyConfig
	Geolocation *profile.Geolocation
	Privacy     *profile.PrivacyConfig
}

var sessionCountryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

var sessionProxyRegionPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$`)

func decodeSessionLaunchOverrides(raw json.RawMessage) (*sessionLaunchOverrides, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("launch_overrides must be an object")
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("launch_overrides requires at least one runtime field")
	}
	for key := range fields {
		if key != "timezone" && key != "proxy" && key != "locale" && key != "geolocation" && key != "privacy" && key != "country_code" {
			return nil, fmt.Errorf("launch_overrides contains an unsupported runtime field")
		}
	}
	overrides := &sessionLaunchOverrides{}
	if value, present := fields["country_code"]; present {
		if err := json.Unmarshal(value, &overrides.CountryCode); err != nil || !sessionCountryCodePattern.MatchString(overrides.CountryCode) {
			return nil, fmt.Errorf("launch_overrides.country_code must be a two-letter uppercase ISO country code")
		}
	}
	if value, present := fields["locale"]; present {
		if err := json.Unmarshal(value, &overrides.Locale); err != nil || overrides.Locale == "" {
			return nil, fmt.Errorf("launch_overrides.locale must be a nonempty BCP 47 language tag")
		}
		if err := profile.ValidateLaunchOverrides(&profile.LaunchOverrides{Locale: overrides.Locale}); err != nil {
			return nil, err
		}
	}
	if value, present := fields["geolocation"]; present && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		var geoFields map[string]json.RawMessage
		if err := json.Unmarshal(value, &geoFields); err != nil || len(geoFields) != 3 {
			return nil, fmt.Errorf("launch_overrides.geolocation requires latitude, longitude and accuracy")
		}
		for key, field := range geoFields {
			if (key != "latitude" && key != "longitude" && key != "accuracy") || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
				return nil, fmt.Errorf("launch_overrides.geolocation contains an invalid field")
			}
		}
		geo := &profile.Geolocation{}
		if err := json.Unmarshal(value, geo); err != nil {
			return nil, fmt.Errorf("launch_overrides.geolocation requires numeric regional coordinates")
		}
		if err := profile.ValidateGeolocation(geo); err != nil {
			return nil, err
		}
		overrides.Geolocation = geo
	}
	if value, present := fields["privacy"]; present {
		var privacyFields map[string]json.RawMessage
		if err := json.Unmarshal(value, &privacyFields); err != nil || len(privacyFields) != 1 || privacyFields["mode"] == nil {
			return nil, fmt.Errorf("launch_overrides.privacy requires only mode")
		}
		privacy := &profile.PrivacyConfig{}
		if err := json.Unmarshal(value, privacy); err != nil {
			return nil, fmt.Errorf("launch_overrides.privacy.mode is invalid")
		}
		if _, err := profile.NormalizePrivacy(privacy); err != nil {
			return nil, err
		}
		overrides.Privacy = privacy
	}
	if value, present := fields["timezone"]; present {
		if err := json.Unmarshal(value, &overrides.Timezone); err != nil || overrides.Timezone == "" {
			return nil, fmt.Errorf("launch_overrides.timezone must be a nonempty IANA timezone")
		}
		if err := profile.ValidateLaunchOverrides(&profile.LaunchOverrides{Timezone: overrides.Timezone}); err != nil {
			return nil, err
		}
	}
	if value, present := fields["proxy"]; present {
		proxy, err := decodeSessionLaunchProxy(value)
		if err != nil {
			return nil, err
		}
		overrides.Proxy = proxy
	}
	return overrides, nil
}

func decodeSessionLaunchProxy(raw json.RawMessage) (*profile.ProxyConfig, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) == 0 {
		return nil, fmt.Errorf("launch_overrides.proxy must be a managed HTTP proxy object")
	}
	for key := range fields {
		switch key {
		case "type", "host", "port", "username", "password", "region":
		default:
			return nil, fmt.Errorf("launch_overrides.proxy contains an unsupported field")
		}
	}
	proxy := &profile.ProxyConfig{}
	for name, target := range map[string]*string{"type": &proxy.Type, "host": &proxy.Host, "username": &proxy.Username, "password": &proxy.Password, "region": &proxy.Region} {
		if value, present := fields[name]; present {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, target) != nil {
				return nil, fmt.Errorf("launch_overrides.proxy.%s must be a string", name)
			}
		}
	}
	if proxy.Type != "http" || proxy.Host != "127.0.0.1" {
		return nil, fmt.Errorf("launch_overrides.proxy must use http on 127.0.0.1")
	}
	value, present := fields["port"]
	if !present || json.Unmarshal(value, &proxy.Port) != nil || proxy.Port < 1 || proxy.Port > 65535 {
		return nil, fmt.Errorf("launch_overrides.proxy.port must be between 1 and 65535")
	}
	for _, credential := range []string{proxy.Username, proxy.Password} {
		if len(credential) > 4096 {
			return nil, fmt.Errorf("launch_overrides.proxy credentials are too long")
		}
		for _, character := range credential {
			if unicode.IsControl(character) {
				return nil, fmt.Errorf("launch_overrides.proxy credentials must not contain control characters")
			}
		}
	}
	if proxy.Region != "" && !sessionProxyRegionPattern.MatchString(proxy.Region) {
		return nil, fmt.Errorf("launch_overrides.proxy.region must be a region label of at most 64 characters")
	}
	return proxy, nil
}

func profileForSessionLaunch(stored *profile.Profile, overrides *sessionLaunchOverrides) (*profile.Profile, error) {
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("copy stored profile: %w", err)
	}
	var launch profile.Profile
	if err := json.Unmarshal(data, &launch); err != nil {
		return nil, fmt.Errorf("copy stored profile: %w", err)
	}
	if overrides != nil && (overrides.Timezone != "" || overrides.Locale != "") {
		if launch.LaunchOverrides == nil {
			launch.LaunchOverrides = &profile.LaunchOverrides{}
		}
		if overrides.Timezone != "" {
			launch.LaunchOverrides.Timezone = overrides.Timezone
		}
		if overrides.Locale != "" {
			launch.LaunchOverrides.Locale = overrides.Locale
		}
	}
	if overrides != nil && overrides.Proxy != nil {
		proxy := *overrides.Proxy
		launch.SessionProxy = &proxy
	}
	if overrides != nil {
		launch.SessionCountryCode = overrides.CountryCode
	}
	launch.SessionPrivacy = &profile.PrivacyConfig{Mode: "standard"}
	if overrides != nil && overrides.Privacy != nil {
		privacy := *overrides.Privacy
		launch.SessionPrivacy = &privacy
	}
	if overrides != nil && overrides.Geolocation != nil {
		geo := *overrides.Geolocation
		launch.SessionGeolocation = &geo
	}
	return &launch, nil
}
