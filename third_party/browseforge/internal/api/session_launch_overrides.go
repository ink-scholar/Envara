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
	Timezone string
	Proxy    *profile.ProxyConfig
}

var sessionProxyRegionPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$`)

func decodeSessionLaunchOverrides(raw json.RawMessage) (*sessionLaunchOverrides, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("launch_overrides must be an object containing timezone or proxy")
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("launch_overrides requires timezone or proxy")
	}
	for key := range fields {
		if key != "timezone" && key != "proxy" {
			return nil, fmt.Errorf("launch_overrides accepts only timezone and proxy")
		}
	}
	overrides := &sessionLaunchOverrides{}
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
	if overrides != nil && overrides.Timezone != "" {
		if launch.LaunchOverrides == nil {
			launch.LaunchOverrides = &profile.LaunchOverrides{}
		}
		launch.LaunchOverrides.Timezone = overrides.Timezone
	}
	if overrides != nil && overrides.Proxy != nil {
		proxy := *overrides.Proxy
		launch.SessionProxy = &proxy
	}
	return &launch, nil
}
