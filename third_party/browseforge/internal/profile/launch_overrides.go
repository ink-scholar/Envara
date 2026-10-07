package profile

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // Fixed IANA zones also work in a packaged Windows app.
)

// LaunchOverrides records user-selected fixed launch values separately from
// generated fingerprint pool data. An omitted or empty field keeps automatic
// GeoIP / runtime-policy behavior; it never treats an old pool value as manual.
type LaunchOverrides struct {
	Timezone string `json:"timezone,omitempty"`
	Locale   string `json:"locale,omitempty"`
	TargetOS string `json:"target_os,omitempty"`
}

var launchLocalePattern = regexp.MustCompile(`^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$`)

func ValidateLaunchOverrides(overrides *LaunchOverrides) error {
	if overrides == nil {
		return nil
	}
	if overrides.Timezone != "" {
		if overrides.Timezone == "Local" || strings.TrimSpace(overrides.Timezone) != overrides.Timezone {
			return fmt.Errorf("launch_overrides.timezone must be a fixed IANA timezone")
		}
		if _, err := time.LoadLocation(overrides.Timezone); err != nil {
			return fmt.Errorf("launch_overrides.timezone is invalid: %w", err)
		}
	}
	if overrides.Locale != "" && !launchLocalePattern.MatchString(overrides.Locale) {
		return fmt.Errorf("launch_overrides.locale must be a BCP 47 language tag such as en-US or zh-CN")
	}
	switch overrides.TargetOS {
	case "", "macos", "windows", "linux":
	default:
		return fmt.Errorf("launch_overrides.target_os must be macos, windows, or linux")
	}
	return nil
}
