package api

import (
	"encoding/json"
	"fmt"

	"browseforge/internal/profile"
)

// Session overrides accept only the already-resolved timezone. Other profile
// values remain owned by stored configuration, including a fixed locale/OS.
func decodeSessionLaunchTimezone(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", fmt.Errorf("launch_overrides must be an object containing timezone")
	}
	if len(fields) != 1 {
		return "", fmt.Errorf("launch_overrides accepts only a nonempty timezone")
	}
	value, ok := fields["timezone"]
	if !ok {
		return "", fmt.Errorf("launch_overrides accepts only timezone")
	}
	var timezone string
	if err := json.Unmarshal(value, &timezone); err != nil || timezone == "" {
		return "", fmt.Errorf("launch_overrides.timezone must be a nonempty IANA timezone")
	}
	if err := profile.ValidateLaunchOverrides(&profile.LaunchOverrides{Timezone: timezone}); err != nil {
		return "", err
	}
	return timezone, nil
}

func profileForSessionLaunch(stored *profile.Profile, timezone string) (*profile.Profile, error) {
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("copy stored profile: %w", err)
	}
	var launch profile.Profile
	if err := json.Unmarshal(data, &launch); err != nil {
		return nil, fmt.Errorf("copy stored profile: %w", err)
	}
	if timezone != "" {
		if launch.LaunchOverrides == nil {
			launch.LaunchOverrides = &profile.LaunchOverrides{}
		}
		launch.LaunchOverrides.Timezone = timezone
	}
	return &launch, nil
}
