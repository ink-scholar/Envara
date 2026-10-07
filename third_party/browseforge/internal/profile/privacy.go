package profile

import (
	"fmt"
	"math"
)

// Runtime-only context values. They never belong to profile exports or storage.
type PrivacyConfig struct {
	Mode string `json:"mode"`
}

type Geolocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
}

func NormalizePrivacy(value *PrivacyConfig) (*PrivacyConfig, error) {
	if value == nil {
		return &PrivacyConfig{Mode: "standard"}, nil
	}
	switch value.Mode {
	case "off", "standard", "strict":
		return &PrivacyConfig{Mode: value.Mode}, nil
	default:
		return nil, fmt.Errorf("privacy.mode must be off, standard or strict")
	}
}

func ValidateGeolocation(value *Geolocation) error {
	if value == nil {
		return nil
	}
	if math.IsNaN(value.Latitude) || math.IsInf(value.Latitude, 0) || value.Latitude < -90 || value.Latitude > 90 ||
		math.IsNaN(value.Longitude) || math.IsInf(value.Longitude, 0) || value.Longitude < -180 || value.Longitude > 180 ||
		math.IsNaN(value.Accuracy) || math.IsInf(value.Accuracy, 0) || value.Accuracy < 1000 || value.Accuracy > 1000000 {
		return fmt.Errorf("geolocation requires valid coordinates and regional accuracy between 1000 and 1000000 metres")
	}
	return nil
}
