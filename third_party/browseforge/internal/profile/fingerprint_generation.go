package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
)

// FingerprintGeneration records values supplied by one version of a provider
// generator. Explicit edits transfer ownership to the caller, including edits
// which keep the same value.
type FingerprintGeneration struct {
	Provider        string         `json:"provider"`
	Version         int            `json:"version"`
	TupleID         string         `json:"tuple_id"`
	GeneratedFields map[string]any `json:"generated_fields"`
}

type chromiumDeviceTuple struct {
	id                      string
	width, height, cpu, ram int
	dpr                     float64
}

func chromiumDeviceTuples(targetOS string) []chromiumDeviceTuple {
	if targetOS == "macos" {
		return []chromiumDeviceTuple{
			{"macos-1280x800-4-4-1-v1", 1280, 800, 4, 4, 1},
			{"macos-1440x900-8-8-2-v1", 1440, 900, 8, 8, 2},
			{"macos-1920x1080-8-8-1-v1", 1920, 1080, 8, 8, 1},
		}
	}
	return []chromiumDeviceTuple{
		{targetOS + "-1366x768-4-4-1-v1", 1366, 768, 4, 4, 1},
		{targetOS + "-1920x1080-8-8-1-v1", 1920, 1080, 8, 8, 1},
		{targetOS + "-1600x900-8-8-1-v1", 1600, 900, 8, 8, 1},
	}
}

func fingerprintTargetOS(p *Profile, hostOS string) (string, error) {
	targetOS := ""
	if p.LaunchOverrides != nil {
		targetOS = p.LaunchOverrides.TargetOS
	}
	if targetOS == "" && p.Identity != nil {
		targetOS = p.Identity.TargetOS
	}
	if targetOS == "" {
		targetOS = hostOS
		if targetOS == "darwin" {
			targetOS = "macos"
		} else if targetOS == "windows" || targetOS == "win32" {
			targetOS = "windows"
		}
	}
	switch targetOS {
	case "macos", "windows", "linux":
		return targetOS, nil
	default:
		return "", fmt.Errorf("fingerprint target OS must be macos, windows, or linux")
	}
}

func generateProfileFingerprint(p *Profile) error {
	if p.RuntimeID != "camoufox" && !usesFingerprintSeed(p.RuntimeID) {
		return nil
	}
	targetOS, err := fingerprintTargetOS(p, runtime.GOOS)
	if err != nil {
		return err
	}
	if (p.Identity == nil || p.Identity.TargetOS == "") && (p.LaunchOverrides == nil || p.LaunchOverrides.TargetOS == "") {
		if p.Identity == nil {
			p.Identity = &IdentityConfig{}
		}
		p.Identity.TargetOS = targetOS
	}
	p.FingerprintGeneration = nil
	var tupleID string
	var fields map[string]any
	if p.RuntimeID == "camoufox" {
		tupleID, fields, err = NewCamoufoxIdentity(targetOS)
		if err != nil {
			return err
		}
	} else {
		tuples := chromiumDeviceTuples(targetOS)
		tuple := tuples[uint64(p.FingerprintSeed)%uint64(len(tuples))]
		tupleID = tuple.id
		fields = map[string]any{
			"screen.width": tuple.width, "screen.height": tuple.height,
			"screen.devicePixelRatio":       tuple.dpr,
			"navigator.hardwareConcurrency": tuple.cpu, "navigator.deviceMemory": tuple.ram,
		}
	}
	if p.Fingerprint == nil {
		p.Fingerprint = make(map[string]any)
	}
	generated := make(map[string]any)
	for key, value := range fields {
		if _, explicit := p.Fingerprint[key]; !explicit {
			p.Fingerprint[key] = value
			generated[key] = value
		}
	}
	encoded, err := json.Marshal(generated)
	if err != nil {
		return fmt.Errorf("copy generated fingerprint provenance: %w", err)
	}
	var recorded map[string]any
	if err := json.Unmarshal(encoded, &recorded); err != nil {
		return fmt.Errorf("copy generated fingerprint provenance: %w", err)
	}
	p.FingerprintGeneration = &FingerprintGeneration{Provider: p.RuntimeID, Version: 1, TupleID: tupleID, GeneratedFields: recorded}
	return nil
}

func resetGeneratedFingerprint(p *Profile) {
	if generation := p.FingerprintGeneration; generation != nil {
		for key, generated := range generation.GeneratedFields {
			current, currentErr := json.Marshal(p.Fingerprint[key])
			original, originalErr := json.Marshal(generated)
			if currentErr == nil && originalErr == nil && bytes.Equal(current, original) {
				delete(p.Fingerprint, key)
			}
		}
	}
	p.FingerprintGeneration = nil
	// These are per-identity noise inputs, including legacy records which lack
	// generation metadata. Explicit hardware, GPU and font constraints stay.
	for _, key := range []string{"canvas:seed", "audio:seed", "fonts:spacing_seed", "canvas:aaOffset", "canvas:aaCapOffset"} {
		delete(p.Fingerprint, key)
	}
}
