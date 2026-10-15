package browser

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func TestAppendProfileFingerprintArgsDevicePixelRatio(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{name: "integer one", value: 1, want: "1"},
		{name: "integer retina", value: int64(2), want: "2"},
		{name: "JSON integer", value: float64(2), want: "2"},
		{name: "fractional", value: 1.5, want: "1.5"},
		{name: "JSON number", value: json.Number("1.25"), want: "1.25"},
		{name: "minimum", value: 0.5, want: "0.5"},
		{name: "maximum", value: 4.0, want: "4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := []string{"--no-first-run"}
			args := appendProfileFingerprintArgs(base, map[string]any{
				"screen.width":            1440,
				"screen.devicePixelRatio": tc.value,
			}, "", "", "")
			want := []string{
				"--no-first-run",
				"--fingerprint-screen-width=1440",
				"--force-device-scale-factor=" + tc.want,
				"--fingerprint-screen-device-scale-factor=" + tc.want,
			}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("launch args = %#v, want %#v", args, want)
			}
		})
	}
}

func TestAppendProfileFingerprintArgsIgnoresMissingOrInvalidDevicePixelRatio(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fingerprint map[string]any
	}{
		{name: "nil fingerprint"},
		{name: "missing field", fingerprint: map[string]any{}},
		{name: "null", fingerprint: map[string]any{"screen.devicePixelRatio": nil}},
		{name: "empty string", fingerprint: map[string]any{"screen.devicePixelRatio": ""}},
		{name: "numeric string", fingerprint: map[string]any{"screen.devicePixelRatio": "2"}},
		{name: "boolean", fingerprint: map[string]any{"screen.devicePixelRatio": true}},
		{name: "zero", fingerprint: map[string]any{"screen.devicePixelRatio": 0}},
		{name: "negative", fingerprint: map[string]any{"screen.devicePixelRatio": -1}},
		{name: "below minimum", fingerprint: map[string]any{"screen.devicePixelRatio": 0.49}},
		{name: "above maximum", fingerprint: map[string]any{"screen.devicePixelRatio": 4.01}},
		{name: "not a number", fingerprint: map[string]any{"screen.devicePixelRatio": math.NaN()}},
		{name: "positive infinity", fingerprint: map[string]any{"screen.devicePixelRatio": math.Inf(1)}},
		{name: "negative infinity", fingerprint: map[string]any{"screen.devicePixelRatio": math.Inf(-1)}},
		{name: "invalid JSON number", fingerprint: map[string]any{"screen.devicePixelRatio": json.Number("invalid")}},
		{name: "overflow JSON number", fingerprint: map[string]any{"screen.devicePixelRatio": json.Number("1e999")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := []string{"--no-first-run"}
			args := appendProfileFingerprintArgs(base, tc.fingerprint, "", "", "")
			if !reflect.DeepEqual(args, base) {
				t.Fatalf("launch args changed without a valid DPR: %#v", args)
			}
		})
	}
}
