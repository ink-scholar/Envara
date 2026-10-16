package browser

import (
	"reflect"
	"testing"
)

func TestCloakDeviceWindowFitsGeneratedAndExplicitScreens(t *testing.T) {
	for _, tc := range []struct {
		name, os string
		fp       map[string]any
		want     []string
	}{
		{"legacy automatic", "macos", nil, nil},
		{"partial override", "macos", map[string]any{"screen.width": 1280}, nil},
		{"small macOS tuple", "macos", map[string]any{"screen.width": 1280, "screen.height": 800}, []string{"--window-position=0,0", "--window-size=1280,680"}},
		{"Windows tuple", "windows", map[string]any{"screen.width": 1920, "screen.height": 1080}, []string{"--window-position=0,0", "--window-size=1920,948"}},
		{"explicit work area", "macos", map[string]any{"screen.width": 1440, "screen.height": 900, "screen.availWidth": 1300, "screen.availHeight": 800}, []string{"--window-position=0,0", "--window-size=1300,713"}},
		{"work area cannot exceed screen", "macos", map[string]any{"screen.width": 1280, "screen.height": 800, "screen.availWidth": 1920, "screen.availHeight": 1080}, []string{"--window-position=0,0", "--window-size=1280,680"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloakBrowserDeviceWindowArgs(tc.fp, tc.os); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("window args = %v, want %v", got, tc.want)
			}
		})
	}
}
