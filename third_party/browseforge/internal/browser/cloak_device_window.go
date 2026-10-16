package browser

import "fmt"

// A real window must fit the saved screen. Without an explicit size Chromium's
// default window may be taller than a generated device's screen.
func cloakBrowserDeviceWindowArgs(fp map[string]any, targetOS string) []string {
	width, hasWidth := fingerprintInt(fp, "screen.width")
	height, hasHeight := fingerprintInt(fp, "screen.height")
	if !hasWidth || !hasHeight {
		return nil
	}
	defaults := browseForgeDefaultScreen(targetOS)
	availWidth := clampScreenAvail(fingerprintIntDefault(fp, "screen.availWidth", int(width)), int(width))
	workAreaHeight := maxInt(int(height)-(defaults.Height-defaults.AvailHeight), 1)
	availHeight := clampScreenAvail(fingerprintIntDefault(fp, "screen.availHeight", workAreaHeight), workAreaHeight)
	// The free macOS provider derives its own work area and does not consume
	// every avail-height flag. Leave room for native application chrome too.
	windowHeight := maxInt(availHeight-(defaults.OuterHeight-defaults.InnerHeight), 1)
	return []string{
		"--window-position=0,0",
		fmt.Sprintf("--window-size=%d,%d", availWidth, windowHeight),
	}
}
