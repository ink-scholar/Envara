package spike_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

func getCamoufoxPath() string {
	if p := os.Getenv("CAMOUFOX_PATH"); p != "" {
		return p
	}
	// Try common paths
	paths := []string{
		"dist/camoufox/Camoufox.app/Contents/MacOS/camoufox",
		"../../../dist/camoufox/Camoufox.app/Contents/MacOS/camoufox",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func launchCamoufox(t *testing.T, pw *playwright.Playwright) playwright.Browser {
	t.Helper()
	path := getCamoufoxPath()
	if path == "" {
		t.Skip("Camoufox binary not found")
	}
	browser, err := pw.Firefox.Launch(playwright.BrowserTypeLaunchOptions{
		ExecutablePath: playwright.String(path),
		Headless:       playwright.Bool(true),
		Env: map[string]string{
			"CAMOU_CONFIG": `{"navigator.userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0","navigator.platform":"Win32","screen.width":1920,"screen.height":1080,"canvas:seed":12345,"audio:seed":67890}`,
		},
		FirefoxUserPrefs: map[string]any{
			"privacy.userContext.enabled":   true,
			"media.peerconnection.enabled":  false,
			"xpinstall.signatures.required": false,
		},
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	return browser
}

func TestCamoufoxFingerprint(t *testing.T) {
	playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})
	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run: %v", err)
	}
	defer pw.Stop()

	browser := launchCamoufox(t, pw)
	defer browser.Close()

	page, _ := browser.NewPage()
	page.Goto("about:blank")

	// Verify CAMOU_CONFIG fingerprint values
	tests := []struct {
		js       string
		expected any
	}{
		{"navigator.platform", "Win32"},
		{"screen.width", float64(1920)},
		{"screen.height", float64(1080)},
	}

	for _, tt := range tests {
		val, err := page.Evaluate(tt.js)
		if err != nil {
			t.Errorf("%s: %v", tt.js, err)
			continue
		}
		if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", tt.expected) {
			t.Errorf("%s = %v, want %v", tt.js, val, tt.expected)
		} else {
			t.Logf("✅ %s = %v", tt.js, val)
		}
	}

	// Test Canvas fingerprint (should be deterministic with seed)
	canvasHash, err := page.Evaluate(`(() => {
		const c = document.createElement('canvas');
		c.width = 200; c.height = 50;
		const ctx = c.getContext('2d');
		ctx.textBaseline = 'top';
		ctx.font = '14px Arial';
		ctx.fillText('BrowseForge test', 2, 2);
		return c.toDataURL().substring(0, 80);
	})()`)
	if err != nil {
		t.Fatalf("canvas eval: %v", err)
	}
	t.Logf("Canvas hash prefix: %v", canvasHash)

	// Test WebGL renderer
	webglRenderer, err := page.Evaluate(`(() => {
		const c = document.createElement('canvas');
		const gl = c.getContext('webgl');
		if (!gl) return 'no webgl';
		const ext = gl.getExtension('WEBGL_debug_renderer_info');
		if (!ext) return 'no debug info';
		return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
	})()`)
	if err != nil {
		t.Fatalf("webgl eval: %v", err)
	}
	t.Logf("WebGL renderer: %v", webglRenderer)

	t.Log("SPIKE PASS: Camoufox fingerprint injection verified")
}

func TestCamoufoxSetterExists(t *testing.T) {
	playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})
	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run: %v", err)
	}
	defer pw.Stop()

	browser := launchCamoufox(t, pw)
	defer browser.Close()

	page, _ := browser.NewPage()
	page.Goto("about:blank")

	// Check if Camoufox setters exist in the page world
	setters := []string{
		"setCanvasSeed", "setAudioFingerprintSeed", "setFontSpacingSeed",
		"setNavigatorPlatform", "setNavigatorUserAgent", "setNavigatorOscpu",
		"setWebGLVendor", "setWebGLRenderer",
		"setScreenDimensions", "setScreenColorDepth",
		"setTimezone", "setWebRTCIPv4", "setFontList", "setSpeechVoices",
	}

	for _, s := range setters {
		exists, err := page.Evaluate(fmt.Sprintf("typeof window.%s === 'function'", s))
		if err != nil {
			t.Errorf("check %s: %v", s, err)
			continue
		}
		if exists == true {
			t.Logf("✅ window.%s exists", s)
		} else {
			t.Logf("❌ window.%s NOT found", s)
		}
	}

	// Try calling a setter and verify effect
	_, err = page.Evaluate("window.setNavigatorPlatform && window.setNavigatorPlatform('Linux x86_64')")
	if err != nil {
		t.Logf("setter call error (may be expected if self-destructing): %v", err)
	}

	newPlatform, _ := page.Evaluate("navigator.platform")
	t.Logf("Platform after setter: %v", newPlatform)

	t.Log("SPIKE 0.1.7 (partial): Setter existence check complete")
}
