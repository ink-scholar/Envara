package spike_test

import (
	"os"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

func TestPlaywrightLaunchCamoufox(t *testing.T) {
	camoufoxPath := os.Getenv("CAMOUFOX_PATH")
	if camoufoxPath == "" {
		camoufoxPath = "dist/camoufox/Camoufox.app/Contents/MacOS/camoufox"
	}
	if _, err := os.Stat(camoufoxPath); os.IsNotExist(err) {
		t.Skipf("Camoufox not found at %s", camoufoxPath)
	}

	playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})

	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run: %v", err)
	}
	defer pw.Stop()

	browser, err := pw.Firefox.Launch(playwright.BrowserTypeLaunchOptions{
		ExecutablePath: playwright.String(camoufoxPath),
		Headless:       playwright.Bool(true),
		Env: map[string]string{
			"CAMOU_CONFIG": `{"navigator.userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0","navigator.platform":"Win32","screen.width":1920,"screen.height":1080}`,
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
	defer browser.Close()

	page, err := browser.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}

	if _, err = page.Goto("about:blank"); err != nil {
		t.Fatalf("goto: %v", err)
	}

	ua, _ := page.Evaluate("navigator.userAgent")
	t.Logf("UA: %v", ua)

	platform, _ := page.Evaluate("navigator.platform")
	t.Logf("Platform: %v", platform)

	if platform != "Win32" {
		t.Errorf("expected Win32, got %v", platform)
	}

	t.Log("SPIKE PASS: Playwright launches and controls Camoufox with CAMOU_CONFIG")
}
