package spike_test

import (
	"net/url"
	"os"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

func TestPlaywrightBindEndpointWithCamoufox(t *testing.T) {
	camoufoxPath := os.Getenv("CAMOUFOX_PATH")
	if camoufoxPath == "" {
		camoufoxPath = "browsers/camoufox/Camoufox.app/Contents/MacOS/camoufox"
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

	userDataDir := t.TempDir()
	ctx, err := pw.Firefox.LaunchPersistentContext(userDataDir, playwright.BrowserTypeLaunchPersistentContextOptions{
		ExecutablePath: playwright.String(camoufoxPath),
		Headless:       playwright.Bool(true),
		NoViewport:     playwright.Bool(true),
	})
	if err != nil {
		t.Fatalf("launch persistent context: %v", err)
	}
	defer ctx.Close()

	browser := ctx.Browser()
	if browser == nil {
		t.Fatal("persistent context browser is nil")
	}

	result, err := browser.Bind("browseforge-bind-test", playwright.BrowserBindOptions{
		Host: playwright.String("127.0.0.1"),
		Port: playwright.Int(0),
	})
	if err != nil {
		t.Fatalf("browser.Bind: %v", err)
	}
	defer browser.Unbind()

	endpoint, err := url.Parse(result.Endpoint)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", result.Endpoint, err)
	}
	if endpoint.Path == "" || endpoint.Path == "/" {
		t.Fatalf("bind endpoint missing websocket path: %s", result.Endpoint)
	}

	pw2, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run second client: %v", err)
	}
	defer pw2.Stop()

	connected, err := pw2.Firefox.Connect(result.Endpoint)
	if err != nil {
		t.Fatalf("connect to bind endpoint %s: %v", result.Endpoint, err)
	}
	defer connected.Close()

	page, err := connected.NewPage(playwright.BrowserNewPageOptions{NoViewport: playwright.Bool(true)})
	if err != nil {
		t.Fatalf("new page through bind endpoint: %v", err)
	}
	defer page.Close()

	if _, err := page.Goto("about:blank"); err != nil {
		t.Fatalf("goto through bind endpoint: %v", err)
	}
}

func TestPlaywrightBindEndpointWithCloakBrowser(t *testing.T) {
	if os.Getenv("CLOAKBROWSER_SPIKE") != "1" {
		t.Skip("set CLOAKBROWSER_SPIKE=1 to run the CloakBrowser runtime spike")
	}

	cloakBrowserPath := os.Getenv("CLOAKBROWSER_PATH")
	if cloakBrowserPath == "" {
		cloakBrowserPath = "browsers/cloakbrowser/Chromium.app/Contents/MacOS/Chromium"
	}
	if _, err := os.Stat(cloakBrowserPath); os.IsNotExist(err) {
		t.Skipf("CloakBrowser not found at %s", cloakBrowserPath)
	}

	playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})

	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run: %v", err)
	}
	defer pw.Stop()

	userDataDir := t.TempDir()
	ctx, err := pw.Chromium.LaunchPersistentContext(userDataDir, playwright.BrowserTypeLaunchPersistentContextOptions{
		ExecutablePath: playwright.String(cloakBrowserPath),
		Headless:       playwright.Bool(false),
		Args: []string{
			"--fingerprint=123456789",
			"--fingerprint-timezone=UTC",
			"--fingerprint-locale=en-US",
		},
	})
	if err != nil {
		t.Fatalf("launch persistent context: %v", err)
	}
	defer ctx.Close()

	browser := ctx.Browser()
	if browser == nil {
		t.Fatal("persistent context browser is nil")
	}

	result, err := browser.Bind("browseforge-cloak-bind-test", playwright.BrowserBindOptions{
		Host: playwright.String("127.0.0.1"),
		Port: playwright.Int(0),
	})
	if err != nil {
		t.Fatalf("browser.Bind: %v", err)
	}
	defer browser.Unbind()

	endpoint, err := url.Parse(result.Endpoint)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", result.Endpoint, err)
	}
	if endpoint.Path == "" || endpoint.Path == "/" {
		t.Fatalf("bind endpoint missing websocket path: %s", result.Endpoint)
	}

	pw2, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run second client: %v", err)
	}
	defer pw2.Stop()

	connected, err := pw2.Chromium.Connect(result.Endpoint)
	if err != nil {
		t.Fatalf("connect to bind endpoint %s: %v", result.Endpoint, err)
	}
	defer connected.Close()

	page, err := connected.NewPage()
	if err != nil {
		t.Fatalf("new page through bind endpoint: %v", err)
	}
	defer page.Close()

	if _, err := page.Goto("about:blank"); err != nil {
		t.Fatalf("goto through bind endpoint: %v", err)
	}
}
