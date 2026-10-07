package browser

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

func TestMacLocaleLauncherQuotesExecutableAndForwardsArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX launcher is used only by the macOS native runtime")
	}
	dir := t.TempDir()
	// Deliberate shell syntax in an actual file name verifies it stays data.
	binaryPath := filepath.Join(dir, "Browser' `literal` $(literal).sh")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	launcher, err := prepareMacLocaleExecutable(binaryPath, dir, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(launcher)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("launcher is not private and executable: %v %v", info, err)
	}
	output, err := exec.Command(launcher, "--remote-debugging-pipe", "--user-data-dir=/example directory", "--fingerprint=42").CombinedOutput()
	if err != nil {
		t.Fatalf("exec-only shim failed: %v %s", err, output)
	}
	want := "-AppleLanguages\n(en-US)\n--remote-debugging-pipe\n--user-data-dir=/example directory\n--fingerprint=42\n"
	if string(output) != want {
		t.Fatalf("launcher changed arguments: got %q want %q", output, want)
	}
	if strings.Contains(macLocaleLauncherSource(binaryPath, "en-US"), "AppleLocale") {
		t.Fatal("the locale launcher added an unnecessary Cocoa startup argument")
	}
}

func TestMacStartupCleanupOnlyMatchesFreshGeneratedLocaleTab(t *testing.T) {
	entry := map[string]any{"url": "http://(en-us)/", "transitionType": "auto_toplevel"}
	for _, test := range []struct {
		name    string
		history any
		want    bool
	}{
		{"generated", map[string]any{"currentIndex": 0, "entries": []any{entry}}, true},
		{"different locale", map[string]any{"currentIndex": 0, "entries": []any{map[string]any{"url": "http://(zh-cn)/", "transitionType": "auto_toplevel"}}}, false},
		{"generated with Chromium typed URL field", map[string]any{"currentIndex": 0, "entries": []any{map[string]any{"url": "http://(en-us)/", "transitionType": "auto_toplevel", "userTypedURL": "http://(en-us)/"}}}, true},
		{"typed transition at same URL", map[string]any{"currentIndex": 0, "entries": []any{map[string]any{"url": "http://(en-us)/", "transitionType": "typed", "userTypedURL": "http://(en-us)/"}}}, false},
		{"mismatched typed URL", map[string]any{"currentIndex": 0, "entries": []any{map[string]any{"url": "http://(en-us)/", "transitionType": "auto_toplevel", "userTypedURL": "https://user.example/"}}}, false},
		{"user link", map[string]any{"currentIndex": 0, "entries": []any{map[string]any{"url": "http://(en-us)/", "transitionType": "link"}}}, false},
		{"restored history", map[string]any{"currentIndex": 0, "entries": []any{entry, map[string]any{"url": "https://example.com"}}}, false},
		{"noninitial index", map[string]any{"currentIndex": 1, "entries": []any{entry}}, false},
		{"missing index", map[string]any{"entries": []any{entry}}, false},
		{"malformed response", "history unavailable", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isMacLocaleStartupHistory(test.history, "en-US"); got != test.want {
				t.Fatalf("cleanup match=%v, want %v", got, test.want)
			}
		})
	}
}

type lateMacStartupPage struct {
	desktopTestPage
	closes int
}

func (p *lateMacStartupPage) Close(...playwright.PageCloseOptions) error {
	p.closes++
	p.closeExternally()
	return nil
}

type macStartupCDP struct {
	playwright.CDPSession
	history any
}

func (c *macStartupCDP) Send(string, map[string]any) (any, error) { return c.history, nil }
func (c *macStartupCDP) Detach() error                            { return nil }

type lateMacStartupContext struct {
	playwright.BrowserContext
	user, generated *lateMacStartupPage
	pageReads       int
}

func (c *lateMacStartupContext) Pages() []playwright.Page {
	c.pageReads++
	if c.pageReads == 1 {
		return []playwright.Page{c.user}
	}
	return []playwright.Page{c.user, c.generated}
}

func (c *lateMacStartupContext) NewCDPSession(page any) (playwright.CDPSession, error) {
	url := "https://user.example/"
	if page == c.generated {
		url = "http://(zh-cn)/"
	}
	return &macStartupCDP{history: map[string]any{
		"currentIndex": 0,
		"entries":      []any{map[string]any{"url": url, "userTypedURL": url, "transitionType": "auto_toplevel"}},
	}}, nil
}

func TestMacStartupCleanupFindsLateGeneratedPageAndPreservesUserPage(t *testing.T) {
	ctx := &lateMacStartupContext{user: &lateMacStartupPage{}, generated: &lateMacStartupPage{}}
	cleanMacLocaleStartupPage(ctx, "zh-CN")
	if ctx.generated.closes != 1 || ctx.user.closes != 0 {
		t.Fatalf("startup cleanup closed generated=%d user=%d pages", ctx.generated.closes, ctx.user.closes)
	}
}
