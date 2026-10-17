package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
)

func posixShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func macLocaleLauncherSource(binaryPath, locale string) string {
	// Cocoa controls Chromium's ICU/application locale on macOS. Playwright's
	// argument validator rejects the required positional array value; this
	// exec-only shim forwards all its existing browser arguments unchanged.
	return "#!/bin/sh\nexec " + posixShellQuote(binaryPath) + " -AppleLanguages " + posixShellQuote("("+locale+")") + " \"$@\"\n"
}

func prepareMacLocaleExecutable(binaryPath, profileDir, locale string) (string, error) {
	launchersDir := filepath.Join(profileDir, ".envara-native-launchers")
	if err := os.MkdirAll(launchersDir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(launchersDir, 0700); err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(binaryPath + "\x00" + locale))
	launcherPath := filepath.Join(launchersDir, hex.EncodeToString(key[:12])+".sh")
	temporary, err := os.CreateTemp(launchersDir, ".launch-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0700); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.WriteString(macLocaleLauncherSource(binaryPath, locale)); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, launcherPath); err != nil {
		return "", err
	}
	return launcherPath, nil
}

type macLocaleNavigationHistory struct {
	CurrentIndex *int `json:"currentIndex"`
	Entries      []struct {
		URL            string `json:"url"`
		UserTypedURL   string `json:"userTypedURL"`
		TransitionType string `json:"transitionType"`
	} `json:"entries"`
}

func isMacLocaleStartupHistory(value any, locale string) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}
	var history macLocaleNavigationHistory
	if err := json.Unmarshal(data, &history); err != nil || history.CurrentIndex == nil || *history.CurrentIndex != 0 || len(history.Entries) != 1 {
		return false
	}
	entry := history.Entries[0]
	expectedURL := fmt.Sprintf("http://(%s)/", locale)
	return entry.TransitionType == "auto_toplevel" && strings.EqualFold(entry.URL, expectedURL) &&
		(entry.UserTypedURL == "" || strings.EqualFold(entry.UserTypedURL, expectedURL))
}

func cleanMacLocaleStartupPage(ctx playwright.BrowserContext, locale string) {
	// Cocoa's array value also produces a startup URL in the free macOS v145
	// Chromium build. Inspect the original CDP history, not the error-page URL,
	// and remove only that automatically generated entry. User/restored pages
	// and their navigation history are never removed.
	deadline := time.Now().Add(time.Second)
	for {
		// Concurrent browser startup can deliver the Cocoa argument page after
		// the initial context snapshot. Inspect newly arrived pages as well.
		for _, page := range ctx.Pages() {
			if page.IsClosed() {
				continue
			}
			cdp, err := ctx.NewCDPSession(page)
			if err != nil {
				continue
			}
			history, historyErr := cdp.Send("Page.getNavigationHistory", nil)
			_ = cdp.Detach()
			if historyErr == nil && isMacLocaleStartupHistory(history, locale) {
				if len(ctx.Pages()) == 1 {
					if _, err := ctx.NewPage(); err != nil {
						return
					}
				}
				_ = page.Close()
				return
			}
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
