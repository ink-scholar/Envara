package browser

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/playwright-community/playwright-go"
)

// The pinned Camoufox runs Playwright init scripts in an isolated world. Its
// supported add-on API provides native, before-handshake WebSocket filtering
// without changing page constructors or enabling main-world automation.
const firefoxWebSocketBackground = `
const matches = (host, domain) => host === domain || host.endsWith('.' + domain);
const hostname = raw => { try { return new URL(raw).hostname.toLowerCase().replace(/\.$/, ''); } catch { return ''; } };
const loopback = host => host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127(?:\.[0-9]{1,3}){3}$/.test(host) || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(host);
browser.webRequest.onBeforeRequest.addListener(details => {
  try {
    const requestURL = new URL(details.url), host = hostname(details.url);
    const ancestors = details.frameAncestors || [];
    const top = ancestors.find(frame => frame.frameId === 0);
    const first = hostname(top ? top.url : details.frameId === 0 ? (details.documentUrl || details.originUrl) : '');
    if (loopback(host) && !loopback(first)) return { cancel: true };
    const domain = policy.domains.find(value => matches(host, value));
    const exempt = first && (matches(host, first) || matches(first, host) || policy.serviceRoots[domain]?.some(value => matches(first, value)));
    return { cancel: policy.mode !== 'off' && Boolean(domain) && !exempt };
  } catch { return { cancel: true }; }
}, { urls: ['ws://*/*', 'wss://*/*'], types: ['websocket'] }, ['blocking']);
// This message is available only after the blocking listener is registered.
// No remote page receives an extension API or startup control channel.
browser.runtime.onMessage.addListener((message, sender) => {
  if (message === 'envara-websocket-privacy-ready' && sender.url === policy.readinessURL) return Promise.resolve(true);
});
`

const firefoxWebSocketReadiness = `browser.runtime.sendMessage('envara-websocket-privacy-ready').then(ready => {
  if (ready === true) document.documentElement.dataset.envaraPrivacyReady = 'true';
}).catch(() => {});`

type firefoxPrivacyAddon struct {
	directory string
	readyURL  string
}

func (a *firefoxPrivacyAddon) Close() {
	// Removal is retried by subsequent close paths if the filesystem refused it.
	if err := os.RemoveAll(a.directory); err != nil {
		slog.Warn("WebSocket privacy add-on cleanup failed", "error", err)
	}
}

func (a *firefoxPrivacyAddon) WaitReady(ctx playwright.BrowserContext) error {
	page, err := ctx.NewPage()
	if err != nil {
		return err
	}
	defer page.Close()
	// A local, app-owned document verifies extension startup without any loopback
	// listener, stored credential, proxy bypass, or network request.
	if _, err := page.Goto(a.readyURL); err != nil {
		return err
	}
	handle, err := page.WaitForFunction(`() => document.documentElement.dataset.envaraPrivacyReady === 'true'`, nil, playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(15000)})
	if err != nil {
		return fmt.Errorf("Camoufox WebSocket privacy add-on did not become ready: %w", err)
	}
	handle.Dispose()
	return nil
}

func prepareFirefoxPrivacyAddon(mode string) (_ *firefoxPrivacyAddon, err error) {
	directory, err := os.MkdirTemp("", "envara-websocket-privacy-")
	if err != nil {
		return nil, err
	}
	readinessPath := filepath.ToSlash(filepath.Join(directory, "readiness.html"))
	if !strings.HasPrefix(readinessPath, "/") {
		readinessPath = "/" + readinessPath
	}
	addon := &firefoxPrivacyAddon{directory: directory, readyURL: (&url.URL{Scheme: "file", Path: readinessPath}).String()}
	defer func() {
		if err != nil {
			addon.Close()
		}
	}()
	manifest := map[string]any{"manifest_version": 2, "name": "Envara WebSocket privacy", "version": "1.0.0",
		"browser_specific_settings": map[string]any{"gecko": map[string]string{"id": "websocket-privacy@envara.local"}},
		"permissions":               []string{"webRequest", "webRequestBlocking", "<all_urls>"}, "background": map[string]any{"scripts": []string{"background.js"}},
		"content_scripts": []any{map[string]any{"matches": []string{addon.readyURL}, "js": []string{"readiness.js"}, "run_at": "document_end"}}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	domains := append([]string{}, standardTrackerDomains...)
	if mode == "strict" {
		domains = append(domains, strictTrackerDomains...)
	}
	policy, err := json.Marshal(map[string]any{"mode": mode, "domains": domains, "serviceRoots": trackerServiceRoots, "readinessURL": addon.readyURL})
	if err != nil {
		return nil, err
	}
	background := "const policy = " + string(policy) + ";\n" + firefoxWebSocketBackground
	if err = os.WriteFile(filepath.Join(directory, "manifest.json"), manifestBytes, 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(directory, "background.js"), []byte(background), 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(directory, "readiness.js"), []byte(firefoxWebSocketReadiness), 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(directory, "readiness.html"), []byte("<!doctype html><html><head><meta charset=\"utf-8\"></head><body></body></html>"), 0600); err != nil {
		return nil, err
	}
	return addon, nil
}
