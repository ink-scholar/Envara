package browser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"browseforge/internal/fingerprint"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

func (m *Manager) launchFirefox(p *profile.Profile) (*Session, error) {
	privacyMode, err := browserPrivacyMode(p)
	if err != nil {
		return nil, err
	}
	desc, err := m.runtimes.ResolveProfile(p)
	if err != nil {
		return nil, err
	}
	camoufoxPath := desc.BinaryPath
	if _, err := os.Stat(camoufoxPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("runtimes.camoufox.binary_path not found: %s", camoufoxPath)
	}

	// Build CAMOU_CONFIG: start from profile fingerprint, then overlay GeoIP.
	// WebGL strategy: keep each WebGL family only when the profile contains the
	// complete parameter family; partial renderer/vendor spoofing is less
	// coherent than letting Camoufox generate a native fallback.
	config := make(map[string]any)
	for k, v := range p.Fingerprint {
		config[k] = v
	}
	normalizeCamouWebGLProfile(config)
	if err := profile.ValidateLaunchOverrides(p.LaunchOverrides); err != nil {
		return nil, err
	}

	effectiveProxy := m.effectiveProxy(p)
	if effectiveProxy.Proxy != nil && requiresLaunchGeo(p) {
		proxy := effectiveProxy.Proxy
		tz, locale := fingerprint.DetectProxyGeoResult(proxy.Type, proxy.Host, proxy.Port, proxy.Username, proxy.Password)
		config["timezone"] = tz
		parts := splitLocale(locale)
		config["locale:language"] = parts[0]
		config["locale:region"] = parts[1]
	} else if requiresLaunchGeo(p) {
		tz, locale := fingerprint.DetectLocalGeoResult()
		config["timezone"] = tz
		parts := splitLocale(locale)
		config["locale:language"] = parts[0]
		config["locale:region"] = parts[1]
	}
	if err := applyCamoufoxLaunchOverrides(config, p, runtime.GOARCH); err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode camoufox config: %w", err)
	}

	userDataDir, err := filepath.Abs(filepath.Join(p.ProfileDir, "browser-data"))
	if err != nil {
		return nil, fmt.Errorf("browser data path: %w", err)
	}
	if err := os.MkdirAll(userDataDir, 0755); err != nil {
		return nil, fmt.Errorf("create browser data dir: %w", err)
	}
	cleanProfileLocks(userDataDir)

	absPath, err := filepath.Abs(camoufoxPath)
	if err != nil {
		return nil, fmt.Errorf("camoufox path: %w", err)
	}

	downloadsDir, err := filepath.Abs(filepath.Join(p.ProfileDir, "downloads"))
	if err != nil {
		return nil, fmt.Errorf("downloads path: %w", err)
	}
	if err := os.MkdirAll(downloadsDir, 0755); err != nil {
		return nil, fmt.Errorf("create downloads dir: %w", err)
	}

	opts := playwright.BrowserTypeLaunchPersistentContextOptions{
		ExecutablePath:  playwright.String(absPath),
		Headless:        playwright.Bool(false),
		AcceptDownloads: playwright.Bool(true),
		Env: camoufoxEnv(configJSON, map[string]string{
			"DISPLAY":               os.Getenv("DISPLAY"),
			"HOME":                  os.Getenv("HOME"),
			"LIBGL_ALWAYS_SOFTWARE": os.Getenv("LIBGL_ALWAYS_SOFTWARE"),
		}),
		FirefoxUserPrefs: map[string]any{
			"xpinstall.signatures.required":          false,
			"browser.download.folderList":            2,
			"browser.download.dir":                   downloadsDir,
			"browser.download.useDownloadDir":        true,
			"browser.helperApps.neverAsk.saveToDisk": "application/octet-stream,image/jpeg,image/png,application/pdf,application/zip",
			"webgl.disabled":                         false,
			"webgl.force-enabled":                    true,
			"webgl.forbid-software":                  false,
		},
		NoViewport: playwright.Bool(true),
	}
	if privacyMode != "off" {
		opts.ServiceWorkers = playwright.ServiceWorkerPolicyBlock
	}
	for key, value := range firefoxPrivacyPrefs(privacyMode, p.SessionGeolocation != nil) {
		opts.FirefoxUserPrefs[key] = value
	}

	var relay *SOCKS5Relay
	if effectiveProxy.Proxy != nil {
		proxy := effectiveProxy.Proxy
		needsRelay := proxy.Type == "socks5" && proxy.Username != ""
		if needsRelay {
			upstream := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
			var localAddr string
			relay, localAddr, err = StartSOCKS5Relay(upstream, proxy.Username, proxy.Password)
			if err != nil {
				return nil, fmt.Errorf("socks5 relay: %w", err)
			}
			opts.Proxy = &playwright.Proxy{Server: "socks5://" + localAddr}
		} else {
			server := fmt.Sprintf("%s://%s:%d", proxy.Type, proxy.Host, proxy.Port)
			opts.Proxy = &playwright.Proxy{
				Server:   server,
				Username: playwright.String(proxy.Username),
				Password: playwright.String(proxy.Password),
			}
		}
	}

	ctx, err := m.pw.Firefox.LaunchPersistentContext(userDataDir, opts)
	if err != nil {
		if relay != nil {
			relay.Close()
		}
		return nil, fmt.Errorf("launch firefox: %w", humanizeError(err))
	}
	privacyState, err := installBrowserPrivacy(ctx, p, false)
	if err != nil {
		if relay != nil {
			relay.Close()
		}
		ctx.Close()
		return nil, fmt.Errorf("install browser privacy: %w", err)
	}

	dlDir := downloadsDir
	onDl := func(d playwright.Download) { go d.SaveAs(filepath.Join(dlDir, d.SuggestedFilename())) }
	for _, pg := range ctx.Pages() {
		pg.OnDownload(onDl)
	}
	ctx.OnPage(func(pg playwright.Page) { pg.OnDownload(onDl) })

	pages := ctx.Pages()
	var page playwright.Page
	if len(pages) > 0 {
		page = pages[0]
	} else {
		page, err = ctx.NewPage()
		if err != nil {
			if relay != nil {
				relay.Close()
			}
			ctx.Close()
			return nil, fmt.Errorf("new page: %w", err)
		}
	}

	return &Session{
		ID:             fmt.Sprintf("sess_%s", p.ID),
		routeDigest:    SessionRouteDigest(effectiveProxy.Proxy),
		ProfileID:      p.ID,
		RuntimeID:      string(bfruntime.Camoufox),
		Context:        ctx,
		Page:           page,
		relay:          relay,
		ProfileDir:     p.ProfileDir,
		UserDataDir:    userDataDir,
		ExecutablePath: absPath,
		Privacy:        privacyState,
	}, nil
}

const camouConfigChunkSize = 24 * 1024

func normalizeCamouWebGLProfile(config map[string]any) {
	if !hasCompleteCamouWebGLProfile(config) {
		removeCamouWebGLKeys(config, "webGl:")
	}
	if hasCamouWebGLKeys(config, "webGl2:") && !hasCompleteCamouWebGL2Profile(config) {
		removeCamouWebGLKeys(config, "webGl2:")
	}
}

func hasCompleteCamouWebGLProfile(config map[string]any) bool {
	return hasCamouWebGLKeys(config, "webGl:",
		"renderer",
		"vendor",
		"supportedExtensions",
		"parameters",
		"shaderPrecisionFormats",
		"contextAttributes",
	)
}

func hasCompleteCamouWebGL2Profile(config map[string]any) bool {
	return hasCamouWebGLKeys(config, "webGl2:",
		"supportedExtensions",
		"parameters",
		"shaderPrecisionFormats",
		"contextAttributes",
	)
}

func hasCamouWebGLKeys(config map[string]any, prefix string, names ...string) bool {
	if len(names) == 0 {
		for key := range config {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
		return false
	}
	for _, name := range names {
		if _, ok := config[prefix+name]; !ok {
			return false
		}
	}
	return true
}

func removeCamouWebGLKeys(config map[string]any, prefixes ...string) {
	if len(prefixes) == 0 {
		prefixes = []string{"webGl:", "webGl2:"}
	}
	for key := range config {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				delete(config, key)
				break
			}
		}
	}
}

func camoufoxEnv(configJSON []byte, base map[string]string) map[string]string {
	configText := string(configJSON)
	env := make(map[string]string, len(base)+1+(len(configText)/camouConfigChunkSize))
	for k, v := range base {
		env[k] = v
	}
	if len(configText) <= camouConfigChunkSize {
		env["CAMOU_CONFIG"] = configText
		return env
	}
	for i, chunk := 0, 1; i < len(configText); chunk++ {
		end := i + camouConfigChunkSize
		if end >= len(configText) {
			end = len(configText)
		} else {
			for end > i && !utf8.RuneStart(configText[end]) {
				end--
			}
		}
		env[fmt.Sprintf("CAMOU_CONFIG_%d", chunk)] = configText[i:end]
		i = end
	}
	return env
}
