package browser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"browseforge/internal/config"
	"browseforge/internal/fingerprint"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

const chromiumWebRTCIPHandlingArg = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"

const chromiumAutomationMitigationInitScript = `(() => {
	// Keep Playwright's injected globals out of detector-visible namespaces. The
	// native BrowseForge Chromium patch owns navigator.webdriver so the property
	// remains a native getter returning false instead of a JS monkey patch.
	for (const key of Object.keys(window)) {
		if (/^(cdc_|__webdriver|__driver_evaluate|__webdriver_script_fn|__selenium)/.test(key)) {
			try { delete window[key]; } catch (_) {}
		}
	}
	if (!("chrome" in window)) {
		try {
			Object.defineProperty(window, "chrome", {
				value: { runtime: {} },
				configurable: true,
				enumerable: true,
				writable: false
			});
		} catch (_) {}
	}
})();`

func (m *Manager) launchChromium(p *profile.Profile) (*Session, error) {
	privacyMode, err := browserPrivacyMode(p)
	if err != nil {
		return nil, err
	}
	desc, err := m.runtimes.ResolveProfile(p)
	if err != nil {
		return nil, err
	}
	chromiumPath := desc.BinaryPath
	if chromiumPath == "" {
		return nil, fmt.Errorf("runtimes.%s.binary_path is not configured", desc.ID)
	}

	userDataDir, err := filepath.Abs(filepath.Join(p.ProfileDir, "browser-data"))
	if err != nil {
		return nil, fmt.Errorf("browser data path: %w", err)
	}
	if err := os.MkdirAll(userDataDir, 0755); err != nil {
		return nil, fmt.Errorf("create browser data dir: %w", err)
	}
	cleanProfileLocks(userDataDir)

	absChromiumPath, err := filepath.Abs(chromiumPath)
	if err != nil {
		return nil, fmt.Errorf("%s path: %w", desc.ID, err)
	}

	args := []string{
		"--no-first-run",
		"--test-type",
		chromiumWebRTCIPHandlingArg,
	}
	args = append(args, chromiumPrivacyArgs(privacyMode)...)
	if p.FingerprintSeed > 0 {
		args = append(args, fmt.Sprintf("--fingerprint=%d", p.FingerprintSeed))
	}

	policy, err := chromiumLaunchPolicyForProfile(p, m.cfg.ChromiumRuntimeSettings(string(desc.ID)))
	if err != nil {
		return nil, err
	}
	if quota := cloakStorageQuotaMB(policy); quota < 0 {
		return nil, fmt.Errorf("%s storage_quota_mb must be >= 0", desc.ID)
	}

	var tz, locale, proxyRegion string
	geoResult := fingerprint.GeoDetectionResult{}
	effectiveProxy := m.effectiveProxy(p)
	if effectiveProxy.Proxy != nil {
		proxy := effectiveProxy.Proxy
		if desc.ID == bfruntime.BrowseForgeChromium {
			proxyRegion, err = sanitizeBrowseForgeProxyRegion(proxy.Region)
			if err != nil {
				return nil, err
			}
			if proxyRegion == "" {
				return nil, fmt.Errorf("browseforge-chromium proxy_region is required when a proxy is configured; set proxy.region to a geographic label such as us-ny or tw-taipei via the Dashboard proxy settings, update_profile MCP tool, or PUT /api/profiles/{id}")
			}
		} else {
			proxyRegion = strings.TrimSpace(proxy.Region)
		}
		if requiresLaunchGeo(p) || (desc.ID == bfruntime.BrowseForgeChromium && p.SessionCountryCode == "") {
			geoResult = fingerprint.DetectProxyGeo(proxy.Type, proxy.Host, proxy.Port, proxy.Username, proxy.Password)
			tz, locale = geoResult.Values()
			if tz == "" {
				tz, locale = fallbackGeoForProxyRegion(proxyRegion)
				geoResult = fingerprint.GeoDetectionResult{Timezone: tz, Locale: locale, Source: "proxy_region_fallback", Status: "geo_provider_unavailable"}
			}
		}
		if desc.ID == bfruntime.BrowseForgeChromium {
			if err := validateBrowseForgeProxyCountry(proxyRegion, p.SessionCountryCode, geoResult); err != nil {
				return nil, err
			}
		}
		args = append(args, "--fingerprint-webrtc-ip=auto")
	} else if requiresLaunchGeo(p) {
		geoResult = fingerprint.DetectLocalGeo()
		tz, locale = geoResult.Values()
	}
	tz, locale, err = launchGeoOverrides(p, tz, locale)
	if err != nil {
		return nil, err
	}
	if !requiresLaunchGeo(p) && geoResult.Source == "" {
		geoResult = fingerprint.GeoDetectionResult{Timezone: tz, Locale: locale, CountryCode: p.SessionCountryCode, Source: "profile_launch_overrides", Status: "manual"}
	}
	platform, err := resolveCloakFingerprintPlatform(policy, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	if desc.ID == bfruntime.BrowseForgeChromium {
		platform, err = resolveChromiumFingerprintPlatform(policy, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return nil, err
		}
	}
	persona, err := buildChromiumLaunchPersona(p, desc.ID, platform, tz, locale, proxyRegion, runtime.GOARCH, policy)
	if err != nil {
		return nil, err
	}
	persona.Native.Locale.GeoSource = geoResult.Source
	persona.Native.Locale.GeoStatus = geoResult.Status
	if desc.ID == bfruntime.CloakBrowser && runtime.GOOS == "darwin" && locale != "" {
		// Playwright's regional ICU override exposes one language on the page.
		// Use that same native preference for dedicated workers and HTTP too.
		persona.Native.Locale.AcceptLanguage = locale
		persona.Native.Locale.NavigatorLanguage = locale
		persona.Native.Locale.NavigatorLanguages = []string{locale}
		persona.Native.Locale.SecCHLang = locale
	}
	if desc.ID == bfruntime.BrowseForgeChromium {
		args = appendChromiumLaunchPersonaArgs(args, persona)
		args, err = appendBrowseForgeDockerSoftwareGPUArgs(args)
		if err != nil {
			return nil, err
		}
		args = append(args, browseForgeChromiumWindowArgs(persona)...)
		nativeConfigPath, err := writeBrowseForgeNativeConfig(userDataDir, persona)
		if err != nil {
			return nil, err
		}
		args = append(args,
			"--browseforge-stealth-config="+nativeConfigPath,
			"--browseforge-stealth-mode="+browseForgeChromiumNativeMode(policy),
		)
	} else {
		args = append(args, cloakBrowserNativeIdentityArgs(persona)...)
		if quota := cloakStorageQuotaMB(policy); quota > 0 {
			args = append(args, fmt.Sprintf("--fingerprint-storage-quota=%d", quota))
		}
		if persona.PluginsPDF != "" {
			args = append(args, "--fingerprint-plugins-pdf="+persona.PluginsPDF)
		}
		args = appendCloakBrowserFingerprintArgs(args, p.Fingerprint, persona.Native.Locale.AcceptLanguage)
		args = append(args, cloakBrowserDeviceWindowArgs(p.Fingerprint, persona.Native.Platform.OS)...)
		// The free macOS v145 Cloak build ignores fingerprint-locale for
		// navigator.language, but honors Chromium's native accept-lang path.
		args = append(args, "--accept-lang="+chromiumAcceptLanguageSwitchValue(persona.Native.Locale.AcceptLanguage))
	}
	launchExecutablePath := absChromiumPath
	if desc.ID == bfruntime.CloakBrowser && runtime.GOOS == "darwin" && persona.Native.Locale.Locale != "" {
		launchExecutablePath, err = prepareMacLocaleExecutable(absChromiumPath, p.ProfileDir, persona.Native.Locale.Locale)
		if err != nil {
			return nil, fmt.Errorf("prepare native macOS locale launcher: %w", err)
		}
	}

	if m.cfg.NoSandbox {
		args = append(args, "--no-sandbox")
	}

	fontsDir, err := resolveCloakFontsDir(policy)
	if err != nil {
		return nil, err
	}
	if err := validateCloakFingerprintPolicy(policy, platform, runtime.GOOS); err != nil {
		return nil, err
	}
	if fontsDir != "" {
		args = append(args, "--fingerprint-fonts-dir="+fontsDir)
	}

	baseArgs := append([]string(nil), args...)
	args, err = applyCloakBrowserLaunchPolicy(baseArgs, userDataDir, policy, false)
	if err != nil {
		return nil, err
	}

	downloadsDir, err := filepath.Abs(filepath.Join(p.ProfileDir, "downloads"))
	if err != nil {
		return nil, fmt.Errorf("downloads path: %w", err)
	}
	if err := os.MkdirAll(downloadsDir, 0755); err != nil {
		return nil, fmt.Errorf("create downloads dir: %w", err)
	}

	prefsDir := filepath.Join(userDataDir, "Default")
	if err := os.MkdirAll(prefsDir, 0755); err != nil {
		return nil, fmt.Errorf("create chromium prefs dir: %w", err)
	}
	prefsPath := filepath.Join(prefsDir, "Preferences")
	prefs := map[string]any{}
	if data, err := os.ReadFile(prefsPath); err == nil {
		if err := json.Unmarshal(data, &prefs); err != nil {
			return nil, fmt.Errorf("decode chromium preferences: %w", err)
		}
	}
	prefs["savefile"] = map[string]any{"default_directory": downloadsDir}
	prefs["download"] = map[string]any{"default_directory": downloadsDir, "prompt_for_download": false}
	prefs["webrtc"] = map[string]any{
		"ip_handling_policy":      "disable_non_proxied_udp",
		"multiple_routes_enabled": false,
		"nonproxied_udp_enabled":  false,
	}
	out, err := json.Marshal(prefs)
	if err != nil {
		return nil, fmt.Errorf("encode chromium preferences: %w", err)
	}
	if err := os.WriteFile(prefsPath, out, 0644); err != nil {
		return nil, fmt.Errorf("write chromium preferences: %w", err)
	}

	ignoreArgs := []string{
		"--enable-automation",
		"--enable-unsafe-swiftshader",
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
	}
	if !m.cfg.NoSandbox {
		ignoreArgs = append(ignoreArgs, "--no-sandbox")
	}

	launch := func(launchArgs []string) (playwright.BrowserContext, *SOCKS5Relay, error) {
		opts := playwright.BrowserTypeLaunchPersistentContextOptions{
			ExecutablePath:    playwright.String(launchExecutablePath),
			Headless:          playwright.Bool(false),
			AcceptDownloads:   playwright.Bool(true),
			Args:              launchArgs,
			NoViewport:        playwright.Bool(true),
			Env:               browseForgeChromiumEnv(persona),
			ExtraHttpHeaders:  browseForgeChromiumHTTPHeaders(persona),
			IgnoreDefaultArgs: ignoreArgs,
		}
		if privacyMode != "off" {
			opts.ServiceWorkers = playwright.ServiceWorkerPolicyBlock
		}
		if locale != "" && desc.ID == bfruntime.CloakBrowser && runtime.GOOS == "darwin" {
			opts.Locale = playwright.String(locale)
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
					return nil, nil, fmt.Errorf("socks5 relay: %w", err)
				}
				opts.Proxy = &playwright.Proxy{Server: "socks5://" + localAddr, Bypass: playwright.String(loopbackProxyBypass)}
			} else {
				server := fmt.Sprintf("%s://%s:%d", proxy.Type, proxy.Host, proxy.Port)
				opts.Proxy = &playwright.Proxy{
					Server:   server,
					Bypass:   playwright.String(loopbackProxyBypass),
					Username: playwright.String(proxy.Username),
					Password: playwright.String(proxy.Password),
				}
			}
		}

		ctx, err := m.pw.Chromium.LaunchPersistentContext(userDataDir, opts)
		if err != nil {
			if relay != nil {
				relay.Close()
			}
			return nil, nil, err
		}
		return ctx, relay, nil
	}

	ctx, relay, err := launch(args)
	fallbackAttempted := false
	if err != nil {
		if policy != nil &&
			(policy.RepairTransientCacheOnLaunchFailure || policy.AutoSafeGPUFallback) &&
			isChromiumGPUOrCacheLaunchFailure(err) {
			slog.Warn("repairing transient chromium cache after launch failure", "profile", p.ID, "userDataDir", userDataDir, "error", err)
			repairTransientChromiumData(userDataDir)
		}
		if shouldAutoFallbackCloakBrowserLaunch(policy, err) {
			fallbackAttempted = true
			slog.Warn("retrying CloakBrowser launch with safe GPU fallback", "profile", p.ID, "userDataDir", userDataDir, "error", err)
			if restartErr := m.restartPlaywright(); restartErr != nil {
				return nil, fmt.Errorf("launch chromium: %w; safe GPU fallback playwright restart failed: %v", humanizeError(err), restartErr)
			}
			fallbackArgs, fallbackArgErr := applyCloakBrowserLaunchPolicy(baseArgs, userDataDir, policy, true)
			if fallbackArgErr != nil {
				return nil, fallbackArgErr
			}
			ctx, relay, err = launch(fallbackArgs)
			if err == nil {
				slog.Info("CloakBrowser launch recovered with safe GPU fallback", "profile", p.ID)
			}
		}
	}
	if err != nil {
		if fallbackAttempted {
			return nil, fmt.Errorf("launch chromium: %w", noManagerRetryError{err: humanizeError(err)})
		}
		return nil, fmt.Errorf("launch chromium: %w", humanizeError(err))
	}
	if desc.ID == bfruntime.CloakBrowser && runtime.GOOS == "darwin" && persona.Native.Locale.Locale != "" {
		cleanMacLocaleStartupPage(ctx, persona.Native.Locale.Locale)
	}
	if err := installChromiumAutomationMitigations(ctx); err != nil {
		if relay != nil {
			relay.Close()
		}
		ctx.Close()
		return nil, fmt.Errorf("install chromium automation mitigations: %w", err)
	}
	privacyState, err := installBrowserPrivacy(ctx, p, true)
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
		RuntimeID:      string(desc.ID),
		Context:        ctx,
		Page:           page,
		relay:          relay,
		ProfileDir:     p.ProfileDir,
		UserDataDir:    userDataDir,
		ExecutablePath: absChromiumPath,
		Privacy:        privacyState,
	}, nil
}

func installChromiumAutomationMitigations(ctx playwright.BrowserContext) error {
	script := playwright.Script{Content: playwright.String(chromiumAutomationMitigationInitScript)}
	if err := ctx.AddInitScript(script); err != nil {
		return err
	}
	for _, page := range ctx.Pages() {
		if err := page.AddInitScript(script); err != nil {
			return err
		}
	}
	return nil
}

type browseForgeNativePersonaConfig struct {
	SchemaVersion string                           `json:"schema_version"`
	RuntimeID     string                           `json:"runtime_id"`
	Seed          uint64                           `json:"seed"`
	Browser       browseForgeNativeBrowserIdentity `json:"browser"`
	Platform      browseForgeNativePlatform        `json:"platform"`
	Locale        browseForgeNativeLocale          `json:"locale"`
	Network       browseForgeNativeNetwork         `json:"network"`
	DNS           browseForgeNativeDNS             `json:"dns"`
	Geolocation   browseForgeNativeGeolocation     `json:"geolocation"`
	Hardware      browseForgeNativeHardware        `json:"hardware"`
	Screen        browseForgeNativeScreen          `json:"screen"`
	GPU           browseForgeNativeGPU             `json:"gpu"`
	Fonts         browseForgeNativeFontProfile     `json:"fonts"`
	Canvas        browseForgeNativeCanvasProfile   `json:"canvas"`
	Audio         browseForgeNativeAudioProfile    `json:"audio"`
	Math          browseForgeNativeMathProfile     `json:"math"`
	Geometry      browseForgeNativeGeometryProfile `json:"geometry"`
	Plugins       browseForgeNativePluginProfile   `json:"plugins"`
	Media         browseForgeNativeMediaProfile    `json:"media"`
	Permissions   browseForgeNativePermissions     `json:"permissions"`
	WebRTC        browseForgeNativeWebRTC          `json:"webrtc"`
	Storage       browseForgeNativeStorage         `json:"storage"`
	Realms        browseForgeNativeRealmPolicy     `json:"realms"`
}

type browseForgeNativePersonaSnapshot struct {
	SchemaVersion string                           `json:"schema_version"`
	RuntimeID     string                           `json:"runtime_id"`
	Seed          uint64                           `json:"seed"`
	PersonaIDHash string                           `json:"persona_id_hash"`
	OriginSaltKey string                           `json:"origin_salt_key"`
	Browser       browseForgeNativeBrowserIdentity `json:"browser"`
	Platform      browseForgeNativePlatform        `json:"platform"`
	Locale        browseForgeNativeLocale          `json:"locale"`
	Network       browseForgeNativeNetwork         `json:"network"`
	DNS           browseForgeNativeDNS             `json:"dns"`
	Geolocation   browseForgeNativeGeolocation     `json:"geolocation"`
	Hardware      browseForgeNativeHardware        `json:"hardware"`
	Screen        browseForgeNativeScreen          `json:"screen"`
	GPU           browseForgeNativeGPU             `json:"gpu"`
	Fonts         browseForgeNativeFontProfile     `json:"fonts"`
	Canvas        browseForgeNativeCanvasProfile   `json:"canvas"`
	Audio         browseForgeNativeAudioProfile    `json:"audio"`
	Math          browseForgeNativeMathProfile     `json:"math"`
	Geometry      browseForgeNativeGeometryProfile `json:"geometry"`
	Plugins       browseForgeNativePluginProfile   `json:"plugins"`
	Media         browseForgeNativeMediaProfile    `json:"media"`
	Permissions   browseForgeNativePermissions     `json:"permissions"`
	WebRTC        browseForgeNativeWebRTC          `json:"webrtc"`
	Storage       browseForgeNativeStorage         `json:"storage"`
	Realms        browseForgeNativeRealmPolicy     `json:"realms"`
}

type browseForgeNativeBrowserIdentity struct {
	Family          string                          `json:"family"`
	Major           int                             `json:"major"`
	FullVersion     string                          `json:"full_version"`
	Brands          []string                        `json:"brands"`
	BrandVersions   []browseForgeNativeBrandVersion `json:"brand_versions"`
	FullVersionList []browseForgeNativeBrandVersion `json:"full_version_list"`
	UserAgent       string                          `json:"user_agent"`
	ClientHints     browseForgeNativeClientHints    `json:"client_hints"`
}

type browseForgeNativeBrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type browseForgeNativeClientHints struct {
	SecCHUA             string   `json:"sec_ch_ua"`
	SecCHUAFullVersion  string   `json:"sec_ch_ua_full_version_list"`
	Platform            string   `json:"platform"`
	PlatformVersion     string   `json:"platform_version"`
	Architecture        string   `json:"architecture"`
	Bitness             string   `json:"bitness"`
	Mobile              bool     `json:"mobile"`
	Model               string   `json:"model"`
	FormFactors         []string `json:"form_factors"`
	ExpectedNavigatorUA string   `json:"expected_navigator_user_agent"`
}

type browseForgeNativePlatform struct {
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Platform        string   `json:"platform"`
	PlatformCH      string   `json:"platform_ch"`
	PlatformVersion string   `json:"platform_version"`
	Mobile          bool     `json:"mobile"`
	Bitness         string   `json:"bitness"`
	Model           string   `json:"model"`
	FormFactors     []string `json:"form_factors"`
}

type browseForgeNativeLocale struct {
	Timezone             string   `json:"timezone"`
	TimezoneOffsetMins   int      `json:"timezone_offset_mins"`
	DSTPolicy            string   `json:"dst_policy"`
	SystemTimezoneSource string   `json:"system_timezone_source"`
	Locale               string   `json:"locale"`
	AcceptLanguage       string   `json:"accept_language"`
	NavigatorLanguage    string   `json:"navigator_language"`
	NavigatorLanguages   []string `json:"navigator_languages"`
	SecCHLang            string   `json:"sec_ch_lang,omitempty"`
	GeoSource            string   `json:"geo_source,omitempty"`
	GeoStatus            string   `json:"geo_status,omitempty"`
}

type browseForgeNativeNetwork struct {
	ProxyEnabled bool   `json:"proxy_enabled"`
	ProxyType    string `json:"proxy_type,omitempty"`
	ProxyRegion  string `json:"proxy_region,omitempty"`
	CountryCode  string `json:"country_code,omitempty"`
	RegionCode   string `json:"region_code,omitempty"`
	City         string `json:"city,omitempty"`
	ASNType      string `json:"asn_type,omitempty"`
}

type browseForgeNativeDNS struct {
	Mode           string `json:"mode"`
	ResolverPolicy string `json:"resolver_policy"`
}

type browseForgeNativeGeolocation struct {
	Mode        string `json:"mode"`
	CountryCode string `json:"country_code,omitempty"`
	RegionCode  string `json:"region_code,omitempty"`
	City        string `json:"city,omitempty"`
}

type browseForgeNativeHardware struct {
	HardwareConcurrency int `json:"hardware_concurrency"`
	DeviceMemoryGB      int `json:"device_memory_gb"`
}

type browseForgeNativeScreen struct {
	Width          int     `json:"width"`
	Height         int     `json:"height"`
	AvailWidth     int     `json:"avail_width"`
	AvailHeight    int     `json:"avail_height"`
	OuterWidth     int     `json:"outer_width"`
	OuterHeight    int     `json:"outer_height"`
	InnerWidth     int     `json:"inner_width"`
	InnerHeight    int     `json:"inner_height"`
	ViewportWidth  int     `json:"viewport_width"`
	ViewportHeight int     `json:"viewport_height"`
	DPR            float64 `json:"dpr"`
	ColorDepth     int     `json:"color_depth"`
	TouchPoints    int     `json:"touch_points"`
	Orientation    string  `json:"orientation"`
}

type browseForgeNativeGPU struct {
	Mode                   string            `json:"mode"`
	Vendor                 string            `json:"vendor"`
	Renderer               string            `json:"renderer"`
	ANGLEBackend           string            `json:"angle_backend"`
	WebGL                  bool              `json:"webgl"`
	WebGL2                 bool              `json:"webgl2"`
	WebGPU                 string            `json:"webgpu"`
	GLVersion              string            `json:"gl_version,omitempty"`
	ShadingLanguageVersion string            `json:"shading_language_version,omitempty"`
	ContextAttributes      map[string]string `json:"context_attributes,omitempty"`
	Extensions             []string          `json:"extensions,omitempty"`
	ShaderPrecision        map[string]string `json:"shader_precision,omitempty"`
	Limits                 map[string]int    `json:"limits,omitempty"`
	RenderHashBaseline     string            `json:"render_hash_baseline,omitempty"`
	WorkerOffscreenCanvas  bool              `json:"worker_offscreen_canvas"`
	WebGLParams            map[string]string `json:"webgl_params,omitempty"`
}

type browseForgeNativeFontProfile struct {
	ProfileID string   `json:"profile_id"`
	Families  []string `json:"families"`
	Emoji     string   `json:"emoji"`
	CJK       bool     `json:"cjk"`
	Source    string   `json:"source"`
}

type browseForgeNativeCanvasProfile struct {
	Mode               string `json:"mode"`
	Seed               int64  `json:"seed,omitempty"`
	Stable             bool   `json:"stable"`
	TextMetricsMode    string `json:"text_metrics_mode"`
	TextMetricsSeed    int64  `json:"text_metrics_seed,omitempty"`
	EmojiBaseline      string `json:"emoji_baseline"`
	RenderHashBaseline string `json:"render_hash_baseline,omitempty"`
}

type browseForgeNativeMathProfile struct {
	Stable bool `json:"stable"`
}

type browseForgeNativeGeometryProfile struct {
	ClientRectsStable bool `json:"client_rects_stable"`
}

type browseForgeNativeAudioProfile struct {
	Mode       string `json:"mode"`
	Seed       int64  `json:"seed,omitempty"`
	SampleRate int    `json:"sample_rate"`
	Stable     bool   `json:"stable"`
}

type browseForgeNativePluginProfile struct {
	PDFViewer bool     `json:"pdf_viewer"`
	Plugins   []string `json:"plugins"`
	MIMETypes []string `json:"mime_types"`
}

type browseForgeNativeMediaProfile struct {
	H264    bool     `json:"h264"`
	VP9     bool     `json:"vp9"`
	AV1     bool     `json:"av1"`
	Devices []string `json:"devices"`
}

type browseForgeNativePermissions struct {
	Notification string `json:"notification"`
}

type browseForgeNativeWebRTC struct {
	Mode              string `json:"mode"`
	ProxyRegion       string `json:"proxy_region"`
	DirectIPRedaction bool   `json:"direct_ip_redaction"`
}

type browseForgeNativeStorage struct {
	QuotaMB        int    `json:"quota_mb"`
	Persistent     bool   `json:"persistent"`
	Cookies        string `json:"cookies"`
	LocalStorage   string `json:"local_storage"`
	SessionStorage string `json:"session_storage"`
	IndexedDB      string `json:"indexed_db"`
	QuotaBehavior  string `json:"quota_behavior"`
}

type browseForgeNativeRealmPolicy struct {
	DocumentStartInjection bool     `json:"document_start_injection"`
	Targets                []string `json:"targets"`
}

type chromiumLaunchPersona struct {
	Native            browseForgeNativePersonaConfig
	NavigatorPlatform string
	CanvasNoise       int64
	HasCanvasNoise    bool
	AudioNoise        int64
	HasAudioNoise     bool
	FontsList         string
	HasFontsList      bool
	HasWebGLVendor    bool
	HasWebGLRenderer  bool
	PluginsPDF        string
}

func buildChromiumLaunchPersona(p *profile.Profile, runtimeID bfruntime.ID, platform, timezone, locale, proxyRegion, goarch string, policy *config.CloakBrowserConfig) (chromiumLaunchPersona, error) {
	if p == nil {
		return chromiumLaunchPersona{}, fmt.Errorf("profile is nil")
	}
	nativePlatform, err := nativePersonaPlatform(platform, goarch)
	if err != nil {
		return chromiumLaunchPersona{}, err
	}
	if runtimeID == bfruntime.BrowseForgeChromium {
		proxyRegion, err = sanitizeBrowseForgeProxyRegion(proxyRegion)
		if err != nil {
			return chromiumLaunchPersona{}, err
		}
	} else {
		proxyRegion = strings.TrimSpace(proxyRegion)
	}
	fp := p.Fingerprint
	acceptLanguage := effectiveChromiumAcceptLanguage(fp, locale)
	navigatorLanguages := navigatorLanguagesFromAcceptLanguage(acceptLanguage)
	// CloakBrowser owns its native UA and Client Hints together. Its versioned
	// provider flags differ from BrowseForge's native persona contract. Chromium's
	// --user-agent without native metadata leaves UA-CH versions empty on macOS
	// v145, while synthetic HTTP headers would disagree with the page's JS.
	browserIdentity := browseForgeNativeBrowserIdentity{Family: "chromium"}
	if runtimeID == bfruntime.BrowseForgeChromium {
		userAgent := effectiveChromiumUserAgent(fp, platform)
		fullVersion := chromiumVersionFromUserAgent(userAgent)
		brandVersions := chromiumBrandVersions(fullVersion)
		browserIdentity = browseForgeNativeBrowserIdentity{
			Family:          "chromium",
			Major:           chromiumMajorVersion(fullVersion),
			FullVersion:     fullVersion,
			Brands:          []string{"Chromium"},
			BrandVersions:   brandVersions,
			FullVersionList: chromiumFullVersionList(brandVersions, fullVersion),
			UserAgent:       userAgent,
			ClientHints:     chromiumClientHints(userAgent, nativePlatform, brandVersions),
		}
	}
	vendor, hasWebGLVendor := fingerprintString(fp, "webGl:vendor")
	renderer, hasWebGLRenderer := fingerprintString(fp, "webGl:renderer")
	gpuMode := "native"
	if runtimeID == bfruntime.BrowseForgeChromium {
		gpuMode, err = browseForgeDockerGPUMode()
		if err != nil {
			return chromiumLaunchPersona{}, err
		}
		if gpuMode == "software" && (!hasWebGLVendor || !hasWebGLRenderer) {
			vendor = "Google Inc. (Google)"
			renderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"
			hasWebGLVendor = true
			hasWebGLRenderer = true
		} else {
			if !hasWebGLVendor {
				vendor = "browser-default"
			}
			if !hasWebGLRenderer {
				renderer = "browser-default"
			}
		}
	} else {
		if !hasWebGLVendor {
			vendor = "Intel Inc."
		}
		if !hasWebGLRenderer {
			renderer = "Intel Iris OpenGL Engine"
		}
	}
	storageQuota := int64(0)
	if runtimeID == bfruntime.BrowseForgeChromium {
		storageQuota = 8192
	}
	if quota := cloakStorageQuotaMB(policy); quota > 0 {
		storageQuota = quota
	} else if quota < 0 {
		return chromiumLaunchPersona{}, fmt.Errorf("%s storage_quota_mb must be >= 0", runtimeID)
	}
	generatedNativeIdentity := runtimeID == bfruntime.BrowseForgeChromium && p.FingerprintGeneration != nil && p.FingerprintGeneration.Provider == string(runtimeID) && p.FingerprintGeneration.Version == 1
	screenDefaults := browseForgeDefaultScreen(nativePlatform.OS)
	screenWidth := fingerprintIntDefault(fp, "screen.width", screenDefaults.Width)
	screenHeight := fingerprintIntDefault(fp, "screen.height", screenDefaults.Height)
	availWidthDefault, availHeightDefault := screenDefaults.AvailWidth, screenDefaults.AvailHeight
	if generatedNativeIdentity {
		availWidthDefault = screenWidth
		availHeightDefault = maxInt(screenHeight-(screenDefaults.Height-screenDefaults.AvailHeight), 1)
	}
	availWidth := clampScreenAvail(fingerprintIntDefault(fp, "screen.availWidth", availWidthDefault), screenWidth)
	availHeight := clampScreenAvail(fingerprintIntDefault(fp, "screen.availHeight", availHeightDefault), screenHeight)
	dpr := fingerprintFloatDefault(fp, "screen.devicePixelRatio", screenDefaults.DPR)
	screenChromeInset := maxInt(screenDefaults.OuterHeight-screenDefaults.InnerHeight, 0)
	outerWidth := fingerprintIntDefault(fp, "window.outerWidth", availWidth)
	outerHeight := fingerprintIntDefault(fp, "window.outerHeight", availHeight)
	innerWidth := fingerprintIntDefault(fp, "window.innerWidth", availWidth)
	innerHeight := fingerprintIntDefault(fp, "window.innerHeight", maxInt(availHeight-screenChromeInset, 1))
	fonts, fontsList, hasFontsList, err := browseForgeFontContract(fp, nativePlatform, locale, policy)
	if err != nil {
		return chromiumLaunchPersona{}, err
	}
	canvas := browseForgeCanvasProfile(fp, browseForgePersonaSeed(p))
	audio := browseForgeAudioProfile(fp, browseForgePersonaSeed(p))
	plugins := browseForgePluginProfile(policy)
	network := browseForgeNetworkProfile(proxyRegion)
	persona := chromiumLaunchPersona{
		Native: browseForgeNativePersonaConfig{
			SchemaVersion: "1.0",
			RuntimeID:     string(runtimeID),
			Seed:          browseForgePersonaSeed(p),
			Browser:       browserIdentity,
			Platform:      nativePlatform,
			Locale: browseForgeNativeLocale{
				Timezone:             timezone,
				TimezoneOffsetMins:   timezoneOffsetMinutes(timezone),
				DSTPolicy:            "iana-timezone",
				SystemTimezoneSource: "persona-contract",
				Locale:               locale,
				AcceptLanguage:       acceptLanguage,
				NavigatorLanguage:    firstLanguage(acceptLanguage),
				NavigatorLanguages:   navigatorLanguages,
				SecCHLang:            strings.Join(navigatorLanguages, ","),
			},
			Network:     network,
			DNS:         browseForgeDNSProfile(network),
			Geolocation: browseForgeGeolocationProfile(network),
			Hardware: browseForgeNativeHardware{
				HardwareConcurrency: fingerprintIntDefault(fp, "navigator.hardwareConcurrency", 8),
				DeviceMemoryGB:      fingerprintIntDefault(fp, "navigator.deviceMemory", 8),
			},
			Screen: browseForgeNativeScreen{
				Width:          screenWidth,
				Height:         screenHeight,
				AvailWidth:     availWidth,
				AvailHeight:    availHeight,
				OuterWidth:     outerWidth,
				OuterHeight:    outerHeight,
				InnerWidth:     innerWidth,
				InnerHeight:    innerHeight,
				ViewportWidth:  innerWidth,
				ViewportHeight: innerHeight,
				DPR:            dpr,
				ColorDepth:     fingerprintIntDefault(fp, "screen.colorDepth", screenDefaults.ColorDepth),
				TouchPoints:    0,
				Orientation:    "landscape-primary",
			},
			GPU:         browseForgeGPUProfile(gpuMode, vendor, renderer),
			Fonts:       fonts,
			Canvas:      canvas,
			Math:        browseForgeNativeMathProfile{Stable: true},
			Geometry:    browseForgeNativeGeometryProfile{ClientRectsStable: true},
			Audio:       audio,
			Plugins:     plugins,
			Media:       browseForgeMediaProfile(),
			Permissions: browseForgeNativePermissions{Notification: "prompt"},
			WebRTC: browseForgeNativeWebRTC{
				Mode:              "disable_non_proxied_udp",
				ProxyRegion:       proxyRegion,
				DirectIPRedaction: true,
			},
			Storage: browseForgeNativeStorage{
				QuotaMB:        int(storageQuota),
				Persistent:     false,
				Cookies:        "profile-persistent",
				LocalStorage:   "profile-persistent",
				SessionStorage: "session-scoped",
				IndexedDB:      "profile-persistent",
				QuotaBehavior:  "chromium-profile-quota",
			},
			Realms: browseForgeNativeRealmPolicy{
				DocumentStartInjection: true,
				Targets:                []string{"window", "same-origin-iframe", "sandbox-iframe", "nested-iframe", "dedicated-worker", "shared-worker", "service-worker", "offscreen-canvas-worker"},
			},
		},
		NavigatorPlatform: platform,
		HasWebGLVendor:    hasWebGLVendor,
		HasWebGLRenderer:  hasWebGLRenderer,
		PluginsPDF:        cloakPluginsPDF(policy),
	}
	if v, ok := fingerprintInt(fp, "canvas:seed"); ok {
		persona.CanvasNoise = v
		persona.HasCanvasNoise = true
	} else if generatedNativeIdentity && browseForgeChromiumNativeMode(policy) != "strict" {
		// The native engine reads a dedicated switch, not persona.canvas.seed.
		// Versioned generation keeps existing/imported profiles unchanged.
		persona.CanvasNoise = int64(browseForgePersonaSeed(p)%0x7ffffffe) + 1
		persona.HasCanvasNoise = true
		persona.Native.Canvas.Mode = "stable-seeded"
		persona.Native.Canvas.Seed = persona.CanvasNoise
		persona.Native.Canvas.RenderHashBaseline = "seeded"
	}
	// Upstream audio noise changes AudioBuffer backing-array semantics; keep it opt-in.
	if v, ok := fingerprintInt(fp, "audio:seed"); ok {
		persona.AudioNoise = v
		persona.HasAudioNoise = true
	}
	if hasFontsList {
		persona.FontsList = fontsList
		persona.HasFontsList = true
	}
	return persona, nil
}

func appendChromiumLaunchPersonaArgs(args []string, persona chromiumLaunchPersona) []string {
	native := persona.Native
	args = append(args,
		"--fingerprint-timezone="+native.Locale.Timezone,
		"--fingerprint-locale="+native.Locale.Locale,
		"--fingerprint-platform="+persona.NavigatorPlatform,
	)
	if native.Storage.QuotaMB > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-storage-quota=%d", native.Storage.QuotaMB))
	}
	if persona.PluginsPDF != "" {
		args = append(args, "--fingerprint-plugins-pdf="+persona.PluginsPDF)
	}
	if native.Browser.UserAgent != "" {
		args = append(args, "--user-agent="+native.Browser.UserAgent, "--fingerprint-user-agent="+native.Browser.UserAgent)
		if native.Browser.FullVersion != "" {
			args = append(args, "--fingerprint-ua-full-version="+native.Browser.FullVersion)
		}
	}
	args = append(args,
		"--fingerprint-ua-platform="+native.Platform.PlatformCH,
		"--fingerprint-ua-platform-version="+native.Platform.PlatformVersion,
		"--fingerprint-ua-architecture="+native.Platform.Arch,
		"--fingerprint-ua-bitness="+native.Platform.Bitness,
		"--fingerprint-ua-mobile="+secCHBool(native.Platform.Mobile),
		"--fingerprint-ua-model="+native.Platform.Model,
		"--fingerprint-ua-form-factors="+strings.Join(native.Platform.FormFactors, ","),
		"--fingerprint-sec-ch-ua="+native.Browser.ClientHints.SecCHUA,
		"--fingerprint-sec-ch-ua-full-version-list="+native.Browser.ClientHints.SecCHUAFullVersion,
	)
	if acceptLanguage := chromiumAcceptLanguageSwitchValue(native.Locale.AcceptLanguage); acceptLanguage != "" {
		args = append(args, "--fingerprint-accept-language="+acceptLanguage)
	}
	if native.Hardware.HardwareConcurrency > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-hardware-concurrency=%d", native.Hardware.HardwareConcurrency))
	}
	if native.Hardware.DeviceMemoryGB > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-device-memory=%d", native.Hardware.DeviceMemoryGB))
	}
	if native.Screen.Width > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-screen-width=%d", native.Screen.Width))
	}
	if native.Screen.Height > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-screen-height=%d", native.Screen.Height))
	}
	if native.Screen.AvailWidth > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-screen-avail-width=%d", native.Screen.AvailWidth))
	}
	if native.Screen.AvailHeight > 0 {
		args = append(args, fmt.Sprintf("--fingerprint-screen-avail-height=%d", native.Screen.AvailHeight))
	}
	if native.Screen.DPR > 0 {
		dpr := fmt.Sprintf("%g", native.Screen.DPR)
		args = append(args, "--force-device-scale-factor="+dpr, "--fingerprint-screen-device-scale-factor="+dpr)
	}
	if persona.HasCanvasNoise {
		args = append(args, fmt.Sprintf("--fingerprint-canvas-noise=%d", persona.CanvasNoise))
	}
	if persona.HasAudioNoise {
		args = append(args, fmt.Sprintf("--fingerprint-audio-noise=%d", persona.AudioNoise))
	}
	if persona.HasFontsList {
		args = append(args, "--fingerprint-fonts-list="+persona.FontsList)
	}
	if persona.HasWebGLVendor {
		args = append(args, "--fingerprint-webgl-vendor="+native.GPU.Vendor)
	}
	if persona.HasWebGLRenderer {
		args = append(args, "--fingerprint-webgl-renderer="+native.GPU.Renderer)
	}
	return args
}

func browseForgeChromiumWindowArgs(persona chromiumLaunchPersona) []string {
	native := persona.Native
	width := native.Screen.AvailWidth
	height := native.Screen.AvailHeight
	if width <= 0 {
		width = native.Screen.Width
	}
	if height <= 0 {
		height = native.Screen.Height
	}
	if width <= 0 || height <= 0 {
		return nil
	}
	return []string{
		"--window-position=0,0",
		fmt.Sprintf("--window-size=%d,%d", width, height),
	}
}

func appendBrowseForgeDockerSoftwareGPUArgs(args []string) ([]string, error) {
	mode, err := browseForgeDockerGPUMode()
	if err != nil {
		return nil, err
	}
	if mode != "software" {
		return args, nil
	}
	return appendUniqueChromiumArgs(args,
		"--use-gl=angle",
		"--use-angle=swiftshader-webgl",
		"--enable-unsafe-swiftshader",
		"--disable-remote-fonts",
	), nil
}

func browseForgeChromiumEnv(persona chromiumLaunchPersona) map[string]string {
	native := persona.Native
	env := map[string]string{
		"DISPLAY":               os.Getenv("DISPLAY"),
		"HOME":                  os.Getenv("HOME"),
		"LIBGL_ALWAYS_SOFTWARE": os.Getenv("LIBGL_ALWAYS_SOFTWARE"),
	}
	if native.Locale.Timezone != "" {
		env["TZ"] = native.Locale.Timezone
	}
	if native.Locale.Locale != "" {
		localeEnv := strings.ReplaceAll(native.Locale.Locale, "-", "_") + ".UTF-8"
		env["LANG"] = localeEnv
		env["LC_ALL"] = localeEnv
		env["BROWSEFORGE_INTL_LOCALE"] = native.Locale.Locale
	}
	if acceptLanguage := native.Locale.AcceptLanguage; acceptLanguage != "" {
		env["BROWSEFORGE_ACCEPT_LANGUAGE"] = acceptLanguage
	}
	return env
}

func browseForgeDockerGPUMode() (string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("BROWSEFORGE_DOCKER_GPU_MODE")))
	switch mode {
	case "", "native":
		return "native", nil
	case "software":
		return "software", nil
	case "passthrough":
		return "passthrough", nil
	default:
		return "", fmt.Errorf("BROWSEFORGE_DOCKER_GPU_MODE must be one of software, native, or passthrough; got %q", os.Getenv("BROWSEFORGE_DOCKER_GPU_MODE"))
	}
}

func writeBrowseForgeNativeConfig(userDataDir string, persona chromiumLaunchPersona) (string, error) {
	snapshot, err := resolveBrowseForgeNativePersona(persona.Native)
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(userDataDir, "BrowseForgeNative")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("create BrowseForge native config dir: %w", err)
	}
	configPath := filepath.Join(configDir, "persona.json")
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode BrowseForge native config: %w", err)
	}
	if err := os.WriteFile(configPath, append(data, '\n'), 0644); err != nil {
		return "", fmt.Errorf("write BrowseForge native config: %w", err)
	}
	return configPath, nil
}

func resolveBrowseForgeNativePersona(cfg browseForgeNativePersonaConfig) (browseForgeNativePersonaSnapshot, error) {
	if err := validateBrowseForgePersonaContract(cfg); err != nil {
		return browseForgeNativePersonaSnapshot{}, err
	}
	canonical, err := json.Marshal(cfg)
	if err != nil {
		return browseForgeNativePersonaSnapshot{}, fmt.Errorf("encode BrowseForge native canonical config: %w", err)
	}
	personaHash := sha256.Sum256(canonical)
	originKey := hmac.New(sha256.New, []byte(fmt.Sprintf("browseforge-origin-salt:%d", cfg.Seed)))
	_, _ = originKey.Write(canonical)
	return browseForgeNativePersonaSnapshot{
		SchemaVersion: cfg.SchemaVersion,
		RuntimeID:     cfg.RuntimeID,
		Seed:          cfg.Seed,
		PersonaIDHash: hex.EncodeToString(personaHash[:16]),
		OriginSaltKey: hex.EncodeToString(originKey.Sum(nil)[:16]),
		Browser:       cfg.Browser,
		Platform:      cfg.Platform,
		Locale:        cfg.Locale,
		Network:       cfg.Network,
		DNS:           cfg.DNS,
		Geolocation:   cfg.Geolocation,
		Hardware:      cfg.Hardware,
		Screen:        cfg.Screen,
		GPU:           cfg.GPU,
		Fonts:         cfg.Fonts,
		Canvas:        cfg.Canvas,
		Math:          cfg.Math,
		Geometry:      cfg.Geometry,
		Audio:         cfg.Audio,
		Plugins:       cfg.Plugins,
		Media:         cfg.Media,
		Permissions:   cfg.Permissions,
		WebRTC:        cfg.WebRTC,
		Storage:       cfg.Storage,
		Realms:        cfg.Realms,
	}, nil
}

func browseForgeChromiumNativeMode(policy *config.CloakBrowserConfig) string {
	if policy != nil && strings.TrimSpace(policy.NativeMode) != "" {
		return strings.TrimSpace(policy.NativeMode)
	}
	return "enabled"
}

func browseForgePersonaSeed(p *profile.Profile) uint64 {
	if p.FingerprintSeed > 0 {
		return uint64(p.FingerprintSeed)
	}
	if seed, ok := fingerprintInt(p.Fingerprint, "canvas:seed"); ok {
		return uint64(seed)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(p.ID + ":" + p.RuntimeID))
	seed := h.Sum64()
	if seed == 0 {
		return 1
	}
	return seed
}

func defaultChromiumUserAgent(platform string) string {
	switch platform {
	case "MacIntel":
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.101 Safari/537.36"
	case "Linux aarch64":
		return "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.101 Safari/537.36"
	case "Linux x86_64":
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.101 Safari/537.36"
	default:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.101 Safari/537.36"
	}
}

func chromiumVersionFromUserAgent(userAgent string) string {
	const token = "Chrome/"
	idx := strings.Index(userAgent, token)
	if idx < 0 {
		return "150.0.7871.101"
	}
	version := userAgent[idx+len(token):]
	if end := strings.IndexAny(version, " )"); end >= 0 {
		version = version[:end]
	}
	if version == "" {
		return "150.0.7871.101"
	}
	return version
}

func chromiumMajorVersion(fullVersion string) int {
	major := fullVersion
	if dot := strings.IndexByte(major, '.'); dot >= 0 {
		major = major[:dot]
	}
	parsed, err := strconv.Atoi(major)
	if err != nil || parsed <= 0 {
		return 150
	}
	return parsed
}

func chromiumBrandVersions(fullVersion string) []browseForgeNativeBrandVersion {
	major := strconv.Itoa(chromiumMajorVersion(fullVersion))
	return []browseForgeNativeBrandVersion{
		{Brand: "Not;A=Brand", Version: "8"},
		{Brand: "Chromium", Version: major},
	}
}

func chromiumFullVersionList(brandVersions []browseForgeNativeBrandVersion, fullVersion string) []browseForgeNativeBrandVersion {
	out := make([]browseForgeNativeBrandVersion, 0, len(brandVersions))
	for _, brand := range brandVersions {
		version := fullVersion
		if brand.Brand == "Not;A=Brand" {
			version = "8.0.0.0"
		}
		out = append(out, browseForgeNativeBrandVersion{Brand: brand.Brand, Version: version})
	}
	return out
}

func chromiumClientHints(userAgent string, platform browseForgeNativePlatform, brandVersions []browseForgeNativeBrandVersion) browseForgeNativeClientHints {
	fullVersion := chromiumVersionFromUserAgent(userAgent)
	fullVersionList := chromiumFullVersionList(brandVersions, fullVersion)
	return browseForgeNativeClientHints{
		SecCHUA:             secCHBrandList(brandVersions),
		SecCHUAFullVersion:  secCHBrandList(fullVersionList),
		Platform:            platform.PlatformCH,
		PlatformVersion:     platform.PlatformVersion,
		Architecture:        platform.Arch,
		Bitness:             platform.Bitness,
		Mobile:              platform.Mobile,
		Model:               platform.Model,
		FormFactors:         append([]string(nil), platform.FormFactors...),
		ExpectedNavigatorUA: userAgent,
	}
}

func browseForgeChromiumHTTPHeaders(persona chromiumLaunchPersona) map[string]string {
	native := persona.Native
	headers := make(map[string]string, 12)
	if native.Locale.AcceptLanguage != "" {
		headers["Accept-Language"] = native.Locale.AcceptLanguage
	}
	// Other providers generate UA/UA-CH natively, including Chromium's normal
	// secure-context and Accept-CH negotiation for high-entropy hints.
	if native.RuntimeID != string(bfruntime.BrowseForgeChromium) {
		return headers
	}
	if native.Browser.UserAgent != "" {
		headers["User-Agent"] = native.Browser.UserAgent
	}
	hints := native.Browser.ClientHints
	if hints.SecCHUA != "" {
		headers["Sec-CH-UA"] = hints.SecCHUA
	}
	if hints.SecCHUAFullVersion != "" {
		headers["Sec-CH-UA-Full-Version-List"] = hints.SecCHUAFullVersion
	}
	if hints.Platform != "" {
		headers["Sec-CH-UA-Platform"] = strconv.Quote(hints.Platform)
	}
	if hints.PlatformVersion != "" {
		headers["Sec-CH-UA-Platform-Version"] = strconv.Quote(hints.PlatformVersion)
	}
	if hints.Architecture != "" {
		headers["Sec-CH-UA-Arch"] = strconv.Quote(hints.Architecture)
	}
	if hints.Bitness != "" {
		headers["Sec-CH-UA-Bitness"] = strconv.Quote(hints.Bitness)
	}
	headers["Sec-CH-UA-Mobile"] = secCHBool(hints.Mobile)
	if hints.Model != "" {
		headers["Sec-CH-UA-Model"] = strconv.Quote(hints.Model)
	}
	if len(hints.FormFactors) > 0 {
		quoted := make([]string, 0, len(hints.FormFactors))
		for _, formFactor := range hints.FormFactors {
			if formFactor != "" {
				quoted = append(quoted, strconv.Quote(formFactor))
			}
		}
		if len(quoted) > 0 {
			headers["Sec-CH-UA-Form-Factors"] = strings.Join(quoted, ", ")
		}
	}
	if native.Locale.SecCHLang != "" {
		headers["Sec-CH-Lang"] = native.Locale.SecCHLang
	}
	return headers
}

func secCHBrandList(versions []browseForgeNativeBrandVersion) string {
	parts := make([]string, 0, len(versions))
	for _, item := range versions {
		parts = append(parts, fmt.Sprintf("%q;v=%q", item.Brand, item.Version))
	}
	return strings.Join(parts, ", ")
}

func secCHBool(v bool) string {
	if v {
		return "?1"
	}
	return "?0"
}

func platformVersion(osName string) string {
	switch osName {
	case "windows":
		return "10.0.0"
	case "macos":
		return "10.15.7"
	default:
		return ""
	}
}

func nativePersonaPlatform(platform, goarch string) (browseForgeNativePlatform, error) {
	desktop := []string{}
	switch platform {
	case "Win32":
		return browseForgeNativePlatform{OS: "windows", Arch: "x86", Platform: "Win32", PlatformCH: "Windows", PlatformVersion: platformVersion("windows"), Mobile: false, Bitness: "64", Model: "", FormFactors: desktop}, nil
	case "MacIntel":
		arch := "x86"
		if goarch == "arm64" {
			arch = "arm"
		}
		return browseForgeNativePlatform{OS: "macos", Arch: arch, Platform: "MacIntel", PlatformCH: "macOS", PlatformVersion: platformVersion("macos"), Mobile: false, Bitness: "64", Model: "", FormFactors: desktop}, nil
	case "Linux x86_64":
		return browseForgeNativePlatform{OS: "linux", Arch: "x86", Platform: "Linux x86_64", PlatformCH: "Linux", PlatformVersion: platformVersion("linux"), Mobile: false, Bitness: "64", Model: "", FormFactors: desktop}, nil
	case "Linux aarch64":
		return browseForgeNativePlatform{OS: "linux", Arch: "arm", Platform: "Linux aarch64", PlatformCH: "Linux", PlatformVersion: platformVersion("linux"), Mobile: false, Bitness: "64", Model: "", FormFactors: desktop}, nil
	default:
		return browseForgeNativePlatform{}, fmt.Errorf("chromium native persona platform %q is not supported", platform)
	}
}

func validateBrowseForgeNativePersonaPlatform(platform browseForgeNativePlatform) error {
	if platform.Bitness != "64" {
		return fmt.Errorf("chromium native persona platform mismatch: platform=%s os=%s arch=%s bitness=%s platform_ch=%s", platform.Platform, platform.OS, platform.Arch, platform.Bitness, platform.PlatformCH)
	}
	switch platform.OS {
	case "windows":
		if platform.Platform == "Win32" && platform.Arch == "x86" && platform.PlatformCH == "Windows" && !platform.Mobile && platform.Model == "" {
			return nil
		}
	case "macos":
		if platform.Platform == "MacIntel" && (platform.Arch == "x86" || platform.Arch == "arm") && platform.PlatformCH == "macOS" && !platform.Mobile && platform.Model == "" {
			return nil
		}
	case "linux":
		if ((platform.Platform == "Linux x86_64" && platform.Arch == "x86") || (platform.Platform == "Linux aarch64" && platform.Arch == "arm")) && platform.PlatformCH == "Linux" && !platform.Mobile && platform.Model == "" {
			return nil
		}
	}
	return fmt.Errorf("chromium native persona platform mismatch: platform=%s os=%s arch=%s bitness=%s platform_ch=%s", platform.Platform, platform.OS, platform.Arch, platform.Bitness, platform.PlatformCH)
}

func validateBrowseForgePersonaContract(cfg browseForgeNativePersonaConfig) error {
	if cfg.SchemaVersion != "1.0" {
		return fmt.Errorf("persona contract mismatch: schema_version %q is not supported", cfg.SchemaVersion)
	}
	if strings.TrimSpace(cfg.RuntimeID) == "" {
		return fmt.Errorf("persona contract mismatch: runtime_id must be set")
	}
	if cfg.Seed == 0 {
		return fmt.Errorf("persona contract mismatch: seed must be non-zero")
	}
	if cfg.Browser.Family != "chromium" {
		return fmt.Errorf("persona contract mismatch: browser family %q is not supported", cfg.Browser.Family)
	}
	if strings.TrimSpace(cfg.Browser.UserAgent) == "" {
		return fmt.Errorf("persona contract mismatch: browser user_agent must be set")
	}
	fullVersion := chromiumVersionFromUserAgent(cfg.Browser.UserAgent)
	if cfg.Browser.FullVersion != fullVersion {
		return fmt.Errorf("persona contract mismatch: browser full_version %q does not match user_agent version %q", cfg.Browser.FullVersion, fullVersion)
	}
	if cfg.Browser.Major != chromiumMajorVersion(fullVersion) {
		return fmt.Errorf("persona contract mismatch: browser major %d does not match full_version %q", cfg.Browser.Major, fullVersion)
	}
	expectedBrandVersions := chromiumBrandVersions(fullVersion)
	if secCHBrandList(cfg.Browser.BrandVersions) != secCHBrandList(expectedBrandVersions) {
		return fmt.Errorf("persona contract mismatch: browser brand_versions do not match full_version %q", fullVersion)
	}
	expectedFullVersionList := chromiumFullVersionList(expectedBrandVersions, fullVersion)
	if secCHBrandList(cfg.Browser.FullVersionList) != secCHBrandList(expectedFullVersionList) {
		return fmt.Errorf("persona contract mismatch: browser full_version_list does not match full_version %q", fullVersion)
	}
	if cfg.Browser.ClientHints.SecCHUA != secCHBrandList(cfg.Browser.BrandVersions) {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA %q does not match browser brand_versions", cfg.Browser.ClientHints.SecCHUA)
	}
	if cfg.Browser.ClientHints.SecCHUAFullVersion != secCHBrandList(cfg.Browser.FullVersionList) {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Full-Version-List %q does not match browser full_version_list", cfg.Browser.ClientHints.SecCHUAFullVersion)
	}
	if err := validateBrowseForgeNativePersonaPlatform(cfg.Platform); err != nil {
		return err
	}
	if !userAgentMatchesPlatform(cfg.Browser.UserAgent, cfg.Platform.Platform) {
		return fmt.Errorf("persona contract mismatch: user_agent %q does not match platform %q", cfg.Browser.UserAgent, cfg.Platform.Platform)
	}
	if cfg.Browser.ClientHints.ExpectedNavigatorUA != "" && cfg.Browser.ClientHints.ExpectedNavigatorUA != cfg.Browser.UserAgent {
		return fmt.Errorf("persona contract mismatch: client hints navigator userAgent does not match browser user_agent")
	}
	if cfg.Browser.ClientHints.Platform != "" && cfg.Browser.ClientHints.Platform != cfg.Platform.PlatformCH {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Platform %q does not match platform_ch %q", cfg.Browser.ClientHints.Platform, cfg.Platform.PlatformCH)
	}
	if cfg.Browser.ClientHints.PlatformVersion != cfg.Platform.PlatformVersion {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Platform-Version %q does not match platform_version %q", cfg.Browser.ClientHints.PlatformVersion, cfg.Platform.PlatformVersion)
	}
	if x64UserAgent(cfg.Browser.UserAgent) && cfg.Browser.ClientHints.Architecture == "arm" {
		return fmt.Errorf("persona contract mismatch: x64 user-agent cannot use ARM UA-CH architecture")
	}
	if cfg.Browser.ClientHints.Architecture != "" && cfg.Browser.ClientHints.Architecture != cfg.Platform.Arch {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Arch %q does not match platform arch %q", cfg.Browser.ClientHints.Architecture, cfg.Platform.Arch)
	}
	if cfg.Browser.ClientHints.Bitness != "" && cfg.Browser.ClientHints.Bitness != cfg.Platform.Bitness {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Bitness %q does not match platform bitness %q", cfg.Browser.ClientHints.Bitness, cfg.Platform.Bitness)
	}
	if cfg.Browser.ClientHints.Model != cfg.Platform.Model {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Model %q does not match platform model %q", cfg.Browser.ClientHints.Model, cfg.Platform.Model)
	}
	if strings.Join(cfg.Browser.ClientHints.FormFactors, "\x00") != strings.Join(cfg.Platform.FormFactors, "\x00") {
		return fmt.Errorf("persona contract mismatch: Sec-CH-UA-Form-Factors do not match platform formFactors")
	}
	if cfg.Platform.Mobile != cfg.Browser.ClientHints.Mobile {
		return fmt.Errorf("persona contract mismatch: UA-CH mobile flag does not match platform mobile flag")
	}
	if !cfg.Platform.Mobile && containsStringFold(cfg.Platform.FormFactors, "mobile") {
		return fmt.Errorf("persona contract mismatch: desktop platform cannot advertise mobile formFactors")
	}
	if !cfg.Platform.Mobile && containsStringFold(cfg.Browser.ClientHints.FormFactors, "mobile") {
		return fmt.Errorf("persona contract mismatch: desktop UA cannot advertise mobile Sec-CH-UA-Form-Factors")
	}
	if cfg.Locale.Timezone == "" || cfg.Locale.DSTPolicy != "iana-timezone" || cfg.Locale.SystemTimezoneSource != "persona-contract" {
		return fmt.Errorf("persona contract mismatch: timezone policy must use persona-contract IANA timezone metadata")
	}
	if cfg.Locale.TimezoneOffsetMins != timezoneOffsetMinutes(cfg.Locale.Timezone) {
		return fmt.Errorf("persona contract mismatch: timezone offset %d does not match timezone %q", cfg.Locale.TimezoneOffsetMins, cfg.Locale.Timezone)
	}
	if strings.TrimSpace(cfg.Locale.Locale) == "" {
		return fmt.Errorf("persona contract mismatch: locale must be set")
	}
	if cfg.Locale.AcceptLanguage != "" && !acceptLanguageMatchesLocale(cfg.Locale.AcceptLanguage, cfg.Locale.Locale) {
		return fmt.Errorf("persona contract mismatch: Accept-Language %q does not match locale %q", cfg.Locale.AcceptLanguage, cfg.Locale.Locale)
	}
	if cfg.Locale.AcceptLanguage != "" && cfg.Locale.NavigatorLanguage != "" && !strings.EqualFold(cfg.Locale.NavigatorLanguage, firstLanguage(cfg.Locale.AcceptLanguage)) {
		return fmt.Errorf("persona contract mismatch: navigator.language %q does not match Accept-Language %q", cfg.Locale.NavigatorLanguage, cfg.Locale.AcceptLanguage)
	}
	if cfg.Locale.AcceptLanguage != "" && len(cfg.Locale.NavigatorLanguages) == 0 {
		return fmt.Errorf("persona contract mismatch: navigator.languages must not be empty when Accept-Language is set")
	}
	if len(cfg.Locale.NavigatorLanguages) > 0 && cfg.Locale.AcceptLanguage != "" && !strings.EqualFold(cfg.Locale.NavigatorLanguages[0], firstLanguage(cfg.Locale.AcceptLanguage)) {
		return fmt.Errorf("persona contract mismatch: navigator.languages first entry %q does not match Accept-Language %q", cfg.Locale.NavigatorLanguages[0], cfg.Locale.AcceptLanguage)
	}
	if cfg.Locale.SecCHLang != "" && cfg.Locale.SecCHLang != strings.Join(cfg.Locale.NavigatorLanguages, ",") {
		return fmt.Errorf("persona contract mismatch: Sec-CH-Lang %q does not match navigator.languages", cfg.Locale.SecCHLang)
	}
	if cfg.Browser.ClientHints.Mobile && !strings.Contains(cfg.Browser.UserAgent, "Mobile") {
		return fmt.Errorf("persona contract mismatch: mobile UA-CH persona requires a mobile user-agent token")
	}
	if cfg.Browser.Family == "chromium" && cfg.Plugins.PDFViewer {
		if !containsString(cfg.Plugins.Plugins, "PDF Viewer") && !containsString(cfg.Plugins.Plugins, "Chrome PDF Viewer") && !containsString(cfg.Plugins.Plugins, "Chromium PDF Viewer") {
			return fmt.Errorf("persona contract mismatch: chromium persona requires PDF plugin entry")
		}
		if !containsString(cfg.Plugins.MIMETypes, "application/pdf") {
			return fmt.Errorf("persona contract mismatch: chromium persona requires application/pdf MIME entry")
		}
	}
	if cfg.Hardware.HardwareConcurrency <= 0 || cfg.Hardware.DeviceMemoryGB <= 0 {
		return fmt.Errorf("persona contract mismatch: hardware concurrency and deviceMemory must be positive")
	}
	if cfg.Screen.Width <= 0 || cfg.Screen.Height <= 0 || cfg.Screen.DPR <= 0 {
		return fmt.Errorf("persona contract mismatch: screen width/height/DPR must be positive")
	}
	if cfg.Screen.AvailWidth <= 0 || cfg.Screen.AvailHeight <= 0 || cfg.Screen.AvailWidth > cfg.Screen.Width || cfg.Screen.AvailHeight > cfg.Screen.Height {
		return fmt.Errorf("persona contract mismatch: screen avail size must be positive and not exceed screen size")
	}
	if cfg.Screen.OuterWidth <= 0 || cfg.Screen.OuterHeight <= 0 || cfg.Screen.InnerWidth <= 0 || cfg.Screen.InnerHeight <= 0 {
		return fmt.Errorf("persona contract mismatch: window inner/outer size must be positive")
	}
	if cfg.Screen.InnerWidth > cfg.Screen.OuterWidth || cfg.Screen.InnerHeight > cfg.Screen.OuterHeight {
		return fmt.Errorf("persona contract mismatch: window inner size cannot exceed outer size")
	}
	if cfg.Screen.ViewportWidth != cfg.Screen.InnerWidth || cfg.Screen.ViewportHeight != cfg.Screen.InnerHeight {
		return fmt.Errorf("persona contract mismatch: viewport size must match window inner size")
	}
	if cfg.Screen.ColorDepth <= 0 {
		return fmt.Errorf("persona contract mismatch: screen color depth must be positive")
	}
	if cfg.Screen.Orientation == "" || (!strings.HasPrefix(cfg.Screen.Orientation, "landscape") && !strings.HasPrefix(cfg.Screen.Orientation, "portrait")) {
		return fmt.Errorf("persona contract mismatch: screen orientation must be landscape-* or portrait-*")
	}
	if !cfg.Platform.Mobile && cfg.Screen.TouchPoints != 0 {
		return fmt.Errorf("persona contract mismatch: desktop persona cannot advertise touch points")
	}
	if cfg.Network.ProxyEnabled {
		if cfg.Network.ProxyType == "" || cfg.Network.ProxyRegion == "" {
			return fmt.Errorf("persona contract mismatch: proxy persona requires proxy type and region metadata")
		}
		if cfg.Network.CountryCode == "" {
			return fmt.Errorf("persona contract mismatch: proxy persona requires known request country metadata")
		}
		if cfg.DNS.Mode != "proxy-aligned" || cfg.DNS.ResolverPolicy != "no-host-or-container-resolver-leak" {
			return fmt.Errorf("persona contract mismatch: proxy persona requires proxy-aligned DNS resolver policy")
		}
		if cfg.Geolocation.Mode != "proxy-aligned" || cfg.Geolocation.CountryCode != cfg.Network.CountryCode || cfg.Geolocation.RegionCode != cfg.Network.RegionCode {
			return fmt.Errorf("persona contract mismatch: proxy persona requires geolocation metadata aligned to proxy region")
		}
	} else {
		if cfg.Network.ProxyType != "" || cfg.Network.ProxyRegion != "" {
			return fmt.Errorf("persona contract mismatch: non-proxy persona cannot include proxy metadata")
		}
		if cfg.DNS.Mode != "local" || cfg.DNS.ResolverPolicy != "local-network-consistent" {
			return fmt.Errorf("persona contract mismatch: non-proxy persona requires local DNS resolver policy")
		}
		if cfg.Geolocation.Mode != "local" {
			return fmt.Errorf("persona contract mismatch: non-proxy persona requires local geolocation policy")
		}
	}
	if cfg.WebRTC.Mode == "" {
		return fmt.Errorf("persona contract mismatch: WebRTC policy mode must be set")
	}
	if cfg.WebRTC.ProxyRegion != cfg.Network.ProxyRegion {
		return fmt.Errorf("persona contract mismatch: WebRTC proxy region must match network proxy region")
	}
	if cfg.Network.ProxyEnabled && (cfg.WebRTC.Mode != "disable_non_proxied_udp" || !cfg.WebRTC.DirectIPRedaction) {
		return fmt.Errorf("persona contract mismatch: proxy persona requires WebRTC direct IP redaction")
	}
	if cfg.Network.CountryCode != "" && cfg.Locale.Timezone != "" && !timezoneMatchesCountry(cfg.Locale.Timezone, cfg.Network.CountryCode) {
		return fmt.Errorf("persona contract mismatch: timezone %q does not match request country %q", cfg.Locale.Timezone, cfg.Network.CountryCode)
	}
	if browseForgeLocaleNeedsCJK(cfg.Locale.Locale) && !cfg.Fonts.CJK {
		return fmt.Errorf("persona contract mismatch: CJK locale requires CJK font profile")
	}
	if cfg.GPU.Mode != "software" && cfg.GPU.Mode != "native" && cfg.GPU.Mode != "passthrough" {
		return fmt.Errorf("persona contract mismatch: GPU mode %q must be software, native, or passthrough", cfg.GPU.Mode)
	}
	if cfg.GPU.Vendor == "" || cfg.GPU.Renderer == "" {
		return fmt.Errorf("persona contract mismatch: GPU vendor/renderer must be declared")
	}
	if cfg.Platform.OS == "macos" && strings.Contains(strings.ToLower(cfg.GPU.Renderer), "swiftshader") {
		return fmt.Errorf("persona contract mismatch: macOS persona cannot advertise Linux SwiftShader renderer")
	}
	if cfg.GPU.Mode == "software" && cfg.GPU.WebGL && (cfg.GPU.GLVersion == "" || cfg.GPU.ShadingLanguageVersion == "" || len(cfg.GPU.ContextAttributes) == 0 || len(cfg.GPU.Extensions) == 0 || len(cfg.GPU.ShaderPrecision) == 0 || len(cfg.GPU.Limits) == 0) {
		return fmt.Errorf("persona contract mismatch: software WebGL baseline must include version, context attributes, extensions, shader precision, and limits")
	}
	if cfg.GPU.Mode == "software" && (!strings.Contains(strings.ToLower(cfg.GPU.Renderer), "swiftshader") || cfg.GPU.ANGLEBackend != "swiftshader-webgl" || cfg.GPU.RenderHashBaseline == "") {
		return fmt.Errorf("persona contract mismatch: software GPU mode requires SwiftShader baseline metadata")
	}
	if cfg.Fonts.ProfileID == "" || len(cfg.Fonts.Families) == 0 || cfg.Fonts.Emoji == "" || cfg.Fonts.Source == "" {
		return fmt.Errorf("persona contract mismatch: font profile must declare profile_id, families, emoji, and source")
	}
	if cfg.Canvas.Stable && (cfg.Canvas.Mode == "" || cfg.Canvas.TextMetricsMode == "" || cfg.Canvas.EmojiBaseline == "" || cfg.Canvas.RenderHashBaseline == "") {
		return fmt.Errorf("persona contract mismatch: stable canvas profile must declare mode, text metrics, emoji, and render baseline")
	}
	if cfg.Audio.Stable && (cfg.Audio.Mode == "" || cfg.Audio.SampleRate <= 0) {
		return fmt.Errorf("persona contract mismatch: stable audio profile must declare mode and sample rate")
	}
	if !cfg.Math.Stable {
		return fmt.Errorf("persona contract mismatch: stable math fingerprint policy must be enabled")
	}
	if !cfg.Geometry.ClientRectsStable {
		return fmt.Errorf("persona contract mismatch: stable client rect policy must be enabled")
	}
	if !cfg.Media.H264 && !cfg.Media.VP9 && !cfg.Media.AV1 {
		return fmt.Errorf("persona contract mismatch: media codec baseline must declare expected codec support")
	}
	switch cfg.Permissions.Notification {
	case "prompt", "default", "granted", "denied":
	default:
		return fmt.Errorf("persona contract mismatch: notification permission policy %q is invalid", cfg.Permissions.Notification)
	}
	if cfg.Storage.QuotaMB < 0 {
		return fmt.Errorf("persona contract mismatch: storage quota must be non-negative")
	}
	if cfg.Storage.Cookies != "profile-persistent" || cfg.Storage.LocalStorage != "profile-persistent" || cfg.Storage.SessionStorage != "session-scoped" || cfg.Storage.IndexedDB != "profile-persistent" || cfg.Storage.QuotaBehavior == "" {
		return fmt.Errorf("persona contract mismatch: storage policy must declare profile-backed cookies/localStorage/indexedDB and session-scoped sessionStorage")
	}
	if !cfg.Realms.DocumentStartInjection {
		return fmt.Errorf("persona contract mismatch: document-start injection must be enabled for cross-realm parity")
	}
	for _, target := range []string{"window", "same-origin-iframe", "sandbox-iframe", "nested-iframe", "dedicated-worker", "shared-worker", "service-worker", "offscreen-canvas-worker"} {
		if !containsString(cfg.Realms.Targets, target) {
			return fmt.Errorf("persona contract mismatch: required realm target %q is missing", target)
		}
	}
	return nil
}

func x64UserAgent(userAgent string) bool {
	return strings.Contains(userAgent, "x86_64") || strings.Contains(userAgent, "Win64") || strings.Contains(userAgent, "x64")
}

func containsStringFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A region label is configuration, never evidence of the current proxy exit.
func validateBrowseForgeProxyCountry(proxyRegion, sessionCountry string, detected fingerprint.GeoDetectionResult) error {
	expected := countryCodeForProxyRegion(proxyRegion)
	actual := sessionCountry
	if actual == "" {
		actual = detected.CountryCode
	}
	if actual == "" {
		return fmt.Errorf("browseforge-chromium proxy country could not be verified through the selected route; check the proxy and retry")
	}
	if actual != expected {
		return fmt.Errorf("browseforge-chromium proxy.region country %q does not match the detected egress country %q; update the network region before launching", expected, actual)
	}
	return nil
}

func timezoneMatchesCountry(timezone, countryCode string) bool {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	switch countryCode {
	case "", "ZZ":
		return true
	case "US":
		return strings.HasPrefix(timezone, "America/")
	case "TW":
		return timezone == "Asia/Taipei"
	case "JP":
		return timezone == "Asia/Tokyo"
	case "KR":
		return timezone == "Asia/Seoul"
	case "SG":
		return timezone == "Asia/Singapore"
	case "HK":
		return timezone == "Asia/Hong_Kong"
	case "DE":
		return timezone == "Europe/Berlin"
	case "FR":
		return timezone == "Europe/Paris"
	case "GB", "UK":
		return timezone == "Europe/London"
	default:
		return true
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstLanguage(acceptLanguage string) string {
	first := strings.TrimSpace(strings.Split(acceptLanguage, ",")[0])
	if semi := strings.IndexByte(first, ';'); semi >= 0 {
		first = first[:semi]
	}
	return first
}

func navigatorLanguagesFromAcceptLanguage(acceptLanguage string) []string {
	parts := strings.Split(acceptLanguage, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		lang := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if lang != "" {
			out = append(out, lang)
		}
	}
	if len(out) == 0 {
		return []string{"en-US", "en"}
	}
	return out
}

func timezoneOffsetMinutes(timezone string) int {
	if timezone == "" {
		return 0
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return 0
	}
	_, offset := time.Now().In(loc).Zone()
	return -offset / 60
}

func browseForgeNetworkProfile(proxyRegion string) browseForgeNativeNetwork {
	network := browseForgeNativeNetwork{
		ProxyEnabled: proxyRegion != "",
		ProxyRegion:  proxyRegion,
		ASNType:      "residential-or-mobile",
	}
	if proxyRegion == "" {
		network.ASNType = "local"
		return network
	}
	network.ProxyType = "configured"
	network.CountryCode = countryCodeForProxyRegion(proxyRegion)
	network.RegionCode = regionCodeForProxyRegion(proxyRegion)
	return network
}

var browseForgeProxyRegionCountryCodes = map[string]string{
	"af": "AF",
	"al": "AL",
	"dz": "DZ",
	"as": "AS",
	"ad": "AD",
	"ao": "AO",
	"ai": "AI",
	"aq": "AQ",
	"ag": "AG",
	"ar": "AR",
	"am": "AM",
	"aw": "AW",
	"au": "AU",
	"at": "AT",
	"az": "AZ",
	"bs": "BS",
	"bh": "BH",
	"bd": "BD",
	"bb": "BB",
	"by": "BY",
	"be": "BE",
	"bz": "BZ",
	"bj": "BJ",
	"bm": "BM",
	"bt": "BT",
	"bo": "BO",
	"bq": "BQ",
	"ba": "BA",
	"bw": "BW",
	"bv": "BV",
	"br": "BR",
	"io": "IO",
	"bn": "BN",
	"bg": "BG",
	"bf": "BF",
	"bi": "BI",
	"cv": "CV",
	"kh": "KH",
	"cm": "CM",
	"ca": "CA",
	"ky": "KY",
	"cf": "CF",
	"td": "TD",
	"cl": "CL",
	"cn": "CN",
	"cx": "CX",
	"cc": "CC",
	"co": "CO",
	"km": "KM",
	"cg": "CG",
	"cd": "CD",
	"ck": "CK",
	"cr": "CR",
	"hr": "HR",
	"cu": "CU",
	"cw": "CW",
	"cy": "CY",
	"cz": "CZ",
	"ci": "CI",
	"dk": "DK",
	"dj": "DJ",
	"dm": "DM",
	"do": "DO",
	"ec": "EC",
	"eg": "EG",
	"sv": "SV",
	"gq": "GQ",
	"er": "ER",
	"ee": "EE",
	"sz": "SZ",
	"et": "ET",
	"fk": "FK",
	"fo": "FO",
	"fj": "FJ",
	"fi": "FI",
	"fr": "FR",
	"gf": "GF",
	"pf": "PF",
	"tf": "TF",
	"ga": "GA",
	"gm": "GM",
	"ge": "GE",
	"de": "DE",
	"gh": "GH",
	"gi": "GI",
	"gr": "GR",
	"gl": "GL",
	"gd": "GD",
	"gp": "GP",
	"gu": "GU",
	"gt": "GT",
	"gg": "GG",
	"gn": "GN",
	"gw": "GW",
	"gy": "GY",
	"ht": "HT",
	"hm": "HM",
	"va": "VA",
	"hn": "HN",
	"hk": "HK",
	"hu": "HU",
	"is": "IS",
	"in": "IN",
	"id": "ID",
	"ir": "IR",
	"iq": "IQ",
	"ie": "IE",
	"im": "IM",
	"il": "IL",
	"it": "IT",
	"jm": "JM",
	"jp": "JP",
	"je": "JE",
	"jo": "JO",
	"kz": "KZ",
	"ke": "KE",
	"ki": "KI",
	"kp": "KP",
	"kr": "KR",
	"kw": "KW",
	"kg": "KG",
	"la": "LA",
	"lv": "LV",
	"lb": "LB",
	"ls": "LS",
	"lr": "LR",
	"ly": "LY",
	"li": "LI",
	"lt": "LT",
	"lu": "LU",
	"mo": "MO",
	"mg": "MG",
	"mw": "MW",
	"my": "MY",
	"mv": "MV",
	"ml": "ML",
	"mt": "MT",
	"mh": "MH",
	"mq": "MQ",
	"mr": "MR",
	"mu": "MU",
	"yt": "YT",
	"mx": "MX",
	"fm": "FM",
	"md": "MD",
	"mc": "MC",
	"mn": "MN",
	"me": "ME",
	"ms": "MS",
	"ma": "MA",
	"mz": "MZ",
	"mm": "MM",
	"na": "NA",
	"nr": "NR",
	"np": "NP",
	"nl": "NL",
	"nc": "NC",
	"nz": "NZ",
	"ni": "NI",
	"ne": "NE",
	"ng": "NG",
	"nu": "NU",
	"nf": "NF",
	"mk": "MK",
	"mp": "MP",
	"no": "NO",
	"om": "OM",
	"pk": "PK",
	"pw": "PW",
	"ps": "PS",
	"pa": "PA",
	"pg": "PG",
	"py": "PY",
	"pe": "PE",
	"ph": "PH",
	"pn": "PN",
	"pl": "PL",
	"pt": "PT",
	"pr": "PR",
	"qa": "QA",
	"ro": "RO",
	"ru": "RU",
	"rw": "RW",
	"re": "RE",
	"bl": "BL",
	"sh": "SH",
	"kn": "KN",
	"lc": "LC",
	"mf": "MF",
	"pm": "PM",
	"vc": "VC",
	"ws": "WS",
	"sm": "SM",
	"st": "ST",
	"sa": "SA",
	"sn": "SN",
	"rs": "RS",
	"sc": "SC",
	"sl": "SL",
	"sg": "SG",
	"sx": "SX",
	"sk": "SK",
	"si": "SI",
	"sb": "SB",
	"so": "SO",
	"za": "ZA",
	"gs": "GS",
	"ss": "SS",
	"es": "ES",
	"lk": "LK",
	"sd": "SD",
	"sr": "SR",
	"sj": "SJ",
	"se": "SE",
	"ch": "CH",
	"sy": "SY",
	"tw": "TW",
	"tj": "TJ",
	"tz": "TZ",
	"th": "TH",
	"tl": "TL",
	"tg": "TG",
	"tk": "TK",
	"to": "TO",
	"tt": "TT",
	"tn": "TN",
	"tm": "TM",
	"tc": "TC",
	"tv": "TV",
	"tr": "TR",
	"ug": "UG",
	"ua": "UA",
	"ae": "AE",
	"gb": "GB",
	"um": "UM",
	"us": "US",
	"uy": "UY",
	"uz": "UZ",
	"vu": "VU",
	"ve": "VE",
	"vn": "VN",
	"vg": "VG",
	"vi": "VI",
	"wf": "WF",
	"eh": "EH",
	"ye": "YE",
	"zm": "ZM",
	"zw": "ZW",
	"ax": "AX",
}

func countryCodeForProxyRegion(region string) string {
	return browseForgeProxyRegionCountryCodes[proxyRegionCountryToken(region)]
}

func proxyRegionCountryToken(region string) string {
	region = strings.ToLower(strings.TrimSpace(region))
	if sep := strings.IndexAny(region, "-_"); sep >= 0 {
		return region[:sep]
	}
	return region
}

func regionCodeForProxyRegion(region string) string {
	if dash := strings.IndexAny(region, "-_"); dash >= 0 && dash+1 < len(region) {
		return strings.ToUpper(region[dash+1:])
	}
	return ""
}

func browseForgeDNSProfile(network browseForgeNativeNetwork) browseForgeNativeDNS {
	if network.ProxyEnabled {
		return browseForgeNativeDNS{Mode: "proxy-aligned", ResolverPolicy: "no-host-or-container-resolver-leak"}
	}
	return browseForgeNativeDNS{Mode: "local", ResolverPolicy: "local-network-consistent"}
}

func browseForgeGeolocationProfile(network browseForgeNativeNetwork) browseForgeNativeGeolocation {
	if network.ProxyEnabled {
		return browseForgeNativeGeolocation{Mode: "proxy-aligned", CountryCode: network.CountryCode, RegionCode: network.RegionCode, City: network.City}
	}
	return browseForgeNativeGeolocation{Mode: "local"}
}

func browseForgeGPUProfile(mode, vendor, renderer string) browseForgeNativeGPU {
	if mode == "" {
		mode = "native"
	}
	gpu := browseForgeNativeGPU{
		Mode:                   mode,
		Vendor:                 vendor,
		Renderer:               renderer,
		WebGL:                  true,
		WebGL2:                 false,
		WebGPU:                 "browser-default",
		GLVersion:              "browser-default",
		ShadingLanguageVersion: "browser-default",
		ContextAttributes:      map[string]string{},
		Extensions:             []string{},
		ShaderPrecision:        map[string]string{},
		Limits:                 map[string]int{},
		WorkerOffscreenCanvas:  true,
		WebGLParams:            map[string]string{},
	}
	if mode == "software" {
		gpu.WebGL2 = true
		gpu.ANGLEBackend = "swiftshader-webgl"
		gpu.WebGPU = "disabled-or-software"
		gpu.GLVersion = "OpenGL ES 2.0 Chromium"
		gpu.ShadingLanguageVersion = "OpenGL ES GLSL ES 1.0 Chromium"
		gpu.ContextAttributes = map[string]string{"alpha": "true", "antialias": "true", "depth": "true", "failIfMajorPerformanceCaveat": "false", "powerPreference": "default", "premultipliedAlpha": "true", "preserveDrawingBuffer": "false", "stencil": "false"}
		gpu.Extensions = []string{"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float", "EXT_float_blend", "EXT_texture_filter_anisotropic", "OES_element_index_uint", "OES_standard_derivatives", "OES_texture_float", "OES_texture_half_float", "WEBGL_debug_renderer_info"}
		gpu.ShaderPrecision = map[string]string{"fragmentHighFloat": "23/127/127", "fragmentMediumFloat": "10/15/15", "vertexHighFloat": "23/127/127"}
		gpu.Limits = map[string]int{"maxCombinedTextureImageUnits": 32, "maxCubeMapTextureSize": 16384, "maxFragmentUniformVectors": 1024, "maxRenderbufferSize": 16384, "maxTextureImageUnits": 16, "maxTextureSize": 16384, "maxVaryingVectors": 30, "maxVertexAttribs": 16, "maxVertexTextureImageUnits": 16, "maxVertexUniformVectors": 4096}
		gpu.RenderHashBaseline = "swiftshader-stable"
	}
	return gpu
}

func browseForgeFontContract(fp map[string]any, platform browseForgeNativePlatform, locale string, policy *config.CloakBrowserConfig) (browseForgeNativeFontProfile, string, bool, error) {
	corpusConfigured := policy != nil && strings.TrimSpace(policy.FontsDir) != ""
	if corpusConfigured {
		families, fontsList, ok, err := browseForgeFingerprintFontFamilies(fp)
		if err != nil {
			return browseForgeNativeFontProfile{}, "", false, err
		}
		if ok {
			return browseForgeFontProfile(platform, locale, families, "explicit-corpus"), fontsList, true, nil
		}
	}
	families := browseForgeDefaultFontFamilies(platform.OS, locale)
	return browseForgeFontProfile(platform, locale, families, "persona-default"), "", false, nil
}

func browseForgeDefaultFontFamilies(osName, locale string) []string {
	cjk := browseForgeLocaleNeedsCJK(locale)
	var families []string
	switch strings.ToLower(strings.TrimSpace(osName)) {
	case "linux":
		families = []string{"Noto Sans", "Noto Serif", "Noto Sans Mono", "Liberation Sans", "Liberation Serif", "Liberation Mono", "DejaVu Sans", "DejaVu Serif", "DejaVu Sans Mono", "Arial", "Times New Roman", "Courier New", "Noto Color Emoji"}
		if cjk {
			families = append(families, "Noto Sans CJK TC", "Noto Serif CJK TC", "Noto Sans CJK SC", "Noto Serif CJK SC")
		}
	case "macos":
		families = []string{"Helvetica", "Arial", "Times", "Times New Roman", "Courier", "Courier New", "Menlo", "Geneva", "Apple Color Emoji"}
		if cjk {
			families = append(families, "PingFang TC", "PingFang SC", "Hiragino Sans", "Songti TC")
		}
	case "windows":
		families = []string{"Segoe UI", "Arial", "Times New Roman", "Courier New", "Consolas", "Calibri", "Cambria", "Microsoft Sans Serif", "Segoe UI Emoji"}
		if cjk {
			families = append(families, "Microsoft JhengHei", "Microsoft YaHei", "MingLiU", "SimSun")
		}
	default:
		families = []string{"Arial", "Times New Roman", "Courier New", "Noto Sans", "Noto Serif", "Noto Sans Mono", "Noto Color Emoji"}
		if cjk {
			families = append(families, "Noto Sans CJK TC", "Noto Serif CJK TC")
		}
	}
	return families
}

func browseForgeLocaleNeedsCJK(locale string) bool {
	locale = strings.ToLower(strings.TrimSpace(locale))
	return strings.HasPrefix(locale, "zh") || strings.HasPrefix(locale, "ja") || strings.HasPrefix(locale, "ko")
}

func browseForgeFontProfile(platform browseForgeNativePlatform, locale string, families []string, source string) browseForgeNativeFontProfile {
	cjk := browseForgeLocaleNeedsCJK(locale)
	emoji := "Noto Color Emoji"
	if platform.OS == "macos" {
		emoji = "Apple Color Emoji"
	} else if platform.OS == "windows" {
		emoji = "Segoe UI Emoji"
	}
	return browseForgeNativeFontProfile{ProfileID: platform.OS + "-" + source, Families: append([]string(nil), families...), Emoji: emoji, CJK: cjk, Source: source}
}

func browseForgeFingerprintFontFamilies(fp map[string]any) ([]string, string, bool, error) {
	if fp == nil {
		return nil, "", false, nil
	}
	value, ok := fp["fonts"]
	if !ok {
		return nil, "", false, nil
	}
	var items []string
	switch typed := value.(type) {
	case []string:
		items = typed
	case []any:
		items = make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, "", false, fmt.Errorf("BrowseForge Chromium fingerprint fonts must contain only strings")
			}
			items = append(items, s)
		}
	default:
		return nil, "", false, fmt.Errorf("BrowseForge Chromium fingerprint fonts must be a string list")
	}
	families := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		if err := validateBrowseForgeFontFamily(item); err != nil {
			return nil, "", false, err
		}
		family := strings.TrimSpace(item)
		families = append(families, family)
	}
	if len(families) == 0 {
		return nil, "", false, nil
	}
	fontsList := strings.Join(families, "|")
	if len(fontsList) > 8192 {
		return nil, "", false, fmt.Errorf("BrowseForge Chromium fingerprint fonts list exceeds 8192 bytes")
	}
	return families, fontsList, true, nil
}

func validateBrowseForgeFontFamily(family string) error {
	if len(family) > 128 {
		return fmt.Errorf("BrowseForge Chromium fingerprint fonts family %q exceeds 128 bytes", family)
	}
	for i := range family {
		c := family[i]
		if c < 0x20 || c > 0x7e || c == '|' {
			return fmt.Errorf("BrowseForge Chromium fingerprint fonts family %q contains unsupported character", family)
		}
	}
	return nil
}

func browseForgeCanvasProfile(fp map[string]any, seed uint64) browseForgeNativeCanvasProfile {
	textSeed := int64((seed >> 16) & 0x7fffffff)
	if v, ok := fingerprintInt(fp, "canvas:seed"); ok {
		return browseForgeNativeCanvasProfile{Mode: "stable-seeded", Seed: v, Stable: true, TextMetricsMode: "stable-profile", TextMetricsSeed: textSeed, EmojiBaseline: "noto-color-emoji", RenderHashBaseline: "seeded"}
	}
	return browseForgeNativeCanvasProfile{Mode: "stable-persona", Seed: int64(seed & 0x7fffffff), Stable: true, TextMetricsMode: "stable-profile", TextMetricsSeed: textSeed, EmojiBaseline: "noto-color-emoji", RenderHashBaseline: "persona"}
}

func browseForgeAudioProfile(fp map[string]any, seed uint64) browseForgeNativeAudioProfile {
	if v, ok := fingerprintInt(fp, "audio:seed"); ok {
		return browseForgeNativeAudioProfile{Mode: "stable-seeded", Seed: v, SampleRate: 48000, Stable: true}
	}
	return browseForgeNativeAudioProfile{Mode: "stable-persona", Seed: int64((seed >> 8) & 0x7fffffff), SampleRate: 48000, Stable: true}
}

func browseForgePluginProfile(policy *config.CloakBrowserConfig) browseForgeNativePluginProfile {
	pdf := cloakPluginsPDF(policy)
	enabled := pdf == "" || pdf == "enabled" || pdf == "true" || pdf == "1"
	if !enabled {
		return browseForgeNativePluginProfile{PDFViewer: false}
	}
	return browseForgeNativePluginProfile{
		PDFViewer: true,
		Plugins:   []string{"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer"},
		MIMETypes: []string{"application/pdf", "text/pdf"},
	}
}

func browseForgeMediaProfile() browseForgeNativeMediaProfile {
	return browseForgeNativeMediaProfile{H264: true, VP9: true, AV1: true, Devices: []string{}}
}

func browseForgeDefaultScreen(osName string) browseForgeNativeScreen {
	switch strings.ToLower(strings.TrimSpace(osName)) {
	case "macos":
		return browseForgeNativeScreen{Width: 1512, Height: 982, AvailWidth: 1512, AvailHeight: 949, OuterWidth: 1512, OuterHeight: 949, InnerWidth: 1512, InnerHeight: 862, DPR: 1, ColorDepth: 30}
	default:
		return browseForgeNativeScreen{Width: 1920, Height: 1080, AvailWidth: 1920, AvailHeight: 1040, OuterWidth: 1920, OuterHeight: 1040, InnerWidth: 1920, InnerHeight: 948, DPR: 1, ColorDepth: 24}
	}
}

func clampScreenAvail(avail, size int) int {
	if size <= 0 {
		return avail
	}
	if avail <= 0 || avail > size {
		return size
	}
	return avail
}
func fallbackGeoForProxyRegion(region string) (timezone, locale string) {
	switch proxyRegionCountryToken(region) {
	case "us":
		return "America/New_York", "en-US"
	case "ca":
		return "America/Toronto", "en-CA"
	case "mx":
		return "America/Mexico_City", "es-MX"
	case "br":
		return "America/Sao_Paulo", "pt-BR"
	case "gb", "uk":
		return "Europe/London", "en-GB"
	case "de":
		return "Europe/Berlin", "de-DE"
	case "fr":
		return "Europe/Paris", "fr-FR"
	case "nl":
		return "Europe/Amsterdam", "nl-NL"
	case "es":
		return "Europe/Madrid", "es-ES"
	case "it":
		return "Europe/Rome", "it-IT"
	case "se":
		return "Europe/Stockholm", "sv-SE"
	case "ch":
		return "Europe/Zurich", "de-CH"
	case "pl":
		return "Europe/Warsaw", "pl-PL"
	case "tw":
		return "Asia/Taipei", "zh-TW"
	case "jp":
		return "Asia/Tokyo", "ja-JP"
	case "kr":
		return "Asia/Seoul", "ko-KR"
	case "sg":
		return "Asia/Singapore", "en-SG"
	case "hk":
		return "Asia/Hong_Kong", "zh-HK"
	case "in":
		return "Asia/Kolkata", "en-IN"
	case "id":
		return "Asia/Jakarta", "id-ID"
	case "th":
		return "Asia/Bangkok", "th-TH"
	case "my":
		return "Asia/Kuala_Lumpur", "ms-MY"
	case "ph":
		return "Asia/Manila", "en-PH"
	case "vn":
		return "Asia/Ho_Chi_Minh", "vi-VN"
	case "au":
		return "Australia/Sydney", "en-AU"
	case "nz":
		return "Pacific/Auckland", "en-NZ"
	default:
		return "", ""
	}
}

type BrowseForgeProxyRegionPreset struct {
	Value string
	Label string
}

var browseForgeProxyRegionPresets = []BrowseForgeProxyRegionPreset{
	{Value: "us-ny", Label: "United States \u2014 New York"},
	{Value: "us-ca", Label: "United States \u2014 California"},
	{Value: "us-tx", Label: "United States \u2014 Texas"},
	{Value: "ca-on", Label: "Canada \u2014 Ontario"},
	{Value: "ca-bc", Label: "Canada \u2014 British Columbia"},
	{Value: "mx-cdmx", Label: "Mexico \u2014 Mexico City"},
	{Value: "br-sao-paulo", Label: "Brazil \u2014 S\u00e3o Paulo"},
	{Value: "gb-london", Label: "United Kingdom \u2014 London"},
	{Value: "de-berlin", Label: "Germany \u2014 Berlin"},
	{Value: "fr-paris", Label: "France \u2014 Paris"},
	{Value: "nl-amsterdam", Label: "Netherlands \u2014 Amsterdam"},
	{Value: "es-madrid", Label: "Spain \u2014 Madrid"},
	{Value: "it-milan", Label: "Italy \u2014 Milan"},
	{Value: "se-stockholm", Label: "Sweden \u2014 Stockholm"},
	{Value: "ch-zurich", Label: "Switzerland \u2014 Z\u00fcrich"},
	{Value: "pl-warsaw", Label: "Poland \u2014 Warsaw"},
	{Value: "tw-taipei", Label: "Taiwan \u2014 Taipei"},
	{Value: "jp-tokyo", Label: "Japan \u2014 Tokyo"},
	{Value: "kr-seoul", Label: "South Korea \u2014 Seoul"},
	{Value: "sg", Label: "Singapore"},
	{Value: "hk", Label: "Hong Kong"},
	{Value: "in-mumbai", Label: "India \u2014 Mumbai"},
	{Value: "id-jakarta", Label: "Indonesia \u2014 Jakarta"},
	{Value: "th-bangkok", Label: "Thailand \u2014 Bangkok"},
	{Value: "my-kuala-lumpur", Label: "Malaysia \u2014 Kuala Lumpur"},
	{Value: "ph-manila", Label: "Philippines \u2014 Manila"},
	{Value: "vn-ho-chi-minh", Label: "Vietnam \u2014 Ho Chi Minh City"},
	{Value: "au-sydney", Label: "Australia \u2014 Sydney"},
	{Value: "nz-auckland", Label: "New Zealand \u2014 Auckland"},
	{Value: "af", Label: "Afghanistan"},
	{Value: "al", Label: "Albania"},
	{Value: "dz", Label: "Algeria"},
	{Value: "as", Label: "American Samoa"},
	{Value: "ad", Label: "Andorra"},
	{Value: "ao", Label: "Angola"},
	{Value: "ai", Label: "Anguilla"},
	{Value: "aq", Label: "Antarctica"},
	{Value: "ag", Label: "Antigua and Barbuda"},
	{Value: "ar", Label: "Argentina"},
	{Value: "am", Label: "Armenia"},
	{Value: "aw", Label: "Aruba"},
	{Value: "au", Label: "Australia"},
	{Value: "at", Label: "Austria"},
	{Value: "az", Label: "Azerbaijan"},
	{Value: "bs", Label: "Bahamas"},
	{Value: "bh", Label: "Bahrain"},
	{Value: "bd", Label: "Bangladesh"},
	{Value: "bb", Label: "Barbados"},
	{Value: "by", Label: "Belarus"},
	{Value: "be", Label: "Belgium"},
	{Value: "bz", Label: "Belize"},
	{Value: "bj", Label: "Benin"},
	{Value: "bm", Label: "Bermuda"},
	{Value: "bt", Label: "Bhutan"},
	{Value: "bo", Label: "Bolivia, Plurinational State of"},
	{Value: "bq", Label: "Bonaire, Sint Eustatius and Saba"},
	{Value: "ba", Label: "Bosnia and Herzegovina"},
	{Value: "bw", Label: "Botswana"},
	{Value: "bv", Label: "Bouvet Island"},
	{Value: "br", Label: "Brazil"},
	{Value: "io", Label: "British Indian Ocean Territory"},
	{Value: "bn", Label: "Brunei Darussalam"},
	{Value: "bg", Label: "Bulgaria"},
	{Value: "bf", Label: "Burkina Faso"},
	{Value: "bi", Label: "Burundi"},
	{Value: "cv", Label: "Cabo Verde"},
	{Value: "kh", Label: "Cambodia"},
	{Value: "cm", Label: "Cameroon"},
	{Value: "ca", Label: "Canada"},
	{Value: "ky", Label: "Cayman Islands"},
	{Value: "cf", Label: "Central African Republic"},
	{Value: "td", Label: "Chad"},
	{Value: "cl", Label: "Chile"},
	{Value: "cn", Label: "China"},
	{Value: "cx", Label: "Christmas Island"},
	{Value: "cc", Label: "Cocos (Keeling) Islands"},
	{Value: "co", Label: "Colombia"},
	{Value: "km", Label: "Comoros"},
	{Value: "cg", Label: "Congo"},
	{Value: "cd", Label: "Congo, Democratic Republic of the"},
	{Value: "ck", Label: "Cook Islands"},
	{Value: "cr", Label: "Costa Rica"},
	{Value: "hr", Label: "Croatia"},
	{Value: "cu", Label: "Cuba"},
	{Value: "cw", Label: "Cura\u00e7ao"},
	{Value: "cy", Label: "Cyprus"},
	{Value: "cz", Label: "Czechia"},
	{Value: "ci", Label: "C\u00f4te d'Ivoire"},
	{Value: "dk", Label: "Denmark"},
	{Value: "dj", Label: "Djibouti"},
	{Value: "dm", Label: "Dominica"},
	{Value: "do", Label: "Dominican Republic"},
	{Value: "ec", Label: "Ecuador"},
	{Value: "eg", Label: "Egypt"},
	{Value: "sv", Label: "El Salvador"},
	{Value: "gq", Label: "Equatorial Guinea"},
	{Value: "er", Label: "Eritrea"},
	{Value: "ee", Label: "Estonia"},
	{Value: "sz", Label: "Eswatini"},
	{Value: "et", Label: "Ethiopia"},
	{Value: "fk", Label: "Falkland Islands (Malvinas)"},
	{Value: "fo", Label: "Faroe Islands"},
	{Value: "fj", Label: "Fiji"},
	{Value: "fi", Label: "Finland"},
	{Value: "fr", Label: "France"},
	{Value: "gf", Label: "French Guiana"},
	{Value: "pf", Label: "French Polynesia"},
	{Value: "tf", Label: "French Southern Territories"},
	{Value: "ga", Label: "Gabon"},
	{Value: "gm", Label: "Gambia"},
	{Value: "ge", Label: "Georgia"},
	{Value: "de", Label: "Germany"},
	{Value: "gh", Label: "Ghana"},
	{Value: "gi", Label: "Gibraltar"},
	{Value: "gr", Label: "Greece"},
	{Value: "gl", Label: "Greenland"},
	{Value: "gd", Label: "Grenada"},
	{Value: "gp", Label: "Guadeloupe"},
	{Value: "gu", Label: "Guam"},
	{Value: "gt", Label: "Guatemala"},
	{Value: "gg", Label: "Guernsey"},
	{Value: "gn", Label: "Guinea"},
	{Value: "gw", Label: "Guinea-Bissau"},
	{Value: "gy", Label: "Guyana"},
	{Value: "ht", Label: "Haiti"},
	{Value: "hm", Label: "Heard Island and McDonald Islands"},
	{Value: "va", Label: "Holy See"},
	{Value: "hn", Label: "Honduras"},
	{Value: "hu", Label: "Hungary"},
	{Value: "is", Label: "Iceland"},
	{Value: "in", Label: "India"},
	{Value: "id", Label: "Indonesia"},
	{Value: "ir", Label: "Iran, Islamic Republic of"},
	{Value: "iq", Label: "Iraq"},
	{Value: "ie", Label: "Ireland"},
	{Value: "im", Label: "Isle of Man"},
	{Value: "il", Label: "Israel"},
	{Value: "it", Label: "Italy"},
	{Value: "jm", Label: "Jamaica"},
	{Value: "jp", Label: "Japan"},
	{Value: "je", Label: "Jersey"},
	{Value: "jo", Label: "Jordan"},
	{Value: "kz", Label: "Kazakhstan"},
	{Value: "ke", Label: "Kenya"},
	{Value: "ki", Label: "Kiribati"},
	{Value: "kp", Label: "Korea, Democratic People's Republic of"},
	{Value: "kr", Label: "Korea, Republic of"},
	{Value: "kw", Label: "Kuwait"},
	{Value: "kg", Label: "Kyrgyzstan"},
	{Value: "la", Label: "Lao People's Democratic Republic"},
	{Value: "lv", Label: "Latvia"},
	{Value: "lb", Label: "Lebanon"},
	{Value: "ls", Label: "Lesotho"},
	{Value: "lr", Label: "Liberia"},
	{Value: "ly", Label: "Libya"},
	{Value: "li", Label: "Liechtenstein"},
	{Value: "lt", Label: "Lithuania"},
	{Value: "lu", Label: "Luxembourg"},
	{Value: "mo", Label: "Macao"},
	{Value: "mg", Label: "Madagascar"},
	{Value: "mw", Label: "Malawi"},
	{Value: "my", Label: "Malaysia"},
	{Value: "mv", Label: "Maldives"},
	{Value: "ml", Label: "Mali"},
	{Value: "mt", Label: "Malta"},
	{Value: "mh", Label: "Marshall Islands"},
	{Value: "mq", Label: "Martinique"},
	{Value: "mr", Label: "Mauritania"},
	{Value: "mu", Label: "Mauritius"},
	{Value: "yt", Label: "Mayotte"},
	{Value: "mx", Label: "Mexico"},
	{Value: "fm", Label: "Micronesia, Federated States of"},
	{Value: "md", Label: "Moldova, Republic of"},
	{Value: "mc", Label: "Monaco"},
	{Value: "mn", Label: "Mongolia"},
	{Value: "me", Label: "Montenegro"},
	{Value: "ms", Label: "Montserrat"},
	{Value: "ma", Label: "Morocco"},
	{Value: "mz", Label: "Mozambique"},
	{Value: "mm", Label: "Myanmar"},
	{Value: "na", Label: "Namibia"},
	{Value: "nr", Label: "Nauru"},
	{Value: "np", Label: "Nepal"},
	{Value: "nl", Label: "Netherlands, Kingdom of the"},
	{Value: "nc", Label: "New Caledonia"},
	{Value: "nz", Label: "New Zealand"},
	{Value: "ni", Label: "Nicaragua"},
	{Value: "ne", Label: "Niger"},
	{Value: "ng", Label: "Nigeria"},
	{Value: "nu", Label: "Niue"},
	{Value: "nf", Label: "Norfolk Island"},
	{Value: "mk", Label: "North Macedonia"},
	{Value: "mp", Label: "Northern Mariana Islands"},
	{Value: "no", Label: "Norway"},
	{Value: "om", Label: "Oman"},
	{Value: "pk", Label: "Pakistan"},
	{Value: "pw", Label: "Palau"},
	{Value: "ps", Label: "Palestine, State of"},
	{Value: "pa", Label: "Panama"},
	{Value: "pg", Label: "Papua New Guinea"},
	{Value: "py", Label: "Paraguay"},
	{Value: "pe", Label: "Peru"},
	{Value: "ph", Label: "Philippines"},
	{Value: "pn", Label: "Pitcairn"},
	{Value: "pl", Label: "Poland"},
	{Value: "pt", Label: "Portugal"},
	{Value: "pr", Label: "Puerto Rico"},
	{Value: "qa", Label: "Qatar"},
	{Value: "ro", Label: "Romania"},
	{Value: "ru", Label: "Russian Federation"},
	{Value: "rw", Label: "Rwanda"},
	{Value: "re", Label: "R\u00e9union"},
	{Value: "bl", Label: "Saint Barth\u00e9lemy"},
	{Value: "sh", Label: "Saint Helena, Ascension and Tristan da Cunha"},
	{Value: "kn", Label: "Saint Kitts and Nevis"},
	{Value: "lc", Label: "Saint Lucia"},
	{Value: "mf", Label: "Saint Martin (French part)"},
	{Value: "pm", Label: "Saint Pierre and Miquelon"},
	{Value: "vc", Label: "Saint Vincent and the Grenadines"},
	{Value: "ws", Label: "Samoa"},
	{Value: "sm", Label: "San Marino"},
	{Value: "st", Label: "Sao Tome and Principe"},
	{Value: "sa", Label: "Saudi Arabia"},
	{Value: "sn", Label: "Senegal"},
	{Value: "rs", Label: "Serbia"},
	{Value: "sc", Label: "Seychelles"},
	{Value: "sl", Label: "Sierra Leone"},
	{Value: "sx", Label: "Sint Maarten (Dutch part)"},
	{Value: "sk", Label: "Slovakia"},
	{Value: "si", Label: "Slovenia"},
	{Value: "sb", Label: "Solomon Islands"},
	{Value: "so", Label: "Somalia"},
	{Value: "za", Label: "South Africa"},
	{Value: "gs", Label: "South Georgia and the South Sandwich Islands"},
	{Value: "ss", Label: "South Sudan"},
	{Value: "es", Label: "Spain"},
	{Value: "lk", Label: "Sri Lanka"},
	{Value: "sd", Label: "Sudan"},
	{Value: "sr", Label: "Suriname"},
	{Value: "sj", Label: "Svalbard and Jan Mayen"},
	{Value: "se", Label: "Sweden"},
	{Value: "ch", Label: "Switzerland"},
	{Value: "sy", Label: "Syrian Arab Republic"},
	{Value: "tw", Label: "Taiwan"},
	{Value: "tj", Label: "Tajikistan"},
	{Value: "tz", Label: "Tanzania, United Republic of"},
	{Value: "th", Label: "Thailand"},
	{Value: "tl", Label: "Timor-Leste"},
	{Value: "tg", Label: "Togo"},
	{Value: "tk", Label: "Tokelau"},
	{Value: "to", Label: "Tonga"},
	{Value: "tt", Label: "Trinidad and Tobago"},
	{Value: "tn", Label: "Tunisia"},
	{Value: "tm", Label: "Turkmenistan"},
	{Value: "tc", Label: "Turks and Caicos Islands"},
	{Value: "tv", Label: "Tuvalu"},
	{Value: "tr", Label: "T\u00fcrkiye"},
	{Value: "ug", Label: "Uganda"},
	{Value: "ua", Label: "Ukraine"},
	{Value: "ae", Label: "United Arab Emirates"},
	{Value: "gb", Label: "United Kingdom of Great Britain and Northern Ireland"},
	{Value: "um", Label: "United States Minor Outlying Islands"},
	{Value: "us", Label: "United States of America"},
	{Value: "uy", Label: "Uruguay"},
	{Value: "uz", Label: "Uzbekistan"},
	{Value: "vu", Label: "Vanuatu"},
	{Value: "ve", Label: "Venezuela, Bolivarian Republic of"},
	{Value: "vn", Label: "Viet Nam"},
	{Value: "vg", Label: "Virgin Islands (British)"},
	{Value: "vi", Label: "Virgin Islands (U.S.)"},
	{Value: "wf", Label: "Wallis and Futuna"},
	{Value: "eh", Label: "Western Sahara"},
	{Value: "ye", Label: "Yemen"},
	{Value: "zm", Label: "Zambia"},
	{Value: "zw", Label: "Zimbabwe"},
	{Value: "ax", Label: "\u00c5land Islands"},
}

const BrowseForgeProxyRegionExamples = "us-ny, us-ca, us-tx, ca-on, ca-bc, mx-cdmx, br-sao-paulo, gb-london, de-berlin, fr-paris, nl-amsterdam, es-madrid, it-milan, se-stockholm, ch-zurich, pl-warsaw, tw-taipei, jp-tokyo, kr-seoul, sg, hk, in-mumbai, id-jakarta, th-bangkok, my-kuala-lumpur, ph-manila, vn-ho-chi-minh, au-sydney, nz-auckland, ... country presets such as za, ae, ar"

func BrowseForgeProxyRegionPresets() []BrowseForgeProxyRegionPreset {
	out := make([]BrowseForgeProxyRegionPreset, len(browseForgeProxyRegionPresets))
	copy(out, browseForgeProxyRegionPresets)
	return out
}

func BrowseForgeProxyRegionValues() []string {
	out := make([]string, 0, len(browseForgeProxyRegionPresets))
	for _, preset := range browseForgeProxyRegionPresets {
		out = append(out, preset.Value)
	}
	return out
}

func NormalizeBrowseForgeProxyRegion(region string) (string, error) {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		return "", nil
	}
	if len(region) > 64 {
		return "", fmt.Errorf("browseforge-chromium proxy_region must be a redacted region label of at most 64 characters")
	}
	for _, r := range region {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "", fmt.Errorf("browseforge-chromium proxy_region must contain only letters, digits, hyphen, or underscore")
	}
	if region[0] == '-' || region[0] == '_' || region[len(region)-1] == '-' || region[len(region)-1] == '_' {
		return "", fmt.Errorf("browseforge-chromium proxy_region must start and end with a letter or digit")
	}
	for _, preset := range browseForgeProxyRegionPresets {
		if region == preset.Value {
			return region, nil
		}
	}
	return "", fmt.Errorf("browseforge-chromium proxy_region must be one of the supported presets: %s", BrowseForgeProxyRegionExamples)
}

func sanitizeBrowseForgeProxyRegion(region string) (string, error) {
	return NormalizeBrowseForgeProxyRegion(region)
}

func fingerprintIntDefault(fp map[string]any, key string, fallback int) int {
	if value, ok := fingerprintInt(fp, key); ok {
		return int(value)
	}
	return fallback
}

func fingerprintFloatDefault(fp map[string]any, key string, fallback float64) float64 {
	if fp == nil {
		return fallback
	}
	switch typed := fp[key].(type) {
	case int:
		if typed > 0 {
			return float64(typed)
		}
	case int64:
		if typed > 0 {
			return float64(typed)
		}
	case float64:
		if typed > 0 {
			return typed
		}
	case json.Number:
		if parsed, err := strconv.ParseFloat(string(typed), 64); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func applyCloakBrowserLaunchPolicy(args []string, userDataDir string, policy *config.CloakBrowserConfig, fallback bool) ([]string, error) {
	out := append([]string(nil), args...)
	if policy == nil {
		return out, nil
	}

	if policy.SafeGPU || fallback {
		out = appendUniqueChromiumArgs(out,
			"--disable-gpu",
			"--disable-gpu-compositing",
			"--disable-gpu-sandbox",
			"--disable-gpu-shader-disk-cache",
			"--in-process-gpu",
		)
	}
	if policy.IsolatedRuntimeCache || fallback {
		cacheDir := filepath.Join(userDataDir, "BrowseForgeRuntimeCache", fmt.Sprintf("cache-%d-%d", os.Getpid(), time.Now().UnixNano()))
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return nil, fmt.Errorf("create chromium runtime cache dir: %w", err)
		}
		out = append(out, "--disk-cache-dir="+cacheDir)
	}
	out = appendUniqueChromiumArgs(out, sanitizeExtraChromiumArgs(policy.ExtraArgs)...)
	return out, nil
}

func resolveCloakFingerprintPlatform(policy *config.CloakBrowserConfig, goos string) (string, error) {
	platform := "Win32"
	if goos == "darwin" {
		platform = "MacIntel"
	}
	if policy == nil || policy.FingerprintPlatform == "" || policy.FingerprintPlatform == "auto" {
		return platform, nil
	}
	switch policy.FingerprintPlatform {
	case "windows":
		return "Win32", nil
	case "macos":
		return "MacIntel", nil
	case "linux":
		return "Linux x86_64", nil
	default:
		return "", fmt.Errorf("cloakbrowser fingerprint_platform must be auto, macos, windows, or linux")
	}
}

func resolveChromiumFingerprintPlatform(policy *config.CloakBrowserConfig, goos, goarch string) (string, error) {
	if policy == nil || policy.FingerprintPlatform == "" || policy.FingerprintPlatform == "auto" {
		switch goos {
		case "darwin":
			return "MacIntel", nil
		case "linux":
			if goarch == "arm64" {
				return "Linux aarch64", nil
			}
			return "Linux x86_64", nil
		default:
			return "Win32", nil
		}
	}
	switch policy.FingerprintPlatform {
	case "windows":
		return "Win32", nil
	case "macos":
		return "MacIntel", nil
	case "linux":
		if goarch == "arm64" {
			return "Linux aarch64", nil
		}
		return "Linux x86_64", nil
	default:
		return "", fmt.Errorf("chromium fingerprint_platform must be auto, macos, windows, or linux")
	}
}

func effectiveChromiumUserAgent(fp map[string]any, platform string) string {
	if ua, ok := fingerprintString(fp, "navigator.userAgent"); ok && userAgentMatchesPlatform(ua, platform) {
		return ua
	}
	return defaultChromiumUserAgent(platform)
}

func userAgentMatchesPlatform(userAgent, platform string) bool {
	switch platform {
	case "MacIntel":
		return strings.Contains(userAgent, "Macintosh")
	case "Linux aarch64":
		return strings.Contains(userAgent, "Linux aarch64")
	case "Linux x86_64":
		return strings.Contains(userAgent, "Linux x86_64")
	default:
		return strings.Contains(userAgent, "Windows NT")
	}
}

func effectiveChromiumAcceptLanguage(fp map[string]any, locale string) string {
	profileAcceptLanguage, ok := fingerprintAcceptLanguage(fp)
	if ok && acceptLanguageMatchesLocale(profileAcceptLanguage, locale) {
		return profileAcceptLanguage
	}
	return acceptLanguageForLocale(locale)
}

func acceptLanguageMatchesLocale(acceptLanguage, locale string) bool {
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return strings.TrimSpace(acceptLanguage) != ""
	}
	first := strings.TrimSpace(strings.Split(acceptLanguage, ",")[0])
	return strings.EqualFold(first, locale)
}

func acceptLanguageForLocale(locale string) string {
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return "en-US,en;q=0.9"
	}
	if dash := strings.IndexByte(locale, '-'); dash > 0 {
		primary := locale[:dash]
		return locale + "," + primary + ";q=0.9"
	}
	return locale
}

func chromiumAcceptLanguageSwitchValue(acceptLanguage string) string {
	parts := strings.Split(acceptLanguage, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		lang := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if lang != "" {
			cleaned = append(cleaned, lang)
		}
	}
	return strings.Join(cleaned, ",")
}

func appendCloakBrowserFingerprintArgs(args []string, fp map[string]any, acceptLanguage string) []string {
	if acceptLanguage := chromiumAcceptLanguageSwitchValue(acceptLanguage); acceptLanguage != "" {
		args = append(args, "--fingerprint-accept-language="+acceptLanguage)
	}
	if v, ok := fingerprintInt(fp, "navigator.hardwareConcurrency"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-hardware-concurrency=%d", v))
	}
	if v, ok := fingerprintInt(fp, "navigator.deviceMemory"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-device-memory=%d", v))
	}
	if v, ok := fingerprintInt(fp, "screen.width"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-screen-width=%d", v))
	}
	if v, ok := fingerprintInt(fp, "screen.height"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-screen-height=%d", v))
	}
	if v, ok := fingerprintInt(fp, "screen.availWidth"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-screen-avail-width=%d", v))
	}
	if v, ok := fingerprintInt(fp, "screen.availHeight"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-screen-avail-height=%d", v))
	}
	if dpr := fingerprintFloatDefault(fp, "screen.devicePixelRatio", 0); dpr >= 0.5 && dpr <= 4 {
		value := fmt.Sprintf("%g", dpr)
		args = append(args, "--force-device-scale-factor="+value, "--fingerprint-screen-device-scale-factor="+value)
	}
	if v, ok := fingerprintInt(fp, "canvas:seed"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-canvas-noise=%d", v))
	}
	if v, ok := fingerprintInt(fp, "audio:seed"); ok {
		args = append(args, fmt.Sprintf("--fingerprint-audio-noise=%d", v))
	}
	if v, ok := fingerprintStringList(fp, "fonts", "|"); ok {
		args = append(args, "--fingerprint-fonts-list="+v)
	}
	if v, ok := fingerprintString(fp, "webGl:vendor"); ok {
		args = append(args, "--fingerprint-webgl-vendor="+v)
	}
	if v, ok := fingerprintString(fp, "webGl:renderer"); ok {
		args = append(args, "--fingerprint-webgl-renderer="+v)
	}
	return args
}

func fingerprintString(fp map[string]any, key string) (string, bool) {
	if fp == nil {
		return "", false
	}
	value, ok := fp[key]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}

func fingerprintAcceptLanguage(fp map[string]any) (string, bool) {
	if value, ok := fp["navigator.languages"]; ok {
		switch typed := value.(type) {
		case []string:
			if len(typed) > 0 {
				return strings.Join(typed, ","), true
			}
		case []any:
			langs := make([]string, 0, len(typed))
			for _, item := range typed {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					langs = append(langs, strings.TrimSpace(s))
				}
			}
			if len(langs) > 0 {
				return strings.Join(langs, ","), true
			}
		}
	}
	return fingerprintString(fp, "navigator.language")
}

func fingerprintStringList(fp map[string]any, key string, sep string) (string, bool) {
	if fp == nil {
		return "", false
	}
	value, ok := fp[key]
	if !ok {
		return "", false
	}
	var items []string
	switch typed := value.(type) {
	case []string:
		items = typed
	case []any:
		items = make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				items = append(items, s)
			}
		}
	default:
		return "", false
	}
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !strings.Contains(item, sep) {
			cleaned = append(cleaned, item)
		}
	}
	if len(cleaned) == 0 {
		return "", false
	}
	return strings.Join(cleaned, sep), true
}

func fingerprintInt(fp map[string]any, key string) (int64, bool) {
	if fp == nil {
		return 0, false
	}
	value, ok := fp[key]
	if !ok {
		return 0, false
	}
	var n int64
	switch typed := value.(type) {
	case int:
		n = int64(typed)
	case int64:
		n = typed
	case float64:
		if typed != float64(int64(typed)) {
			return 0, false
		}
		n = int64(typed)
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		n = parsed
	default:
		return 0, false
	}
	return n, n > 0
}

func cloakStorageQuotaMB(policy *config.CloakBrowserConfig) int64 {
	if policy == nil {
		return 0
	}
	return policy.StorageQuotaMB
}

func cloakPluginsPDF(policy *config.CloakBrowserConfig) string {
	if policy == nil {
		return ""
	}
	switch policy.PluginsPDF {
	case "", "enabled", "true", "1", "disabled", "false", "0":
		return policy.PluginsPDF
	default:
		return ""
	}
}

func resolveCloakFontsDir(policy *config.CloakBrowserConfig) (string, error) {
	if policy != nil && policy.FontsDir != "" {
		fontsDir, err := filepath.Abs(policy.FontsDir)
		if err != nil {
			return "", fmt.Errorf("cloakbrowser fonts_dir: %w", err)
		}
		info, err := os.Stat(fontsDir)
		if err != nil {
			return "", fmt.Errorf("cloakbrowser fonts_dir unavailable: %w", err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("cloakbrowser fonts_dir is not a directory: %s", fontsDir)
		}
		return fontsDir, nil
	}
	if info, err := os.Stat("/usr/share/fonts"); err == nil && info.IsDir() {
		return "/usr/share/fonts", nil
	}
	return "", nil
}

func validateCloakFingerprintPolicy(policy *config.CloakBrowserConfig, platform string, goos string) error {
	if policy == nil {
		return nil
	}
	mode := policy.TargetPlatformPolicy
	if mode == "" {
		mode = "warn"
	}
	switch mode {
	case "allow", "warn", "strict":
	default:
		return fmt.Errorf("cloakbrowser target_platform_policy must be strict, warn, or allow")
	}
	switch policy.PluginsPDF {
	case "", "enabled", "true", "1", "disabled", "false", "0":
	default:
		return fmt.Errorf("cloakbrowser plugins_pdf must be enabled/true/1 or disabled/false/0")
	}
	if mode != "allow" && platform == "Win32" && goos != "windows" && policy.FontsDir == "" {
		msg := "Windows CloakBrowser fingerprint on non-Windows host should configure runtimes.cloakbrowser.settings.fonts_dir with a Windows-compatible font pack"
		if mode == "strict" {
			return fmt.Errorf("%s", msg)
		}
		slog.Warn(msg, "goos", goos, "platform", platform)
	}
	return nil
}

func shouldAutoFallbackCloakBrowserLaunch(policy *config.CloakBrowserConfig, err error) bool {
	return policy != nil &&
		policy.AutoSafeGPUFallback &&
		isChromiumGPUOrCacheLaunchFailure(err) &&
		(!policy.SafeGPU || !policy.IsolatedRuntimeCache)
}

func appendUniqueChromiumArgs(args []string, extra ...string) []string {
	seen := make(map[string]bool, len(args)+len(extra))
	for _, arg := range args {
		seen[arg] = true
	}
	for _, arg := range extra {
		if arg == "" || seen[arg] {
			continue
		}
		seen[arg] = true
		args = append(args, arg)
	}
	return args
}
