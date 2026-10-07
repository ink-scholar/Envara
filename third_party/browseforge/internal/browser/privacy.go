package browser

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"

	"browseforge/internal/profile"
	"github.com/mxschmitt/playwright-go"
)

// Explicit collection hosts; ordinary app APIs and authentication are untouched.
var standardTrackerDomains = []string{"google-analytics.com", "doubleclick.net", "api.segment.io", "api.segment.com", "cdn.segment.com"}
var strictTrackerDomains = []string{"googletagmanager.com", "api.mixpanel.com", "api-js.mixpanel.com", "api.amplitude.com", "api2.amplitude.com", "cdn.amplitude.com", "hotjar.com", "hotjar.io", "sessions.bugsnag.com", "notify.bugsnag.com", "browser-intake-datadoghq.com", "browser-intake-datadoghq.eu", "ingest.sentry.io", "ingest.us.sentry.io", "ingest.de.sentry.io"}

// Explicit service roots only; a last-two-label heuristic would incorrectly
// combine unrelated sites on shared hosting or public suffixes.
var trackerServiceRoots = map[string][]string{
	"google-analytics.com":         {"google-analytics.com"},
	"doubleclick.net":              {"doubleclick.net"},
	"googletagmanager.com":         {"googletagmanager.com"},
	"api.segment.io":               {"segment.com", "segment.io"},
	"api.segment.com":              {"segment.com", "segment.io"},
	"cdn.segment.com":              {"segment.com", "segment.io"},
	"api.mixpanel.com":             {"mixpanel.com"},
	"api-js.mixpanel.com":          {"mixpanel.com"},
	"api.amplitude.com":            {"amplitude.com"},
	"api2.amplitude.com":           {"amplitude.com"},
	"cdn.amplitude.com":            {"amplitude.com"},
	"hotjar.com":                   {"hotjar.com", "hotjar.io"},
	"hotjar.io":                    {"hotjar.com", "hotjar.io"},
	"sessions.bugsnag.com":         {"bugsnag.com"},
	"notify.bugsnag.com":           {"bugsnag.com"},
	"browser-intake-datadoghq.com": {"datadoghq.com", "browser-intake-datadoghq.com"},
	"browser-intake-datadoghq.eu":  {"datadoghq.eu", "browser-intake-datadoghq.eu"},
	"ingest.sentry.io":             {"sentry.io"},
	"ingest.us.sentry.io":          {"sentry.io"},
	"ingest.de.sentry.io":          {"sentry.io"},
}

type PrivacyState struct {
	Mode            string
	Geolocation     *profile.Geolocation
	BlockedRequests atomic.Uint64
}

func (s *PrivacyState) Snapshot() map[string]any {
	if s == nil {
		return map[string]any{"mode": "standard", "blockedRequests": uint64(0), "geolocation": nil, "geolocationPolicy": "deny", "enabled": false}
	}
	geoPolicy := "deny"
	var geo *profile.Geolocation
	if s.Geolocation != nil {
		copied := *s.Geolocation
		geo = &copied
		geoPolicy = "proxy-region"
	}
	serviceWorkers := "block"
	if s.Mode == "off" {
		serviceWorkers = "allow"
	}
	return map[string]any{"mode": s.Mode, "blockedRequests": s.BlockedRequests.Load(), "geolocation": geo, "geolocationPolicy": geoPolicy, "trackerScope": "third-party-http", "enabled": s.Mode != "off", "serviceWorkers": serviceWorkers}
}

func checkedPrivacyURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil
	}
	return parsed
}
func matchingHost(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}
func shouldBlockTracker(raw, firstParty, mode string) bool {
	if mode == "off" {
		return false
	}
	target := checkedPrivacyURL(raw)
	if target == nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	trackerDomain := ""
	for _, domain := range standardTrackerDomains {
		if matchingHost(host, domain) {
			trackerDomain = domain
			break
		}
	}
	if trackerDomain == "" && mode == "strict" {
		for _, domain := range strictTrackerDomains {
			if matchingHost(host, domain) {
				trackerDomain = domain
				break
			}
		}
	}
	if trackerDomain == "" {
		return false
	}
	if first := checkedPrivacyURL(firstParty); first != nil {
		firstHost := strings.TrimSuffix(strings.ToLower(first.Hostname()), ".")
		if matchingHost(host, firstHost) || matchingHost(firstHost, host) {
			return false
		}
		for _, root := range trackerServiceRoots[trackerDomain] {
			if matchingHost(firstHost, root) {
				return false
			}
		}
	}
	return true
}
func requestFirstParty(request playwright.Request) (firstParty string) {
	// Requests without a frame (for example a browser-owned request) have no
	// first-party exception. Do not derive the hostname from URL query strings.
	defer func() {
		if recover() != nil {
			firstParty = ""
		}
	}()
	frame := request.Frame()
	if frame == nil {
		return ""
	}
	top := frame
	for top.ParentFrame() != nil {
		top = top.ParentFrame()
	}
	// The destination is first party for a top-level navigation, even while the
	// frame still reports the previous page. Fetches and subframes keep its top.
	if request.IsNavigationRequest() && frame == top {
		return request.URL()
	}
	if checkedPrivacyURL(top.URL()) != nil {
		return top.URL()
	}
	return ""
}

func browserPrivacyMode(p *profile.Profile) (string, error) {
	privacy, err := profile.NormalizePrivacy(p.SessionPrivacy)
	if err != nil {
		return "", err
	}
	if err := profile.ValidateGeolocation(p.SessionGeolocation); err != nil {
		return "", err
	}
	return privacy.Mode, nil
}

func chromiumPrivacyArgs(mode string) []string {
	// Prevent a later prompt from revealing OS location when no egress location
	// is known. Explicit context geolocation permission can still be granted.
	args := []string{"--deny-permission-prompts"}
	if mode != "off" {
		args = append(args, "--disable-domain-reliability", "--disable-breakpad", "--disable-sync", "--metrics-recording-only", "--no-pings")
	}
	return args
}
func firefoxPrivacyPrefs(mode string, hasGeolocation bool) map[string]any {
	prefs := map[string]any{"geo.enabled": hasGeolocation, "geo.provider.network.url": "", "geo.provider.use_corelocation": false, "geo.provider.use_gpsd": false, "geo.provider.ms-windows-location": false}
	if mode != "off" {
		for _, key := range []string{"toolkit.telemetry.enabled", "datareporting.healthreport.uploadEnabled", "datareporting.policy.dataSubmissionEnabled", "datareporting.usage.uploadEnabled", "toolkit.telemetry.archive.enabled", "toolkit.telemetry.unified", "toolkit.telemetry.newProfilePing.enabled", "toolkit.telemetry.shutdownPingSender.enabled", "toolkit.telemetry.firstShutdownPing.enabled", "browser.ping-centre.telemetry"} {
			prefs[key] = false
		}
		prefs["toolkit.telemetry.server"] = ""
		prefs["toolkit.coverage.opt-out"] = true
	}
	return prefs
}

func denyChromiumLocation(ctx playwright.BrowserContext, page playwright.Page) error {
	cdp, err := ctx.NewCDPSession(page)
	if err != nil {
		return err
	}
	params := map[string]any{"permission": map[string]any{"name": "geolocation"}, "setting": "denied"}
	if response, err := cdp.Send("Target.getTargetInfo", nil); err == nil {
		if object, ok := response.(map[string]any); ok {
			if target, ok := object["targetInfo"].(map[string]any); ok {
				if id, ok := target["browserContextId"].(string); ok && id != "" {
					// Some persistent kernels expose a target ID for their default
					// context which Browser.setPermission cannot address. Only use
					// an ID returned by the browser's addressable-context inventory.
					if contexts, err := cdp.Send("Target.getBrowserContexts", nil); err == nil {
						if data, ok := contexts.(map[string]any); ok {
							if ids, ok := data["browserContextIds"].([]any); ok {
								for _, candidate := range ids {
									if candidate == id {
										params["browserContextId"] = id
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if _, err := cdp.Send("Browser.setPermission", params); err != nil {
		cdp.Detach()
		return err
	}
	// Empty coordinates make the position unavailable; they do not clear the
	// override and therefore cannot restore the OS position provider.
	_, err = cdp.Send("Emulation.setGeolocationOverride", map[string]any{})
	if err != nil {
		cdp.Detach()
		return err
	}
	// Detaching resets Chrome's permission overrides. Own this session for the
	// entire page lifetime, rather than accidentally restoring OS permissions.
	page.OnClose(func(playwright.Page) { cdp.Detach() })
	return err
}

func installBrowserPrivacy(ctx playwright.BrowserContext, p *profile.Profile, chromium bool) (*PrivacyState, error) {
	mode, err := browserPrivacyMode(p)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("privacy requires a browser context")
	}
	state := &PrivacyState{Mode: mode}
	if p.SessionGeolocation != nil {
		geo := *p.SessionGeolocation
		state.Geolocation = &geo
	}
	if err := ctx.ClearPermissions(); err != nil {
		return nil, err
	}
	var geo *playwright.Geolocation
	permissions := []string{}
	if state.Geolocation != nil {
		geo = &playwright.Geolocation{Latitude: state.Geolocation.Latitude, Longitude: state.Geolocation.Longitude, Accuracy: playwright.Float(state.Geolocation.Accuracy)}
		permissions = []string{"geolocation"}
	}
	if err := ctx.SetGeolocation(geo); err != nil {
		return nil, err
	}
	if err := ctx.GrantPermissions(permissions); err != nil {
		return nil, err
	}
	if chromium && geo == nil {
		for _, page := range ctx.Pages() {
			if err := denyChromiumLocation(ctx, page); err != nil {
				return nil, err
			}
		}
		ctx.OnPage(func(page playwright.Page) {
			go func() {
				if denyChromiumLocation(ctx, page) != nil {
					page.Close()
				}
			}()
		})
	}
	if mode != "off" {
		if err := ctx.Route("**/*", func(route playwright.Route) {
			request := route.Request()
			if shouldBlockTracker(request.URL(), requestFirstParty(request), mode) {
				if route.Abort("blockedbyclient") == nil {
					state.BlockedRequests.Add(1)
				}
			} else {
				route.Continue()
			}
		}); err != nil {
			return nil, err
		}
	}
	return state, nil
}
