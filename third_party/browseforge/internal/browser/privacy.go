package browser

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"

	"browseforge/internal/profile"
	"github.com/playwright-community/playwright-go"
)

// Explicit collection hosts; ordinary app APIs and authentication are untouched.
var standardTrackerDomains = []string{"google-analytics.com", "doubleclick.net", "api.segment.io", "api.segment.com", "cdn.segment.com", "clarity.ms", "bat.bing.com", "analytics.tiktok.com", "px.ads.linkedin.com", "mc.yandex.ru", "mc.yandex.com", "hm.baidu.com", "cnzz.com", "scorecardresearch.com", "quantserve.com", "quantcount.com", "omtrdc.net", "2o7.net", "demdex.net"}
var strictTrackerDomains = []string{"googletagmanager.com", "api.mixpanel.com", "api-js.mixpanel.com", "cdn.mxpnl.com", "api.amplitude.com", "api2.amplitude.com", "cdn.amplitude.com", "hotjar.com", "hotjar.io", "sessions.bugsnag.com", "notify.bugsnag.com", "browser-intake-datadoghq.com", "browser-intake-datadoghq.eu", "ingest.sentry.io", "ingest.us.sentry.io", "ingest.de.sentry.io", "nr-data.net", "js-agent.newrelic.com", "connect.facebook.net", "ads-twitter.com", "analytics.twitter.com", "googleadservices.com", "googlesyndication.com", "adservice.google.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com", "amazon-adsystem.com"}

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
	"clarity.ms":                   {"clarity.ms"},
	"bat.bing.com":                 {"bing.com"},
	"analytics.tiktok.com":         {"tiktok.com"},
	"px.ads.linkedin.com":          {"linkedin.com"},
	"mc.yandex.ru":                 {"yandex.ru"},
	"mc.yandex.com":                {"yandex.com"},
	"hm.baidu.com":                 {"baidu.com"},
	"cnzz.com":                     {"cnzz.com", "umeng.com"},
	"scorecardresearch.com":        {"scorecardresearch.com"},
	"quantserve.com":               {"quantserve.com", "quantcast.com"},
	"quantcount.com":               {"quantcount.com", "quantcast.com"},
	"omtrdc.net":                   {"omtrdc.net", "adobe.com"},
	"2o7.net":                      {"2o7.net", "adobe.com"},
	"demdex.net":                   {"demdex.net", "adobe.com"},
	"cdn.mxpnl.com":                {"mixpanel.com", "mxpnl.com"},
	"nr-data.net":                  {"nr-data.net", "newrelic.com"},
	"js-agent.newrelic.com":        {"newrelic.com"},
	"connect.facebook.net":         {"facebook.com", "facebook.net"},
	"ads-twitter.com":              {"twitter.com", "x.com"},
	"analytics.twitter.com":        {"twitter.com", "x.com"},
	"googleadservices.com":         {"googleadservices.com"},
	"googlesyndication.com":        {"googlesyndication.com"},
	"adservice.google.com":         {"google.com"},
	"criteo.com":                   {"criteo.com"},
	"criteo.net":                   {"criteo.com", "criteo.net"},
	"taboola.com":                  {"taboola.com"},
	"outbrain.com":                 {"outbrain.com"},
	"adnxs.com":                    {"adnxs.com", "xandr.com"},
	"amazon-adsystem.com":          {"amazon-adsystem.com"},
}

type PrivacyState struct {
	Mode              string
	Geolocation       *profile.Geolocation
	BlockedRequests   atomic.Uint64
	BlockedWebSockets atomic.Uint64
	WebSocketRouting  string
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
	snapshot := map[string]any{"mode": s.Mode, "blockedRequests": s.BlockedRequests.Load(), "geolocation": geo, "geolocationPolicy": geoPolicy, "trackerScope": "third-party-http-websocket", "websocketScope": "page-and-frame", "blockedWebSockets": s.BlockedWebSockets.Load(), "websocketRouting": s.WebSocketRouting, "enabled": s.Mode != "off", "serviceWorkers": serviceWorkers}
	if (s.WebSocketRouting == "constructor" || s.WebSocketRouting == "webextension") && s.Mode != "off" {
		snapshot["blockedWebSockets"] = nil
		snapshot["websocketTrackerRules"] = "built-in-hosts"
	}
	if label := trackerListLabel(); label != "" && s.Mode != "off" {
		snapshot["trackerList"] = label
	}
	return snapshot
}

func checkedPrivacyURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Hostname() == "" {
		return nil
	}
	return parsed
}
func matchingHost(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}
func shouldBlockTracker(raw, firstParty, mode string) bool {
	return blockTrackerRequest(raw, firstParty, mode, kindDefault)
}

// builtinTrackerDomain is the tier entry a host belongs to, if any.
func builtinTrackerDomain(host, mode string) string {
	for _, domain := range standardTrackerDomains {
		if matchingHost(host, domain) {
			return domain
		}
	}
	if mode == "strict" {
		for _, domain := range strictTrackerDomains {
			if matchingHost(host, domain) {
				return domain
			}
		}
	}
	return ""
}

// builtinTrackerExempt keeps a service's own first-party analytics and sibling
// APIs working on its own site.
func builtinTrackerExempt(host, firstHost, trackerDomain string) bool {
	if firstHost == "" {
		return false
	}
	if matchingHost(host, firstHost) || matchingHost(firstHost, host) {
		return true
	}
	for _, root := range trackerServiceRoots[trackerDomain] {
		if matchingHost(firstHost, root) {
			return true
		}
	}
	return false
}

// blockTrackerRequest decides one request. Envara's own tiers decide first; a
// host they name is blocked or deliberately allowed. Otherwise the bundled
// EasyPrivacy rules apply to third-party requests, except that standard never
// blocks what the strict tier holds back as able to break sites, and a page
// the user navigates to is never blocked.
func blockTrackerRequest(raw, firstParty, mode string, kind uint16) bool {
	if mode == "off" {
		return false
	}
	target := checkedPrivacyURL(raw)
	if target == nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	firstHost := ""
	if first := checkedPrivacyURL(firstParty); first != nil {
		firstHost = strings.TrimSuffix(strings.ToLower(first.Hostname()), ".")
	}
	if domain := builtinTrackerDomain(host, mode); domain != "" {
		return !builtinTrackerExempt(host, firstHost, domain)
	}
	if mode != "strict" {
		for _, domain := range strictTrackerDomains {
			if matchingHost(host, domain) {
				return false
			}
		}
	}
	if kind == kindDocument || sameSite(host, firstHost) {
		return false
	}
	return loadedEasyPrivacy().blocks(host, urlTail(target), kind, firstHost)
}

// requestKind is the filter-list kind of a Playwright request.
// Loopback stays on this Mac instead of going to the remote proxy, which
// cannot reach it: a sign-in that redirects to a local application's callback
// (http://127.0.0.1:PORT/...) otherwise ends in a proxy 502. Only a top-level
// navigation to loopback, and requests made by such a local page, may reach it;
// any other page's request to loopback is refused, so sites cannot probe local
// services.
const loopbackProxyBypass = "127.0.0.1,localhost,[::1]"

func loopbackHost(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loopbackRequestRefused(request playwright.Request) (refused bool) {
	defer func() {
		if recover() != nil {
			refused = true
		}
	}()
	if !loopbackHost(request.URL()) {
		return false
	}
	frame := request.Frame()
	if frame == nil {
		return true
	}
	top := frame
	for top.ParentFrame() != nil {
		top = top.ParentFrame()
	}
	if request.IsNavigationRequest() && frame == top {
		return false
	}
	return !loopbackHost(top.URL())
}

func requestKind(request playwright.Request) (kind uint16) {
	defer func() {
		if recover() != nil {
			kind = kindOther
		}
	}()
	subframe := false
	if frame := request.Frame(); frame != nil && frame.ParentFrame() != nil {
		subframe = true
	}
	return requestKindFor(request.ResourceType(), subframe)
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

// WebSocket routes have no Request/frame accessor. Page routes retain the top
// party; the context fallback never borrows another tab's first-party exception.
// Only page/frame WebSockets are covered by this supported Playwright API.
func privacyWebSocketHandler(state *PrivacyState, page playwright.Page) func(playwright.WebSocketRoute) {
	return func(socket playwright.WebSocketRoute) {
		firstParty := ""
		if page != nil {
			firstParty = page.URL()
		}
		refused := loopbackHost(socket.URL()) && !loopbackHost(firstParty)
		blocked := blockTrackerRequest(socket.URL(), firstParty, state.Mode, kindWebsocket)
		if refused || blocked {
			if blocked {
				state.BlockedRequests.Add(1)
				state.BlockedWebSockets.Add(1)
			}
			socket.Close(playwright.WebSocketRouteCloseOptions{Code: playwright.Int(1008), Reason: playwright.String("Blocked by privacy policy")})
			return
		}
		if _, err := socket.ConnectToServer(); err != nil {
			socket.Close(playwright.WebSocketRouteCloseOptions{Code: playwright.Int(1011), Reason: playwright.String("Connection unavailable")})
		}
	}
}

func installPrivacyWebSockets(ctx playwright.BrowserContext, state *PrivacyState) error {
	if err := ctx.RouteWebSocket("**/*", privacyWebSocketHandler(state, nil)); err != nil {
		return err
	}
	ctx.OnPage(func(page playwright.Page) {
		go func() {
			if page.RouteWebSocket("**/*", privacyWebSocketHandler(state, page)) != nil {
				page.Close()
			}
		}()
	})
	for _, page := range ctx.Pages() {
		if err := page.RouteWebSocket("**/*", privacyWebSocketHandler(state, page)); err != nil {
			return err
		}
	}
	return nil
}

func installBrowserPrivacy(ctx playwright.BrowserContext, p *profile.Profile, chromium bool, webSocketAddonReady ...bool) (*PrivacyState, error) {
	mode, err := browserPrivacyMode(p)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("privacy requires a browser context")
	}
	state := &PrivacyState{Mode: mode, WebSocketRouting: "playwright"}
	if p.RuntimeID == "cloakbrowser" {
		state.WebSocketRouting = "constructor"
	} else if p.RuntimeID == "camoufox" {
		if len(webSocketAddonReady) != 1 || !webSocketAddonReady[0] {
			return nil, fmt.Errorf("Camoufox WebSocket privacy add-on is not ready")
		}
		state.WebSocketRouting = "webextension"
	}
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
	if strings.HasPrefix(state.WebSocketRouting, "constructor") {
		if err := installConstructorPrivacyWebSockets(ctx, state); err != nil {
			return nil, err
		}
	} else if state.WebSocketRouting != "webextension" {
		if err := installPrivacyWebSockets(ctx, state); err != nil {
			return nil, err
		}
	}
	if err := ctx.Route("**/*", func(route playwright.Route) {
		request := route.Request()
		if loopbackRequestRefused(request) {
			route.Abort("blockedbyclient")
			return
		}
		if mode != "off" && blockTrackerRequest(request.URL(), requestFirstParty(request), mode, requestKind(request)) {
			if route.Abort("blockedbyclient") == nil {
				state.BlockedRequests.Add(1)
			}
		} else {
			route.Continue()
		}
	}); err != nil {
		return nil, err
	}
	return state, nil
}
