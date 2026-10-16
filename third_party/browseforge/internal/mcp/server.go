package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"browseforge/internal/browser"
	"browseforge/internal/groups"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
	"browseforge/internal/workflow"

	"github.com/mxschmitt/playwright-go"
)

// MCP Server — Model Context Protocol (2025-11-25 spec, Streamable HTTP transport)

type Server struct {
	store               *profile.Store
	groupStore          *groups.Store
	mgr                 *browser.Manager
	hcfg                humanize.Config
	sessionPool         *SessionPool
	workflow            *workflow.Engine
	token               string
	version             string
	publicBaseURL       string
	screenshotArtifacts *screenshotArtifactStore
	reqID               atomic.Int64
}

func NewServer(store *profile.Store, mgr *browser.Manager, hcfg humanize.Config, sessionPool *SessionPool, token, version string, groupStores ...*groups.Store) *Server {
	if version == "" {
		version = "dev"
	}
	var groupStore *groups.Store
	if len(groupStores) > 0 {
		groupStore = groupStores[0]
	}
	return &Server{store: store, groupStore: groupStore, mgr: mgr, hcfg: hcfg, sessionPool: sessionPool, token: token, version: version, screenshotArtifacts: newScreenshotArtifactStore()}
}

func (s *Server) SetWorkflowEngine(engine *workflow.Engine) {
	s.workflow = engine
}

func (s *Server) SetPublicBaseURL(raw string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		s.publicBaseURL = ""
		return
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Host != "" {
		parsed.Host = publicURLHost(parsed.Host)
		raw = strings.TrimRight(parsed.String(), "/")
	}
	s.publicBaseURL = raw
}

func (s *Server) publicBaseURLFromRequest(r *http.Request) string {
	if s.publicBaseURL != "" {
		return s.publicBaseURL
	}
	if r == nil || r.Host == "" {
		return ""
	}
	proto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	host = publicURLHost(host)
	if host == "" {
		return ""
	}
	return strings.TrimRight(proto+"://"+host, "/")
}

func firstHeaderValue(raw string) string {
	if i := strings.IndexByte(raw, ','); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func publicURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		host = strings.Trim(raw, "[]")
		port = ""
	}
	switch host {
	case "0.0.0.0", "::", "":
		host = "localhost"
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	// Bearer token auth (MCP spec: MUST return 401 + WWW-Authenticate for HTTP transport)
	if s.token != "" && !validBearerToken(r.Header.Get("Authorization"), s.token) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, newError(-32700, "Parse error"))
		return
	}

	var result any
	var mcpErr *mcpError

	switch req.Method {
	case "initialize":
		result = s.handleInitialize(req.Params)
	case "tools/list":
		result = s.handleToolsList()
	case "tools/call":
		result, mcpErr = s.handleToolsCall(req.Params, r)
	default:
		mcpErr = newError(-32601, "Method not found: "+req.Method)
	}

	writeJSONRPC(w, req.ID, mcpErr, result)
}

func validBearerToken(auth, token string) bool {
	const prefix = "Bearer "
	if token == "" || len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(token)) == 1
}

func (s *Server) handleInitialize(params json.RawMessage) any {
	return map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "BrowseForge", "version": s.version},
	}
}

func (s *Server) handleToolsList() any {
	return map[string]any{"tools": tools}
}

func (s *Server) handleToolsCall(params json.RawMessage, r *http.Request) (any, *mcpError) {
	var call struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, newError(-32700, "Invalid arguments: "+err.Error())
	}

	if call.Name == "" {
		return nil, newError(-32602, "Tool name is required")
	}

	switch call.Name {
	case "list_runtimes":
		return s.toolListRuntimes(call.Arguments)
	case "list_proxy_regions":
		return s.toolListProxyRegions(call.Arguments)
	case "list_profiles":
		return s.toolListProfiles(call.Arguments)
	case "create_profile":
		return s.toolCreateProfile(call.Arguments)
	case "delete_profile":
		return s.toolDeleteProfile(call.Arguments)
	case "update_profile":
		return s.toolUpdateProfile(call.Arguments)
	case "list_groups":
		return s.toolListGroups(call.Arguments)
	case "get_group":
		return s.toolGetGroup(call.Arguments)
	case "update_group_proxy":
		return s.toolUpdateGroupProxy(call.Arguments)
	case "clear_group_proxy":
		return s.toolClearGroupProxy(call.Arguments)
	case "delete_group":
		return s.toolDeleteGroup(call.Arguments)
	case "open_browser":
		return s.toolOpenBrowser(call.Arguments)
	case "close_browser":
		return s.toolCloseBrowser(call.Arguments)
	case "navigate":
		return s.toolNavigate(call.Arguments)
	case "click":
		return s.toolClick(call.Arguments)
	case "type_text":
		return s.toolTypeText(call.Arguments)
	case "screenshot":
		return s.toolScreenshot(call.Arguments, r)
	case "get_content":
		return s.toolGetContent(call.Arguments)
	case "evaluate":
		return s.toolEvaluate(call.Arguments)
	case "new_tab":
		return s.toolNewTab(call.Arguments)
	case "list_tabs":
		return s.toolListTabs(call.Arguments)
	case "switch_tab":
		return s.toolSwitchTab(call.Arguments)
	case "close_tab":
		return s.toolCloseTab(call.Arguments)
	case "web_search":
		return s.toolWebSearch(call.Arguments)
	case "web_explore":
		return s.toolWebExplore(call.Arguments)
	case "create_session":
		return s.toolCreateSession(call.Arguments)
	case "destroy_session":
		return s.toolDestroySession(call.Arguments)
	case "list_sessions":
		return s.toolListSessions(call.Arguments)
	case "gc_sessions":
		return s.toolGCSessions(call.Arguments)
	case "wait_for":
		return s.toolWaitFor(call.Arguments)
	case "get_page_state":
		return s.toolGetPageState(call.Arguments)
	case "get_cookies":
		return s.toolGetCookies(call.Arguments)
	case "set_cookies":
		return s.toolSetCookies(call.Arguments)
	case "run_workflow":
		return s.toolRunWorkflow(call.Arguments)
	case "form_fill":
		return s.toolFormFill(call.Arguments)
	case "select_option":
		return s.toolSelectOption(call.Arguments)
	case "check":
		return s.toolCheck(call.Arguments)
	case "press_key":
		return s.toolPressKey(call.Arguments)
	case "list_downloads":
		return s.toolListDownloads(call.Arguments)
	case "delete_download":
		return s.toolDeleteDownload(call.Arguments)
	case "read_download":
		return s.toolReadDownload(call.Arguments)
	case "web_extract":
		return s.toolWebExtract(call.Arguments)
	case "doctor_profile":
		return s.toolDoctorProfile(call.Arguments)
	default:
		return nil, newError(-32602, "Unknown tool: "+call.Name)
	}
}

// --- Tool implementations ---

func (s *Server) toolListRuntimes(args map[string]any) (any, *mcpError) {
	return textResult(mustJSON(s.mgr.RuntimeRegistry().List())), nil
}
func (s *Server) toolListProxyRegions(args map[string]any) (any, *mcpError) {
	presets := browser.BrowseForgeProxyRegionPresets()
	regions := make([]map[string]string, 0, len(presets))
	for _, preset := range presets {
		regions = append(regions, map[string]string{"value": preset.Value, "label": preset.Label})
	}
	res := textResult(mustJSON(regions))
	res["regions"] = regions
	res["total"] = len(regions)
	return res, nil
}

func (s *Server) toolListProfiles(args map[string]any) (any, *mcpError) {
	group, _ := args["group"].(string)
	tag, _ := args["tag"].(string)
	profiles := s.store.List(group, tag)
	var items []map[string]string
	for _, p := range profiles {
		items = append(items, map[string]string{"id": p.ID, "name": p.Name, "runtime_id": p.RuntimeID, "group": p.Group})
	}
	return textResult(fmt.Sprintf("Found %d profiles:\n%s", len(items), mustJSON(items))), nil
}

func (s *Server) toolCreateProfile(args map[string]any) (any, *mcpError) {
	name, _ := args["name"].(string)
	if name == "" {
		return nil, newError(-32602, "name is required")
	}
	if _, ok := args["engine"]; ok {
		return nil, newError(-32602, "engine was removed in v2; use runtime_id")
	}
	runtimeID, _ := args["runtime_id"].(string)
	group, _ := args["group"].(string)

	p := &profile.Profile{Name: name, RuntimeID: runtimeID, Group: group}

	if proxyRaw, ok := args["proxy"]; ok && proxyRaw != nil {
		proxyMap, ok := proxyRaw.(map[string]any)
		if !ok {
			return nil, newError(-32602, "proxy must be an object")
		}
		pc, err := parseProxyConfig(proxyMap)
		if err != nil {
			return nil, newError(-32602, err.Error())
		}
		p.Proxy = pc
	}

	desc, err := s.mgr.RuntimeRegistry().ApplyProfileDefaults(p)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	if !desc.Enabled {
		return nil, newError(-32602, fmt.Sprintf("runtime %q is disabled", desc.ID))
	}
	if err := s.validateBrowseForgeProfileProxy(desc.ID, p); err != nil {
		return nil, newError(-32602, err.Error())
	}
	if err := s.store.Create(p); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Created profile %s (%s, runtime: %s)", p.ID, p.Name, p.RuntimeID)), nil
}

func (s *Server) toolDeleteProfile(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	if s.sessionPool != nil {
		s.sessionPool.DestroyProfileSessions(id)
	}
	if err := s.closeProfileBrowser(id, true); err != nil {
		return nil, err
	}
	if err := s.store.Delete(id); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult("Deleted profile " + id), nil
}

func (s *Server) toolUpdateProfile(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	updates := map[string]any{}
	if v, ok := args["name"]; ok {
		updates["name"] = v
	}
	if v, ok := args["group"]; ok {
		updates["group"] = v
	}
	if v, ok := args["runtime_id"]; ok {
		updates["runtime_id"] = v
	}
	if _, ok := args["engine"]; ok {
		return nil, newError(-32602, "engine was removed in v2; use runtime_id")
	}
	if v, ok := args["proxy"]; ok {
		if v == nil {
			updates["proxy"] = nil
		} else {
			proxyMap, ok := v.(map[string]any)
			if !ok {
				return nil, newError(-32602, "proxy must be an object")
			}
			proxyCfg, err := parseProxyConfig(proxyMap)
			if err != nil {
				return nil, newError(-32602, err.Error())
			}
			updates["proxy"] = proxyCfg
		}
	}
	if _, runtimeChanged := updates["runtime_id"]; runtimeChanged || hasProxyUpdate(args) || hasGroupUpdate(args) {
		current, err := s.store.Get(id)
		if err != nil {
			return nil, newError(-32000, err.Error())
		}
		draft := *current
		if runtimeChanged {
			v, ok := updates["runtime_id"].(string)
			if !ok {
				return nil, newError(-32602, "runtime_id must be a string")
			}
			draft.RuntimeID = v
		}
		if _, groupChanged := updates["group"]; groupChanged {
			v, ok := updates["group"].(string)
			if !ok {
				return nil, newError(-32602, "group must be a string")
			}
			draft.Group = v
		}
		if proxyUpdate, ok := updates["proxy"]; ok {
			if proxyUpdate == nil {
				draft.Proxy = nil
			} else {
				draft.Proxy = proxyUpdate.(*profile.ProxyConfig)
			}
		}
		desc, err := s.mgr.RuntimeRegistry().ApplyProfileDefaults(&draft)
		if err != nil {
			return nil, newError(-32602, err.Error())
		}
		if runtimeChanged && !desc.Enabled {
			return nil, newError(-32602, fmt.Sprintf("runtime %q is disabled", desc.ID))
		}
		if err := s.validateBrowseForgeProfileProxy(desc.ID, &draft); err != nil {
			return nil, newError(-32602, err.Error())
		}
		updates["runtime_id"] = draft.RuntimeID
	}
	p, err := s.store.Update(id, updates)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Updated profile %s (%s)", p.ID, p.Name)), nil
}

func (s *Server) toolListGroups(args map[string]any) (any, *mcpError) {
	if s.groupStore == nil {
		return nil, newError(-32000, "group store is not available")
	}
	items := s.groupStore.List()
	groups := make([]map[string]any, 0, len(items))
	for _, g := range items {
		groups = append(groups, s.groupResponse(g))
	}
	res := textResult(mustJSON(groups))
	res["groups"] = groups
	res["total"] = len(groups)
	return res, nil
}

func (s *Server) toolGetGroup(args map[string]any) (any, *mcpError) {
	if s.groupStore == nil {
		return nil, newError(-32000, "group store is not available")
	}
	name, _ := args["group"].(string)
	if name == "" {
		return nil, newError(-32602, "group is required")
	}
	g, ok := s.groupStore.Get(name)
	if !ok {
		return nil, newError(-32000, "group not found: "+name)
	}
	res := textResult(mustJSON(g))
	for k, v := range s.groupResponse(g) {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolUpdateGroupProxy(args map[string]any) (any, *mcpError) {
	if s.groupStore == nil {
		return nil, newError(-32000, "group store is not available")
	}
	name, _ := args["group"].(string)
	if name == "" {
		return nil, newError(-32602, "group is required")
	}
	proxyArg, ok := args["proxy"].(map[string]any)
	if !ok {
		return nil, newError(-32602, "proxy object is required")
	}
	proxyCfg, err := parseProxyConfig(proxyArg)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	mode, _ := args["proxy_mode"].(string)
	if err := s.validateGroupProxyRegion(name, proxyCfg); err != nil {
		return nil, newError(-32602, err.Error())
	}
	g, err := s.groupStore.Upsert(name, proxyCfg, mode)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	active := s.activeBrowserSessionsForGroup(g.Name)
	msg := fmt.Sprintf("Updated group proxy for %s (mode: %s).", g.Name, g.ProxyMode)
	if active > 0 {
		msg += " Close and reopen active profile browsers in this group for the change to take effect."
	}
	res := textResult(msg)
	for k, v := range s.groupResponse(g) {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolClearGroupProxy(args map[string]any) (any, *mcpError) {
	if s.groupStore == nil {
		return nil, newError(-32000, "group store is not available")
	}
	name, _ := args["group"].(string)
	if name == "" {
		return nil, newError(-32602, "group is required")
	}
	g, err := s.groupStore.ClearProxy(name)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	active := s.activeBrowserSessionsForGroup(g.Name)
	msg := fmt.Sprintf("Cleared group proxy for %s.", g.Name)
	if active > 0 {
		msg += " Close and reopen active profile browsers in this group for the change to take effect."
	}
	res := textResult(msg)
	for k, v := range s.groupResponse(g) {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolDeleteGroup(args map[string]any) (any, *mcpError) {
	if s.groupStore == nil {
		return nil, newError(-32000, "group store is not available")
	}
	name, _ := args["group"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, newError(-32602, "group is required")
	}
	active := s.activeBrowserSessionsForGroup(name)
	if active > 0 {
		return nil, activeGroupDeleteError(name, active)
	}
	ungrouped := 0
	if s.store != nil {
		for _, p := range s.store.List("", "") {
			if strings.TrimSpace(p.Group) != name {
				continue
			}
			if _, err := s.store.Update(p.ID, map[string]any{"group": ""}); err != nil {
				return nil, newError(-32000, err.Error())
			}
			ungrouped++
		}
	}
	if _, err := s.groupStore.ClearProxy(name); err != nil {
		return nil, newError(-32602, err.Error())
	}
	res := textResult(fmt.Sprintf("Deleted group %s. Ungrouped %d profile(s); profiles were not deleted.", name, ungrouped))
	res["name"] = name
	res["profiles_ungrouped"] = ungrouped
	res["proxy_cleared"] = true
	res["active_sessions"] = 0
	res["restart_required"] = false
	return res, nil
}

func activeGroupDeleteError(name string, active int) *mcpError {
	return newErrorData(-32000, fmt.Sprintf("group %s has %d active browser session(s); close them before deleting the group", name, active), map[string]any{
		"code":             "GROUP_HAS_ACTIVE_SESSIONS",
		"group":            name,
		"active_sessions":  active,
		"restart_required": true,
	})
}

func (s *Server) groupResponse(g *groups.Group) map[string]any {
	active := s.activeBrowserSessionsForGroup(g.Name)
	return map[string]any{
		"group":            g,
		"name":             g.Name,
		"proxy_mode":       g.ProxyMode,
		"proxy":            g.Proxy,
		"created_at":       g.CreatedAt,
		"updated_at":       g.UpdatedAt,
		"active_sessions":  active,
		"restart_required": active > 0,
	}
}

func (s *Server) activeBrowserSessionsForGroup(groupName string) int {
	groupName = strings.TrimSpace(groupName)
	if s.mgr == nil || s.store == nil || groupName == "" {
		return 0
	}
	count := 0
	for _, sess := range s.mgr.ListSessions() {
		p, err := s.store.Get(sess.ProfileID)
		if err == nil && strings.TrimSpace(p.Group) == groupName {
			count++
		}
	}
	return count
}

func parseProxyConfig(raw map[string]any) (*profile.ProxyConfig, error) {
	proxyType, _ := raw["type"].(string)
	host, _ := raw["host"].(string)
	port := 0
	switch v := raw["port"].(type) {
	case float64:
		if v != float64(int(v)) {
			return nil, fmt.Errorf("proxy.port must be an integer")
		}
		port = int(v)
	case int:
		port = v
	}
	username, _ := raw["username"].(string)
	password, _ := raw["password"].(string)
	region, _ := raw["region"].(string)
	proxyType = strings.TrimSpace(strings.ToLower(proxyType))
	host = strings.TrimSpace(host)
	region = strings.TrimSpace(region)
	if proxyType == "" {
		return nil, fmt.Errorf("proxy.type is required")
	}
	if proxyType != "socks5" && proxyType != "http" {
		return nil, fmt.Errorf("unsupported proxy type %q", proxyType)
	}
	if host == "" {
		return nil, fmt.Errorf("proxy.host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("proxy.port must be between 1 and 65535")
	}
	return &profile.ProxyConfig{Type: proxyType, Host: host, Port: port, Username: username, Password: password, Region: region}, nil
}

func hasProxyUpdate(args map[string]any) bool {
	_, ok := args["proxy"]
	return ok
}

func hasGroupUpdate(args map[string]any) bool {
	_, ok := args["group"]
	return ok
}

func validateBrowseForgeProxyRegion(runtimeID bfruntime.ID, proxy *profile.ProxyConfig) error {
	if runtimeID != bfruntime.BrowseForgeChromium || proxy == nil {
		return nil
	}
	normalized, err := browser.NormalizeBrowseForgeProxyRegion(proxy.Region)
	if err != nil {
		return err
	}
	if normalized == "" {
		return fmt.Errorf("browseforge-chromium proxy_region is required when a proxy is configured; use a redacted geographic label such as %s", browser.BrowseForgeProxyRegionExamples)
	}
	proxy.Region = normalized
	return nil
}

func (s *Server) validateBrowseForgeProfileProxy(runtimeID bfruntime.ID, p *profile.Profile) error {
	if runtimeID != bfruntime.BrowseForgeChromium || p == nil {
		return nil
	}
	if p.Proxy != nil {
		if err := validateBrowseForgeProxyRegion(runtimeID, p.Proxy); err != nil {
			return err
		}
	}
	effective := groups.EffectiveProxy{Source: "none"}
	if s.groupStore != nil {
		effective = s.groupStore.EffectiveProxy(p)
	} else if p.Proxy != nil && strings.TrimSpace(p.Proxy.Host) != "" {
		effective = groups.EffectiveProxy{Proxy: p.Proxy, Source: "profile"}
	}
	if effective.Proxy == nil || effective.Source == "profile" {
		return nil
	}
	proxy := *effective.Proxy
	return validateBrowseForgeProxyRegion(runtimeID, &proxy)
}

func (s *Server) validateGroupProxyRegion(groupName string, proxy *profile.ProxyConfig) error {
	if proxy == nil || s.store == nil || s.mgr == nil {
		return nil
	}
	for _, p := range s.store.List(groupName, "") {
		draft := *p
		desc, err := s.mgr.RuntimeRegistry().ApplyProfileDefaults(&draft)
		if err == nil && desc.ID == bfruntime.BrowseForgeChromium {
			return validateBrowseForgeProxyRegion(desc.ID, proxy)
		}
	}
	return nil
}

func (s *Server) toolOpenBrowser(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	p, err := s.store.Get(id)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	sess, err := s.mgr.LaunchSession(p)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Opened browser for %s (session: %s, runtime: %s)", p.Name, sess.ID, sess.RuntimeID)), nil
}

func (s *Server) closeProfileBrowser(profileID string, ignoreNotFound bool) *mcpError {
	if s.mgr == nil {
		return nil
	}
	sessID := "sess_" + profileID
	if err := s.mgr.CloseSession(sessID); err != nil {
		if ignoreNotFound && strings.HasPrefix(err.Error(), "session not found: ") {
			return nil
		}
		return newError(-32000, err.Error())
	}
	return nil
}

func (s *Server) toolCloseBrowser(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	if s.sessionPool != nil {
		s.sessionPool.DestroyProfileSessions(id)
	}
	if err := s.closeProfileBrowser(id, false); err != nil {
		return nil, err
	}
	return textResult("Closed browser for " + id), nil
}

func (s *Server) toolNavigate(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	url, _ := args["url"].(string)
	page, err := s.mgr.SessionPage("sess_" + id)
	if err != nil {
		return nil, newError(-32000, "no active session for "+id)
	}
	opts := playwright.PageGotoOptions{}
	if wu, ok := args["wait_until"].(string); ok && wu != "" {
		wus := playwright.WaitUntilState(wu)
		opts.WaitUntil = &wus
	}
	if _, err := page.Goto(url, opts); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Navigated to %s", url)), nil
}

func (s *Server) toolClick(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	selector, _ := args["selector"].(string)
	page, err := s.mgr.SessionPage("sess_" + id)
	if err != nil {
		return nil, newError(-32000, "no active session")
	}
	if t, ok := args["timeout"].(float64); ok && t > 0 {
		if err := page.Locator(selector).WaitFor(playwright.LocatorWaitForOptions{Timeout: playwright.Float(t)}); err != nil {
			return nil, newError(-32000, err.Error())
		}
	}
	if err := humanize.Click(page, selector, s.hcfg); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult("Clicked " + selector), nil
}

func (s *Server) toolTypeText(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	selector, _ := args["selector"].(string)
	text, _ := args["text"].(string)
	page, err := s.mgr.SessionPage("sess_" + id)
	if err != nil {
		return nil, newError(-32000, "no active session")
	}
	if clear, _ := args["clear"].(bool); clear {
		page.Locator(selector).Clear()
	}
	if err := humanize.Type(page, selector, text, s.hcfg); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult("Typed text into " + selector), nil
}

func (s *Server) toolScreenshot(args map[string]any, r *http.Request) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	page, err := s.mgr.SessionPage("sess_" + id)
	if err != nil {
		return nil, newError(-32000, "no active session")
	}

	quality := 40
	if q, ok := args["quality"].(float64); ok && q > 0 {
		quality = int(q)
	}
	fullPage := false
	if fp, ok := args["full_page"].(bool); ok {
		fullPage = fp
	}

	format := "jpeg"
	if raw, _ := args["format"].(string); raw != "" {
		format = strings.ToLower(raw)
	}
	if format != "jpeg" && format != "jpg" && format != "png" {
		return nil, newError(-32602, "format must be jpeg or png")
	}
	mimeType := "image/jpeg"
	ext := ".jpg"
	screenshotType := playwright.ScreenshotTypeJpeg
	if format == "png" {
		mimeType = "image/png"
		ext = ".png"
		screenshotType = playwright.ScreenshotTypePng
	}
	opts := playwright.PageScreenshotOptions{
		Type:     screenshotType,
		FullPage: playwright.Bool(fullPage),
	}
	if screenshotType == playwright.ScreenshotTypeJpeg {
		opts.Quality = playwright.Int(quality)
	}
	data, err := page.Screenshot(opts)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	return s.finishScreenshotResult(args, id, data, mimeType, ext, s.publicBaseURLFromRequest(r))
}

func (s *Server) toolGetContent(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	selector, _ := args["selector"].(string)
	page, pageErr := s.mgr.SessionPage("sess_" + id)
	if pageErr != nil {
		return nil, newError(-32000, "no active session")
	}
	var text string
	var err error
	if selector != "" {
		text, err = page.Locator(selector).TextContent()
	} else {
		text, err = page.Content()
	}
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(text), nil
}

func (s *Server) toolEvaluate(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	script, _ := args["script"].(string)
	page, err := s.mgr.SessionPage("sess_" + id)
	if err != nil {
		return nil, newError(-32000, "no active session")
	}
	result, err := page.Evaluate(script)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("%v", result)), nil
}

func (s *Server) toolNewTab(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	sess, ok := s.mgr.GetSession("sess_" + id)
	if !ok {
		return nil, newError(-32000, "no active session")
	}
	page, err := sess.Context.NewPage()
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	if err := s.mgr.SetSessionPage(sess.ID, page); err != nil {
		return nil, newError(-32000, err.Error())
	}
	url, _ := args["url"].(string)
	if url != "" {
		if _, err := page.Goto(url, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateLoad,
			Timeout:   playwright.Float(30000),
		}); err != nil {
			return nil, newError(-32000, "navigate to new tab: "+err.Error())
		}
	}
	return textResult(fmt.Sprintf("New tab opened (total: %d)", len(sess.Context.Pages()))), nil
}

func (s *Server) toolListTabs(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	sess, ok := s.mgr.GetSession("sess_" + id)
	if !ok {
		return nil, newError(-32000, "no active session")
	}
	pages := sess.Context.Pages()
	activePage, err := s.mgr.SessionPage(sess.ID)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	var tabs []map[string]any
	for i, p := range pages {
		active := p == activePage
		tabs = append(tabs, map[string]any{"index": i, "url": p.URL(), "active": active})
	}
	return textResult(mustJSON(tabs)), nil
}

func checkedTabIndex(args map[string]any) (int, *mcpError) {
	value, ok := args["index"].(float64)
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || math.Trunc(value) != value || value >= float64(^uint(0)>>1) {
		return 0, newError(-32602, "index must be a non-negative integer")
	}
	return int(value), nil
}

func (s *Server) toolSwitchTab(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	index, indexErr := checkedTabIndex(args)
	if indexErr != nil {
		return nil, indexErr
	}
	sess, ok := s.mgr.GetSession("sess_" + id)
	if !ok {
		return nil, newError(-32000, "no active session")
	}
	pages := sess.Context.Pages()
	if index < 0 || index >= len(pages) {
		return nil, newError(-32000, fmt.Sprintf("tab index %d out of range (0-%d)", index, len(pages)-1))
	}
	if err := s.mgr.SetSessionPage(sess.ID, pages[index]); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Switched to tab %d: %s", index, pages[index].URL())), nil
}

func (s *Server) toolCloseTab(args map[string]any) (any, *mcpError) {
	id, _ := args["profile_id"].(string)
	index, indexErr := checkedTabIndex(args)
	if indexErr != nil {
		return nil, indexErr
	}
	sess, ok := s.mgr.GetSession("sess_" + id)
	if !ok {
		return nil, newError(-32000, "no active session")
	}
	pages := sess.Context.Pages()
	if index < 0 || index >= len(pages) {
		return nil, newError(-32000, fmt.Sprintf("tab index %d out of range (0-%d)", index, len(pages)-1))
	}
	if err := pages[index].Close(); err != nil {
		return nil, newError(-32000, err.Error())
	}
	return textResult(fmt.Sprintf("Closed tab %d (remaining: %d)", index, len(sess.Context.Pages()))), nil
}
