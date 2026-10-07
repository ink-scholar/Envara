package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"browseforge/internal/humanize"
	"browseforge/internal/profile"
	"browseforge/internal/workflow"

	"github.com/mxschmitt/playwright-go"
	"gopkg.in/yaml.v3"
)

type pageTarget struct {
	page             playwright.Page
	context          playwright.BrowserContext
	profileID        string
	sessionID        string
	browserSessionID string
	profile          *profile.Profile
	tabIndex         int
	tabCount         int
}

func (s *Server) resolvePageTarget(args map[string]any) (*pageTarget, *mcpError) {
	profileID, _ := args["profile_id"].(string)
	sessionID, _ := args["session_id"].(string)

	if sessionID != "" {
		if s.sessionPool == nil {
			return nil, newError(-32000, "web sessions are not available (session pool not initialized)")
		}
		webSession, err := s.sessionPool.GetSession(sessionID)
		if err != nil {
			return nil, newError(-32000, err.Error())
		}
		target := &pageTarget{
			page:      webSession.Page,
			profileID: webSession.ProfileID,
			sessionID: webSession.ID,
		}
		if p, err := s.store.Get(webSession.ProfileID); err == nil {
			target.profile = p
		}
		if browserSession, ok := s.mgr.GetSession("sess_" + webSession.ProfileID); ok {
			target.context = browserSession.Context
			target.browserSessionID = browserSession.ID
			pages := browserSession.Context.Pages()
			target.tabCount = len(pages)
			target.tabIndex = -1
			for i, page := range pages {
				if page == webSession.Page {
					target.tabIndex = i
					break
				}
			}
		}
		if target.page == nil {
			return nil, newError(-32000, "session page is closed: "+sessionID)
		}
		return target, nil
	}

	if profileID == "" {
		return nil, newError(-32602, "profile_id or session_id is required")
	}
	browserSession, ok := s.mgr.GetSession("sess_" + profileID)
	if !ok {
		return nil, newError(-32000, "no active session for "+profileID)
	}
	target := &pageTarget{
		page:             browserSession.Page,
		context:          browserSession.Context,
		profileID:        profileID,
		browserSessionID: browserSession.ID,
	}
	if p, err := s.store.Get(profileID); err == nil {
		target.profile = p
	}
	pages := browserSession.Context.Pages()
	target.tabCount = len(pages)
	target.tabIndex = -1
	for i, page := range pages {
		if page == browserSession.Page {
			target.tabIndex = i
			break
		}
	}
	if target.page == nil {
		return nil, newError(-32000, "active page is not available for "+profileID)
	}
	return target, nil
}

func (s *Server) resolveProfile(args map[string]any) (*profile.Profile, string, *mcpError) {
	profileID, _ := args["profile_id"].(string)
	sessionID, _ := args["session_id"].(string)
	if profileID == "" && sessionID != "" {
		if s.sessionPool == nil {
			return nil, "", newError(-32000, "web sessions are not available (session pool not initialized)")
		}
		webSession, err := s.sessionPool.GetSession(sessionID)
		if err != nil {
			return nil, "", newError(-32000, err.Error())
		}
		profileID = webSession.ProfileID
	}
	if profileID == "" {
		return nil, "", newError(-32602, "profile_id or session_id is required")
	}
	p, err := s.store.Get(profileID)
	if err != nil {
		return nil, "", newError(-32000, err.Error())
	}
	return p, profileID, nil
}

func (s *Server) toolWaitFor(args map[string]any) (any, *mcpError) {
	selector, _ := args["selector"].(string)
	if selector == "" {
		return nil, newError(-32602, "selector is required")
	}
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}

	state := "visible"
	if raw, _ := args["state"].(string); raw != "" {
		state = raw
	}
	if !slices.Contains([]string{"attached", "visible", "hidden", "detached"}, state) {
		return nil, newError(-32602, "state must be one of attached, visible, hidden, detached")
	}

	waitState := playwright.WaitForSelectorState(state)
	opts := playwright.PageWaitForSelectorOptions{State: &waitState}
	timeout := 30000.0
	if t, ok := args["timeout"].(float64); ok && t >= 0 {
		timeout = t
	}
	opts.Timeout = playwright.Float(timeout)

	start := time.Now()
	_, err := target.page.WaitForSelector(selector, opts)
	elapsed := time.Since(start)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}

	payload := map[string]any{
		"matched":    true,
		"selector":   selector,
		"state":      state,
		"profile_id": target.profileID,
		"url":        target.page.URL(),
		"title":      pageTitle(target.page),
		"elapsed_ms": elapsed.Milliseconds(),
	}
	if target.sessionID != "" {
		payload["session_id"] = target.sessionID
	}
	res := textResult(mustJSON(payload))
	for k, v := range payload {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolGetPageState(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	maxText := 1000
	if raw, ok := args["text_max_length"].(float64); ok && raw > 0 {
		maxText = int(raw)
	}

	data, err := target.page.Evaluate(`() => {
		const active = document.activeElement;
		const bodyText = document.body && document.body.innerText ? document.body.innerText.replace(/\s+/g, ' ').trim() : '';
		return {
			url: window.location.href,
			title: document.title || '',
			text: bodyText,
			active_element: active ? {
				tag: active.tagName ? active.tagName.toLowerCase() : '',
				id: active.id || '',
				name: active.getAttribute('name') || '',
				type: active.getAttribute('type') || '',
				placeholder: active.getAttribute('placeholder') || '',
				text: (active.innerText || active.value || '').toString().slice(0, 200)
			} : null
		};
	}`)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	raw, _ := data.(map[string]any)
	payload := map[string]any{
		"profile_id":         target.profileID,
		"browser_session_id": target.browserSessionID,
		"url":                asString(raw["url"]),
		"title":              asString(raw["title"]),
		"text":               truncateString(asString(raw["text"]), maxText),
		"active_element":     raw["active_element"],
		"tab_index":          target.tabIndex,
		"tab_count":          target.tabCount,
	}
	if target.sessionID != "" {
		payload["session_id"] = target.sessionID
	}
	res := textResult(mustJSON(payload))
	for k, v := range payload {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolGetCookies(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	if target.context == nil {
		return nil, newError(-32000, "browser context is not available for "+target.profileID)
	}
	cookies, err := target.context.Cookies()
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	payload := map[string]any{"profile_id": target.profileID, "cookies": cookies, "total": len(cookies)}
	res := textResult(mustJSON(payload))
	res["profile_id"] = target.profileID
	res["cookies"] = cookies
	res["total"] = len(cookies)
	return res, nil
}

func (s *Server) toolSetCookies(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	if target.context == nil {
		return nil, newError(-32000, "browser context is not available for "+target.profileID)
	}
	rawCookies, ok := args["cookies"]
	if !ok {
		return nil, newError(-32602, "cookies is required")
	}
	var cookies []playwright.OptionalCookie
	raw, err := json.Marshal(rawCookies)
	if err != nil {
		return nil, newError(-32602, "encode cookies: "+err.Error())
	}
	if err := json.Unmarshal(raw, &cookies); err != nil {
		return nil, newError(-32602, "decode cookies: "+err.Error())
	}
	if len(cookies) == 0 {
		return nil, newError(-32602, "cookies must not be empty")
	}
	if err := target.context.AddCookies(cookies); err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult(fmt.Sprintf("Set %d cookies for %s", len(cookies), target.profileID))
	res["profile_id"] = target.profileID
	res["count"] = len(cookies)
	return res, nil
}

func (s *Server) toolRunWorkflow(args map[string]any) (any, *mcpError) {
	if s.workflow == nil {
		return nil, newError(-32000, "workflow engine is not available in this MCP mode")
	}
	wf, err := parseWorkflowArgs(args)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	results := s.workflow.Execute(wf)
	res := textResult(mustJSON(results))
	res["results"] = results
	res["workflow"] = wf.Name
	return res, nil
}

func parseWorkflowArgs(args map[string]any) (*workflow.Workflow, error) {
	var wf workflow.Workflow
	if rawYAML, _ := args["yaml"].(string); rawYAML != "" {
		if err := yaml.Unmarshal([]byte(rawYAML), &wf); err != nil {
			return nil, fmt.Errorf("decode workflow yaml: %w", err)
		}
	} else if rawWorkflow, ok := args["workflow"]; ok {
		data, err := json.Marshal(rawWorkflow)
		if err != nil {
			return nil, fmt.Errorf("encode workflow: %w", err)
		}
		if err := json.Unmarshal(data, &wf); err != nil {
			return nil, fmt.Errorf("decode workflow: %w", err)
		}
	} else {
		return nil, fmt.Errorf("workflow or yaml is required")
	}
	if wf.Name == "" {
		wf.Name = "mcp-workflow"
	}
	if len(wf.Steps) == 0 {
		return nil, fmt.Errorf("workflow must include at least one step")
	}
	return &wf, nil
}

func (s *Server) toolFormFill(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	fields, ok := args["fields"].([]any)
	if !ok || len(fields) == 0 {
		return nil, newError(-32602, "fields must be a non-empty array")
	}
	for i, field := range fields {
		f, ok := field.(map[string]any)
		if !ok {
			return nil, newError(-32602, fmt.Sprintf("fields[%d] must be an object", i))
		}
		selector, _ := f["selector"].(string)
		text, _ := f["text"].(string)
		if selector == "" {
			return nil, newError(-32602, fmt.Sprintf("fields[%d].selector is required", i))
		}
		if clear, _ := f["clear"].(bool); clear {
			if err := target.page.Locator(selector).Clear(); err != nil {
				return nil, newError(-32000, err.Error())
			}
		}
		if err := humanize.Type(target.page, selector, text, s.hcfg); err != nil {
			return nil, newError(-32000, err.Error())
		}
	}
	res := textResult(fmt.Sprintf("Filled %d fields", len(fields)))
	res["count"] = len(fields)
	res["profile_id"] = target.profileID
	return res, nil
}

func (s *Server) toolSelectOption(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	selector, _ := args["selector"].(string)
	if selector == "" {
		return nil, newError(-32602, "selector is required")
	}
	values := playwright.SelectOptionValues{
		Values:  stringSlicePointer(args["values"]),
		Labels:  stringSlicePointer(args["labels"]),
		Indexes: intSlicePointer(args["indexes"]),
	}
	if values == (playwright.SelectOptionValues{}) {
		return nil, newError(-32602, "one of values, labels, or indexes is required")
	}
	opts := playwright.PageSelectOptionOptions{}
	if t, ok := args["timeout"].(float64); ok && t >= 0 {
		opts.Timeout = playwright.Float(t)
	}
	selected, err := target.page.SelectOption(selector, values, opts)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult(mustJSON(map[string]any{"selector": selector, "selected": selected}))
	res["selector"] = selector
	res["selected"] = selected
	return res, nil
}

func (s *Server) toolCheck(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	selector, _ := args["selector"].(string)
	if selector == "" {
		return nil, newError(-32602, "selector is required")
	}
	checked := true
	if raw, ok := args["checked"].(bool); ok {
		checked = raw
	}
	checkOpts := playwright.PageCheckOptions{}
	uncheckOpts := playwright.PageUncheckOptions{}
	if t, ok := args["timeout"].(float64); ok && t >= 0 {
		checkOpts.Timeout = playwright.Float(t)
		uncheckOpts.Timeout = playwright.Float(t)
	}
	if checked {
		if err := target.page.Check(selector, checkOpts); err != nil {
			return nil, newError(-32000, err.Error())
		}
	} else {
		if err := target.page.Uncheck(selector, uncheckOpts); err != nil {
			return nil, newError(-32000, err.Error())
		}
	}
	res := textResult(fmt.Sprintf("Set %s checked=%t", selector, checked))
	res["selector"] = selector
	res["checked"] = checked
	return res, nil
}

func (s *Server) toolPressKey(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	key, _ := args["key"].(string)
	if key == "" {
		return nil, newError(-32602, "key is required")
	}
	opts := playwright.KeyboardPressOptions{}
	if delay, ok := args["delay"].(float64); ok && delay >= 0 {
		opts.Delay = playwright.Float(delay)
	}
	if err := target.page.Keyboard().Press(key, opts); err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult("Pressed " + key)
	res["key"] = key
	res["profile_id"] = target.profileID
	return res, nil
}

func (s *Server) toolListDownloads(args map[string]any) (any, *mcpError) {
	p, profileID, mcpErr := s.resolveProfile(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	limit := 50
	if raw, ok := args["limit"].(float64); ok && raw > 0 {
		limit = int(raw)
	}
	downloadsDir := filepath.Join(p.ProfileDir, "downloads")
	entries, err := os.ReadDir(downloadsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, newError(-32000, err.Error())
	}
	type item struct {
		Name    string    `json:"name"`
		Path    string    `json:"path"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"modified_at"`
	}
	items := []item{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		items = append(items, item{
			Name:    entry.Name(),
			Path:    filepath.Join(downloadsDir, entry.Name()),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	slices.SortFunc(items, func(a, b item) int {
		return b.ModTime.Compare(a.ModTime)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	payload := map[string]any{"profile_id": profileID, "downloads_dir": downloadsDir, "files": items, "total": len(items)}
	res := textResult(mustJSON(payload))
	res["profile_id"] = profileID
	res["downloads_dir"] = downloadsDir
	res["files"] = items
	res["total"] = len(items)
	return res, nil
}

func (s *Server) toolDeleteDownload(args map[string]any) (any, *mcpError) {
	p, profileID, mcpErr := s.resolveProfile(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	path, name, err := resolveDownloadPath(p.ProfileDir, args)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	if err := os.Remove(path); err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult("Deleted download " + name)
	res["profile_id"] = profileID
	res["name"] = name
	return res, nil
}

func (s *Server) toolReadDownload(args map[string]any) (any, *mcpError) {
	p, profileID, mcpErr := s.resolveProfile(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	path, name, err := resolveDownloadPath(p.ProfileDir, args)
	if err != nil {
		return nil, newError(-32602, err.Error())
	}
	maxBytes := int64(1024 * 1024)
	if raw, ok := args["max_bytes"].(float64); ok && raw > 0 {
		maxBytes = int64(raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	if info.Size() > maxBytes {
		return nil, newError(-32000, fmt.Sprintf("file is %d bytes, above max_bytes %d", info.Size(), maxBytes))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	mimeType := http.DetectContentType(data)
	payload := map[string]any{
		"profile_id": profileID,
		"name":       name,
		"path":       path,
		"size":       len(data),
		"mime_type":  mimeType,
	}
	if strings.HasPrefix(mimeType, "text/") || strings.Contains(mimeType, "json") || strings.Contains(mimeType, "xml") {
		payload["text"] = string(data)
	} else {
		payload["base64"] = base64.StdEncoding.EncodeToString(data)
	}
	res := textResult(mustJSON(payload))
	for k, v := range payload {
		res[k] = v
	}
	return res, nil
}

func (s *Server) toolWebExtract(args map[string]any) (any, *mcpError) {
	target, mcpErr := s.resolvePageTarget(args)
	if mcpErr != nil {
		return nil, mcpErr
	}
	schema, ok := args["schema"].(map[string]any)
	if !ok || len(schema) == 0 {
		return nil, newError(-32602, "schema must be a non-empty object")
	}
	maxText := 2000
	if raw, ok := args["text_max_length"].(float64); ok && raw > 0 {
		maxText = int(raw)
	}
	data, err := target.page.Evaluate(`(schema) => {
		const read = (spec) => {
			if (typeof spec === 'string') spec = { selector: spec, attr: 'text' };
			if (!spec || !spec.selector) return null;
			const many = !!spec.all;
			const attr = spec.attr || 'text';
			const nodes = Array.from(document.querySelectorAll(spec.selector));
			const pick = (node) => {
				if (!node) return '';
				if (attr === 'text') return (node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim();
				if (attr === 'html') return node.innerHTML || '';
				if (attr === 'href') return node.href || node.getAttribute('href') || '';
				if (attr === 'src') return node.src || node.getAttribute('src') || '';
				return node.getAttribute(attr) || '';
			};
			if (many) return nodes.map(pick).filter(Boolean);
			return pick(nodes[0]);
		};
		const out = {};
		const evidence = {};
		for (const [name, spec] of Object.entries(schema || {})) {
			out[name] = read(spec);
			if (spec && typeof spec === 'object' && spec.selector) evidence[name] = spec.selector;
		}
		return { url: window.location.href, title: document.title || '', data: out, evidence };
	}`, schema)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	raw, _ := data.(map[string]any)
	if extracted, ok := raw["data"].(map[string]any); ok {
		for k, v := range extracted {
			if text, ok := v.(string); ok {
				extracted[k] = truncateString(text, maxText)
			}
		}
	}
	res := textResult(mustJSON(raw))
	for k, v := range raw {
		res[k] = v
	}
	res["profile_id"] = target.profileID
	if target.sessionID != "" {
		res["session_id"] = target.sessionID
	}
	return res, nil
}

func (s *Server) toolDoctorProfile(args map[string]any) (any, *mcpError) {
	profileID, _ := args["profile_id"].(string)
	if profileID == "" {
		return nil, newError(-32602, "profile_id is required")
	}
	p, err := s.store.Get(profileID)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	browserSession, running := s.mgr.GetSession("sess_" + profileID)
	info := map[string]any{
		"profile_id":          p.ID,
		"name":                p.Name,
		"group":               p.Group,
		"runtime_id":          p.RuntimeID,
		"profile_dir":         p.ProfileDir,
		"downloads_dir":       filepath.Join(p.ProfileDir, "downloads"),
		"browser_running":     running,
		"web_sessions":        []SessionInfo{},
		"connect_url_present": false,
		"proxy_configured":    false,
		"proxy_source":        "none",
	}
	if s.groupStore != nil {
		effectiveProxy := s.groupStore.EffectiveProxy(p)
		info["proxy_configured"] = effectiveProxy.Proxy != nil
		info["proxy_source"] = effectiveProxy.Source
		info["proxy_mode"] = effectiveProxy.Mode
	} else if p.Proxy != nil {
		info["proxy_configured"] = p.Proxy.Host != ""
		if p.Proxy.Host != "" {
			info["proxy_source"] = "profile"
		}
	}
	if running {
		info["browser_session_id"] = browserSession.ID
		info["connect_url_present"] = browserSession.ConnectURL != ""
		info["active_url"] = browserSession.Page.URL()
		info["tab_count"] = len(browserSession.Context.Pages())
	}
	if s.sessionPool != nil {
		info["web_sessions"] = s.sessionPool.ListSessions(profileID)
	}
	res := textResult(mustJSON(info))
	for k, v := range info {
		res[k] = v
	}
	return res, nil
}

func pageTitle(page playwright.Page) string {
	title, err := page.Title()
	if err != nil {
		return ""
	}
	return title
}

func stringSlicePointer(raw any) *[]string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

func intSlicePointer(raw any) *[]int {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		if n, ok := item.(float64); ok {
			out = append(out, int(n))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

func resolveDownloadPath(profileDir string, args map[string]any) (string, string, error) {
	name, _ := args["name"].(string)
	if name == "" {
		return "", "", fmt.Errorf("name is required")
	}
	if strings.ContainsAny(name, `/\`) || filepath.Clean(name) != name {
		return "", "", fmt.Errorf("name must be a file name within downloads")
	}
	return filepath.Join(profileDir, "downloads", name), name, nil
}

func (s *Server) finishScreenshotResult(args map[string]any, profileID string, data []byte, mimeType, ext, baseURL string) (map[string]any, *mcpError) {
	delivery := "image"
	if baseURL != "" {
		delivery = "url"
	}
	if raw, _ := args["delivery"].(string); raw != "" {
		delivery = strings.ToLower(strings.TrimSpace(raw))
	}
	if delivery != "url" && delivery != "image" && delivery != "both" {
		return nil, newError(-32602, "delivery must be url, image, or both")
	}
	includeURL := delivery == "url" || delivery == "both"
	includeImage := delivery == "image" || delivery == "both"
	if raw, ok := args["include_image"].(bool); ok {
		includeImage = raw
		if raw && delivery == "url" {
			includeURL = true
		}
	}
	if !includeURL && !includeImage {
		return nil, newError(-32602, "delivery must include url or image")
	}
	if includeURL && baseURL == "" {
		return nil, newError(-32000, "public_base_url is required for URL screenshot delivery")
	}

	payload := map[string]any{
		"profile_id": profileID,
		"bytes":      len(data),
		"mime_type":  mimeType,
		"sha256":     fmt.Sprintf("%x", sha256.Sum256(data)),
	}

	if includeURL {
		ttl := parseScreenshotTTL(args)
		artifactID, expiresAt, err := s.screenshotArtifactStore().save(data, mimeType, ext, ttl)
		if err != nil {
			return nil, newError(-32000, "generate screenshot artifact id: "+err.Error())
		}
		payload["artifact_id"] = artifactID
		payload["screenshot_url"] = screenshotDownloadURL(baseURL, artifactID)
		payload["expires_at"] = expiresAt.Format(time.RFC3339)
		payload["ttl_seconds"] = int(ttl / time.Second)
	}

	savePath, _ := args["save_path"].(string)
	if savePath != "" {
		p, err := s.store.Get(profileID)
		if err != nil {
			return nil, newError(-32000, err.Error())
		}
		path, err := resolveArtifactPath(p.ProfileDir, savePath, ext)
		if err != nil {
			return nil, newError(-32602, err.Error())
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, newError(-32000, err.Error())
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return nil, newError(-32000, err.Error())
		}
		artifactPath, err := filepath.Rel(filepath.Join(p.ProfileDir, "artifacts"), path)
		if err != nil {
			return nil, newError(-32000, err.Error())
		}
		payload["artifact_path"] = filepath.ToSlash(artifactPath)
		payload["saved_path"] = path
	}

	var res map[string]any
	if includeImage {
		res = imageResultWithMime(data, mimeType)
	} else {
		res = textResult(mustJSON(payload))
	}
	for k, v := range payload {
		res[k] = v
	}
	return res, nil
}

func screenshotDownloadURL(baseURL, artifactID string) string {
	return strings.TrimRight(baseURL, "/") + "/api/screenshots/" + url.PathEscape(artifactID)
}

func resolveArtifactPath(profileDir, requested, ext string) (string, error) {
	base := filepath.Join(profileDir, "artifacts")
	if strings.Contains(requested, "\x00") {
		return "", fmt.Errorf("save_path contains invalid NUL byte")
	}
	clean := filepath.Clean(requested)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("save_path must be relative to profile artifacts")
	}
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("save_path must stay within profile artifacts")
	}
	if filepath.Ext(clean) == "" {
		clean += ext
	}
	out := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, out)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("save_path must stay within profile artifacts")
	}
	return out, nil
}
