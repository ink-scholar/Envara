package mcp

import "browseforge/internal/browser"

var tools = []map[string]any{
	tool("list_runtimes", "List available browser runtime providers and capabilities. Use before creating profiles when runtime choice matters.", map[string]any{}),
	toolWithRequired("list_proxy_regions", "List supported proxy.region presets with labels. Use this before setting BrowseForge Chromium proxy settings when the egress location is not already known; pass the returned value exactly as proxy.region.", map[string]any{}, []string{}),
	toolWithRequired("list_profiles", "List available profiles before choosing a browser identity. Use this first when the user did not provide a profile_id.", map[string]any{
		"group": prop("string", "Optional group filter."),
		"tag":   prop("string", "Optional tag filter."),
	}, []string{}),
	toolWithRequired("create_profile", "Create a new browser profile. Prefer existing profiles for logged-in or stateful tasks; create only when a fresh identity is needed.", map[string]any{
		"name":       prop("string", "Profile name."),
		"runtime_id": prop("string", "Runtime provider id such as browseforge-chromium, camoufox, or cloakbrowser."),
		"group":      prop("string", "Optional group name."),
		"proxy":      proxyProp("Optional proxy settings. For browseforge-chromium, first call list_proxy_regions when unsure, then set proxy.region to one returned value. Example: {\"type\":\"http\",\"host\":\"proxy.example.com\",\"port\":1080,\"region\":\"tw\"}."),
	}, []string{"name", "runtime_id"}),
	tool("delete_profile", "Delete a profile and its stored data. Use only when explicitly requested; prefer close_browser/destroy_session for cleanup.", map[string]any{"profile_id": prop("string", "Profile ID.")}),
	toolWithRequired("update_profile", "Update profile metadata or proxy settings. Close and reopen the browser if a runtime setting must take effect.", map[string]any{
		"profile_id": prop("string", "Profile ID."),
		"name":       prop("string", "Optional new name."),
		"group":      prop("string", "Optional new group."),
		"runtime_id": prop("string", "Optional runtime provider id such as browseforge-chromium, camoufox, or cloakbrowser."),
		"proxy":      nullableProxyProp("Optional proxy settings. For browseforge-chromium, first call list_proxy_regions when unsure, then set proxy.region to one returned value. To remove proxy settings, pass proxy:null."),
	}, []string{"profile_id"}),
	tool("list_groups", "List group proxy policies with active_sessions and restart_required. Use before changing group-scoped proxy behavior.", map[string]any{}),
	toolWithRequired("get_group", "Read one group proxy policy with active_sessions and restart_required. Group proxy mode default means profile proxy overrides group proxy; enforced means group proxy overrides profile proxy.", map[string]any{
		"group": prop("string", "Group name."),
	}, []string{"group"}),
	toolWithRequired("update_group_proxy", "Set a group-scoped proxy policy. proxy_mode default means profile proxy overrides group proxy; enforced means group proxy overrides profile proxy. Check restart_required in the result before asking the operator to reopen browsers.", map[string]any{
		"group":      prop("string", "Group name."),
		"proxy_mode": prop("string", "default or enforced. Defaults to default."),
		"proxy":      proxyProp("Proxy settings. For BrowseForge Chromium group users, first call list_proxy_regions when unsure, then set proxy.region to one returned value."),
	}, []string{"group", "proxy"}),
	toolWithRequired("clear_group_proxy", "Clear a group proxy policy. Check restart_required in the result before asking the operator to reopen browsers.", map[string]any{
		"group": prop("string", "Group name."),
	}, []string{"group"}),
	toolWithRequired("delete_group", "Delete a group label and its group proxy policy without deleting profiles. Fails when the group has active browser sessions; close those browsers first.", map[string]any{
		"group": prop("string", "Group name."),
	}, []string{"group"}),
	tool("open_browser", "Open or reuse the profile browser. Use doctor_profile first when diagnosing; after open_browser, call get_page_state or navigate.", map[string]any{"profile_id": prop("string", "Profile ID.")}),
	tool("close_browser", "Close the profile browser. This ends profile-page operations; it also invalidates active profile browser state.", map[string]any{"profile_id": prop("string", "Profile ID.")}),
	toolWithRequired("navigate", "Navigate the active profile page. After navigation, prefer wait_for on a meaningful selector before clicking or extracting.", map[string]any{
		"profile_id": prop("string", "Profile ID with an active browser session."),
		"url":        prop("string", "Target URL. https:// is recommended when no scheme is known."),
		"wait_until": prop("string", "Optional Playwright wait strategy: load, domcontentloaded, networkidle, or commit. Still use wait_for for app readiness."),
	}, []string{"profile_id", "url"}),
	toolWithRequired("click", "Click an element on the active profile page. Use wait_for(selector, visible) first for dynamic pages; use form_fill/select_option/check for standard form controls.", map[string]any{
		"profile_id": prop("string", "Profile ID with an active browser session."),
		"selector":   prop("string", "CSS selector for the target element."),
		"timeout":    prop("number", "Optional milliseconds to wait for the element before clicking."),
	}, []string{"profile_id", "selector"}),
	toolWithRequired("type_text", "Type into one element using humanized input. For multiple fields, prefer form_fill to reduce tool calls and keep a coherent form workflow.", map[string]any{
		"profile_id": prop("string", "Profile ID with an active browser session."),
		"selector":   prop("string", "CSS selector for an input/textarea/editable element."),
		"text":       prop("string", "Text to type."),
		"clear":      prop("boolean", "Optional. Clear the field before typing; default false."),
	}, []string{"profile_id", "selector", "text"}),
	toolWithRequired("screenshot", "Capture the active profile page. When BrowseForge can determine a fetchable base URL, returns a temporary unauthenticated screenshot_url by default; otherwise returns an MCP image block. For GHCR/remote agents, set BROWSEFORGE_PUBLIC_BASE_URL and fetch screenshot_url before expires_at.", map[string]any{
		"profile_id":      prop("string", "Profile ID with an active browser session."),
		"quality":         prop("number", "Optional JPEG quality 1-100; default 40."),
		"full_page":       prop("boolean", "Optional full-page capture; default false."),
		"format":          prop("string", "Optional jpeg or png; default jpeg."),
		"delivery":        prop("string", "Optional url, image, or both. Defaults to url when a base URL is available; otherwise defaults to image. Use url for GHCR/remote agents."),
		"include_image":   prop("boolean", "Optional compatibility override. false omits the MCP image base64 block; true includes it."),
		"url_ttl_seconds": prop("number", "Optional screenshot_url lifetime in seconds. Default 600; clamped to 30-3600."),
		"save_path":       prop("string", "Optional relative profile artifact path for an additional persistent copy. Absolute paths and traversal are rejected."),
	}, []string{"profile_id"}),
	toolWithRequired("get_content", "Get HTML or selector text from the active profile page. Prefer get_page_state for quick observation and web_extract for structured fields.", map[string]any{
		"profile_id": prop("string", "Profile ID with an active browser session."),
		"selector":   prop("string", "Optional CSS selector. When omitted, returns full page HTML."),
	}, []string{"profile_id"}),
	tool("evaluate", "Execute JavaScript on the active profile page. Use as a last resort when no dedicated tool fits; prefer wait_for, form_fill, select_option, check, press_key, get_page_state, or web_extract first.", map[string]any{"profile_id": prop("string", "Profile ID with an active browser session."), "script": prop("string", "JavaScript expression/function body to evaluate.")}),
	toolWithRequired("new_tab", "Open a new tab in the profile browser and make it active. Use list_tabs afterward if tab selection matters.", map[string]any{
		"profile_id": prop("string", "Profile ID with an active browser session."),
		"url":        prop("string", "Optional URL to navigate the new tab to."),
	}, []string{"profile_id"}),
	tool("list_tabs", "List tabs for a profile browser. Use before switch_tab/close_tab when the active tab is uncertain.", map[string]any{"profile_id": prop("string", "Profile ID with an active browser session.")}),
	tool("switch_tab", "Switch the active profile page to an existing tab by index. Call get_page_state after switching to verify context.", map[string]any{"profile_id": prop("string", "Profile ID with an active browser session."), "index": prop("number", "Zero-based tab index from list_tabs.")}),
	tool("close_tab", "Close a tab by index. Avoid closing the only useful tab unless cleanup is intended.", map[string]any{"profile_id": prop("string", "Profile ID with an active browser session."), "index": prop("number", "Zero-based tab index to close.")}),
	toolWithRequired("web_search", "Search the web in a runtime-backed agent session. Save returned session_id and reuse it for web_explore, wait_for, web_extract, screenshots, or cleanup.", map[string]any{
		"query":       prop("string", "Search query."),
		"engine":      prop("string", "Search engine: google, bing, duckduckgo, or ddg. Default google."),
		"profile_id":  prop("string", "Profile ID whose runtime supports agent web sessions. Optional; uses the browseforge_default system profile when both profile_id and session_id are omitted."),
		"session_id":  prop("string", "Existing agent session ID to reuse the same page."),
		"max_results": prop("number", "Maximum result count. Default 10; clamped to 30."),
	}, []string{"query"}),
	toolWithRequired("web_explore", "Navigate an agent session page to a URL and extract readable text/links. Reuse session_id from web_search to inspect a result without losing session continuity.", map[string]any{
		"url":             prop("string", "URL to explore. https:// is prepended when no scheme is provided."),
		"profile_id":      prop("string", "Profile ID whose runtime supports agent web sessions. Optional; uses the browseforge_default system profile when both profile_id and session_id are omitted."),
		"session_id":      prop("string", "Existing agent session ID to reuse the same page."),
		"max_text_length": prop("number", "Maximum text length. Default 3000; clamped to 10000."),
		"max_links":       prop("number", "Maximum links. Default 50; clamped to 200."),
	}, []string{"url"}),
	toolWithRequired("create_session", "Create an isolated agent page for a Chromium profile before multi-step browsing. Reuse the returned session_id across subsequent page utility tools.", map[string]any{
		"profile_id": prop("string", "Chromium profile ID."),
	}, []string{"profile_id"}),
	toolWithRequired("destroy_session", "Destroy an agent web session and close only its page. Use for cleanup after web_search/web_explore workflows; this does not close the profile browser.", map[string]any{
		"session_id": prop("string", "Agent session ID."),
	}, []string{"session_id"}),
	toolWithRequired("list_sessions", "List active agent web sessions. Use this to recover session_id or inspect idle sessions before creating more.", map[string]any{
		"profile_id": prop("string", "Optional profile ID filter."),
	}, []string{}),
	toolWithRequired("gc_sessions", "Run agent session garbage collection now. Use for maintenance, not as a normal page-navigation step.", map[string]any{}, []string{}),
	toolWithRequired("wait_for", "Wait for a selector state. Prefer this after navigate/click/form submit/SPA transitions instead of fixed sleep or repeated blind actions.", map[string]any{
		"profile_id": prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"selector":   prop("string", "CSS selector to wait for."),
		"state":      prop("string", "attached, visible, hidden, or detached. Default visible."),
		"timeout":    prop("number", "Wait timeout in milliseconds. Default 30000."),
	}, []string{"selector"}),
	toolWithRequired("get_page_state", "Observe the current page before deciding the next action. Use this after navigation, tab switch, failed actions, or when page context is uncertain.", map[string]any{
		"profile_id":      prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id":      prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"text_max_length": prop("number", "Maximum visible text excerpt length. Default 1000."),
	}, []string{}),
	toolWithRequired("get_cookies", "Read browser-context cookies for a profile. Use for state inspection/export; do not parse page HTML for cookies.", map[string]any{
		"profile_id": prop("string", "Profile ID. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID whose profile context should be read."),
	}, []string{}),
	toolWithRequired("set_cookies", "Add browser-context cookies. Use for restoring known session state; then navigate or reload and wait_for an authenticated page marker.", map[string]any{
		"profile_id": prop("string", "Profile ID. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID whose profile context should receive cookies."),
		"cookies":    prop("array", "Playwright OptionalCookie array."),
	}, []string{"cookies"}),
	toolWithRequired("run_workflow", "Execute a BrowseForge workflow for repeatable multi-step automation. Prefer this for known procedures instead of many ad hoc tool calls.", map[string]any{
		"workflow": prop("object", "Workflow object: {name, steps}."),
		"yaml":     prop("string", "Workflow YAML string. Ignored when workflow object is provided."),
	}, []string{}),
	toolWithRequired("form_fill", "Fill multiple form fields with humanized typing. Prefer this over repeated type_text calls for forms; use wait_for before and after submit.", map[string]any{
		"profile_id": prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"fields":     prop("array", "Array of {selector,text,clear}."),
	}, []string{"fields"}),
	toolWithRequired("select_option", "Select options in a select element. Prefer this over evaluate for dropdowns because it uses Playwright actionability checks.", map[string]any{
		"profile_id": prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"selector":   prop("string", "CSS selector for the select element."),
		"values":     prop("array", "Option values to select."),
		"labels":     prop("array", "Option labels to select."),
		"indexes":    prop("array", "Option indexes to select."),
		"timeout":    prop("number", "Operation timeout in milliseconds."),
	}, []string{"selector"}),
	toolWithRequired("check", "Check or uncheck checkbox/radio controls. Prefer this over click when the intended checked state matters.", map[string]any{
		"profile_id": prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"selector":   prop("string", "CSS selector for checkbox/radio element."),
		"checked":    prop("boolean", "true to check, false to uncheck. Default true."),
		"timeout":    prop("number", "Operation timeout in milliseconds."),
	}, []string{"selector"}),
	toolWithRequired("press_key", "Press a keyboard key or shortcut. Use for Enter/Escape/Tab or shortcuts after focusing an element; then wait_for or get_page_state.", map[string]any{
		"profile_id": prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"key":        prop("string", "Playwright key name or shortcut, e.g. Enter, Escape, Tab, ControlOrMeta+A."),
		"delay":      prop("number", "Optional key press delay in milliseconds."),
	}, []string{"key"}),
	toolWithRequired("list_downloads", "List files downloaded by a profile. Use after clicking an export/download action; poll this instead of guessing file paths.", map[string]any{
		"profile_id": prop("string", "Profile ID. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID whose profile downloads should be listed."),
		"limit":      prop("number", "Maximum returned files. Default 50."),
	}, []string{}),
	toolWithRequired("delete_download", "Delete one file from a profile downloads directory. Use only for explicit cleanup; name must be a direct file name.", map[string]any{
		"profile_id": prop("string", "Profile ID. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID whose profile downloads should be modified."),
		"name":       prop("string", "Direct file name inside downloads; paths are rejected."),
	}, []string{"name"}),
	toolWithRequired("read_download", "Read one small downloaded file. Text-like files return text; binary files return base64. Use list_downloads first to find the exact name.", map[string]any{
		"profile_id": prop("string", "Profile ID. Provide either profile_id or session_id."),
		"session_id": prop("string", "Agent session ID whose profile downloads should be read."),
		"name":       prop("string", "Direct file name inside downloads; paths are rejected."),
		"max_bytes":  prop("number", "Maximum bytes to read. Default 1048576."),
	}, []string{"name"}),
	toolWithRequired("web_extract", "Extract deterministic structured data from the current page using selectors. Prefer this over evaluate for repeatable extraction; it does not call an LLM.", map[string]any{
		"profile_id":      prop("string", "Profile ID for the active profile page. Provide either profile_id or session_id."),
		"session_id":      prop("string", "Agent session ID for an isolated agent page. Provide either profile_id or session_id."),
		"schema":          prop("object", "Selector schema, e.g. {title:{selector:'h1',attr:'text'}, links:{selector:'a',attr:'href',all:true}}."),
		"text_max_length": prop("number", "Maximum text field length. Default 2000."),
	}, []string{"schema"}),
	toolWithRequired("doctor_profile", "Diagnose profile readiness before retrying or relaunching. Use when a browser/session/tool call fails or when profile state is uncertain.", map[string]any{
		"profile_id": prop("string", "Profile ID to inspect."),
	}, []string{"profile_id"}),
}

func tool(name, desc string, props map[string]any) map[string]any {
	required := []string{}
	for k := range props {
		required = append(required, k)
	}
	return toolWithRequired(name, desc, props, required)
}

func toolWithRequired(name, desc string, props map[string]any, required []string) map[string]any {
	return map[string]any{
		"name": name, "description": desc,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required},
	}
}

func prop(t, desc string) map[string]string { return map[string]string{"type": t, "description": desc} }
func proxyProp(desc string) map[string]any {
	return proxySchema(desc, false)
}

func nullableProxyProp(desc string) map[string]any {
	return proxySchema(desc, true)
}

func proxySchema(desc string, nullable bool) map[string]any {
	proxyType := any("object")
	if nullable {
		proxyType = []string{"object", "null"}
	}
	return map[string]any{
		"type":        proxyType,
		"description": desc,
		"properties": map[string]any{
			"type":     map[string]any{"type": "string", "enum": []string{"socks5", "http"}, "description": "Proxy type."},
			"host":     prop("string", "Proxy host."),
			"port":     prop("number", "Proxy port."),
			"username": prop("string", "Optional proxy username."),
			"password": prop("string", "Optional proxy password."),
			"region": map[string]any{
				"type":        "string",
				"enum":        browser.BrowseForgeProxyRegionValues(),
				"description": "BrowseForge Chromium proxy region preset. Choose a value returned by list_proxy_regions or from this enum; do not type arbitrary labels.",
			},
		},
		"required": []string{"type", "host", "port"},
	}
}
