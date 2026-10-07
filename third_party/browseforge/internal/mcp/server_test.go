package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/groups"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func TestBuildWebSearchMCPResultRawFallback(t *testing.T) {
	resp := &SearchResponse{
		Engine:         "duckduckgo",
		ExtractionMode: "raw_fallback",
		Results:        nil,
		RawFallback: &SearchRawFallback{
			PageTitle: "Synthetic SERP",
			Text:      "visible SERP text for LLM interpretation",
			CandidateLinks: []LinkRef{
				{Text: "Candidate A", URL: "https://example.com/a"},
				{Text: "Candidate B", URL: "https://example.com/b"},
			},
		},
	}

	got := buildWebSearchMCPResult("synthetic query", resp, "sess_test", "prof_test", true)

	if got["session_id"] != "sess_test" {
		t.Fatalf("session_id = %v", got["session_id"])
	}
	if got["profile_id"] != "prof_test" {
		t.Fatalf("profile_id = %v", got["profile_id"])
	}
	if got["session_created"] != true {
		t.Fatalf("session_created = %v", got["session_created"])
	}
	if got["extraction_mode"] != "raw_fallback" {
		t.Fatalf("extraction_mode = %v", got["extraction_mode"])
	}
	if got["engine"] != "duckduckgo" {
		t.Fatalf("engine = %v", got["engine"])
	}
	results, ok := got["results"].([]map[string]string)
	if !ok {
		t.Fatalf("results type = %T", got["results"])
	}
	if len(results) != 0 {
		t.Fatalf("results len = %d", len(results))
	}
	fallback, ok := got["raw_fallback"].(*SearchRawFallback)
	if !ok {
		t.Fatalf("raw_fallback type = %T", got["raw_fallback"])
	}
	if fallback.PageTitle != "Synthetic SERP" || fallback.Text == "" || len(fallback.CandidateLinks) != 2 {
		t.Fatalf("unexpected fallback = %+v", fallback)
	}

	content, ok := got["content"].([]map[string]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %#v", got["content"])
	}
	text, _ := content[0]["text"].(string)
	for _, want := range []string{"duckduckgo", "mode: raw_fallback", "raw_fallback", "candidate_links", "visible SERP text"} {
		if !strings.Contains(text, want) {
			t.Fatalf("content text missing %q: %s", want, text)
		}
	}
}

func TestServeHTTPMalformedJSONReturnsBadRequest(t *testing.T) {
	srv := NewServer(nil, nil, humanizeNoopConfig(), nil, "", "test")
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":-32700`) {
		t.Fatalf("body missing parse error: %s", rec.Body.String())
	}
}

func TestBuildWebSearchMCPResultDefaultsEngine(t *testing.T) {
	got := buildWebSearchMCPResult("synthetic query", &SearchResponse{}, "sess_test", "prof_test", false)

	if got["engine"] != "google" {
		t.Fatalf("engine = %v", got["engine"])
	}
	if got["extraction_mode"] != "structured" {
		t.Fatalf("extraction_mode = %v", got["extraction_mode"])
	}
	content := got["content"].([]map[string]any)
	if !strings.Contains(content[0]["text"].(string), "Found 0 google results") {
		t.Fatalf("content text = %s", content[0]["text"])
	}
}

func TestWebSessionClosedReturnsExplicitError(t *testing.T) {
	sess := &WebSession{ID: "sess_test", Closed: true}

	_, err := sess.WebSearch("query", "", 1)
	if err == nil || !strings.Contains(err.Error(), "session is closed: sess_test") {
		t.Fatalf("WebSearch err = %v", err)
	}

	_, err = sess.WebExplore("https://example.com", 100, 1)
	if err == nil || !strings.Contains(err.Error(), "session is closed: sess_test") {
		t.Fatalf("WebExplore err = %v", err)
	}
}

func humanizeNoopConfig() humanize.Config {
	return humanize.Config{}
}

func TestSearchProviderRegistry(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"", "google"},
		{"google", "google"},
		{"BING", "bing"},
		{"duckduckgo", "duckduckgo"},
		{"ddg", "duckduckgo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := getSearchProvider(tt.name)
			if err != nil {
				t.Fatalf("getSearchProvider(%q): %v", tt.name, err)
			}
			if provider.Name() != tt.want {
				t.Fatalf("provider.Name() = %q, want %q", provider.Name(), tt.want)
			}
		})
	}

	_, err := getSearchProvider("unknown")
	if err == nil || !strings.Contains(err.Error(), "unsupported search engine") {
		t.Fatalf("unknown provider err = %v", err)
	}
}

func TestSearchProviderURLs(t *testing.T) {
	for name, wantHost := range map[string]string{
		"google":     "https://www.google.com/search?",
		"bing":       "https://www.bing.com/search?",
		"duckduckgo": "https://duckduckgo.com/html/?",
	} {
		provider, err := getSearchProvider(name)
		if err != nil {
			t.Fatalf("getSearchProvider(%q): %v", name, err)
		}
		got := provider.SearchURL("BrowseForge MCP")
		if !strings.HasPrefix(got, wantHost) {
			t.Fatalf("%s SearchURL = %q, want prefix %q", name, got, wantHost)
		}
		if !strings.Contains(got, "BrowseForge") || strings.Contains(got, " ") {
			t.Fatalf("%s SearchURL query not encoded as expected: %q", name, got)
		}
	}
}

func TestToolSchemasRequiredFields(t *testing.T) {
	expected := map[string][]string{
		"list_runtimes":      {},
		"list_proxy_regions": {},
		"list_profiles":      {},
		"create_profile":     {"name", "runtime_id"},
		"delete_profile":     {"profile_id"},
		"update_profile":     {"profile_id"},
		"list_groups":        {},
		"get_group":          {"group"},
		"update_group_proxy": {"group", "proxy"},
		"clear_group_proxy":  {"group"},
		"delete_group":       {"group"},
		"open_browser":       {"profile_id"},
		"close_browser":      {"profile_id"},
		"navigate":           {"profile_id", "url"},
		"click":              {"profile_id", "selector"},
		"type_text":          {"profile_id", "selector", "text"},
		"screenshot":         {"profile_id"},
		"get_content":        {"profile_id"},
		"evaluate":           {"profile_id", "script"},
		"new_tab":            {"profile_id"},
		"list_tabs":          {"profile_id"},
		"switch_tab":         {"profile_id", "index"},
		"close_tab":          {"profile_id", "index"},
		"web_search":         {"query"},
		"web_explore":        {"url"},
		"create_session":     {"profile_id"},
		"destroy_session":    {"session_id"},
		"list_sessions":      {},
		"gc_sessions":        {},
		"wait_for":           {"selector"},
		"get_page_state":     {},
		"get_cookies":        {},
		"set_cookies":        {"cookies"},
		"run_workflow":       {},
		"form_fill":          {"fields"},
		"select_option":      {"selector"},
		"check":              {"selector"},
		"press_key":          {"key"},
		"list_downloads":     {},
		"delete_download":    {"name"},
		"read_download":      {"name"},
		"web_extract":        {"schema"},
		"doctor_profile":     {"profile_id"},
	}

	seen := map[string]bool{}
	for _, toolDef := range tools {
		name, _ := toolDef["name"].(string)
		seen[name] = true
		want, ok := expected[name]
		if !ok {
			t.Fatalf("unexpected tool in registry: %s", name)
		}
		schema, ok := toolDef["inputSchema"].(map[string]any)
		if !ok {
			t.Fatalf("%s inputSchema type = %T", name, toolDef["inputSchema"])
		}
		rawRequired, ok := schema["required"].([]string)
		if !ok {
			t.Fatalf("%s required type = %T", name, schema["required"])
		}
		got := append([]string(nil), rawRequired...)
		slices.Sort(got)
		want = append([]string(nil), want...)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s required = %v, want %v", name, got, want)
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s properties type = %T", name, schema["properties"])
		}
		if name == "create_profile" || name == "update_profile" {
			if _, ok := properties["engine"]; ok {
				t.Fatalf("%s schema advertises deprecated profile engine", name)
			}
		}
		if name == "create_profile" || name == "update_profile" || name == "update_group_proxy" {
			proxy, ok := properties["proxy"].(map[string]any)
			if !ok {
				t.Fatalf("%s proxy schema type = %T", name, properties["proxy"])
			}
			proxyProperties, ok := proxy["properties"].(map[string]any)
			if !ok {
				t.Fatalf("%s proxy properties type = %T", name, proxy["properties"])
			}
			region, ok := proxyProperties["region"].(map[string]any)
			if !ok {
				t.Fatalf("%s proxy region schema type = %T", name, proxyProperties["region"])
			}
			enum, ok := region["enum"].([]string)
			if !ok {
				t.Fatalf("%s proxy region enum type = %T", name, region["enum"])
			}
			for _, want := range []string{"us-ny", "us-tx", "ca-on", "tw-taipei", "jp-tokyo", "gb-london", "au-sydney"} {
				if !slices.Contains(enum, want) {
					t.Fatalf("%s proxy region enum = %v, missing %s", name, enum, want)
				}
			}
		}
		if name == "update_profile" {
			proxy, ok := properties["proxy"].(map[string]any)
			if !ok {
				t.Fatalf("update_profile proxy schema type = %T", properties["proxy"])
			}
			proxyType, ok := proxy["type"].([]string)
			if !ok || !slices.Contains(proxyType, "null") {
				t.Fatalf("update_profile proxy type = %#v, want nullable object", proxy["type"])
			}
		}
		if name == "web_search" {
			if _, ok := properties["engine"]; !ok {
				t.Fatalf("web_search schema missing search engine property")
			}
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Fatalf("expected tool missing from registry: %s", name)
		}
	}
}

func TestToolListRuntimesReturnsRuntimeDescriptors(t *testing.T) {
	s := NewServer(nil, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox":     {BinaryPath: "/opt/camoufox"},
		"cloakbrowser": {BinaryPath: "/opt/cloakbrowser"},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolListRuntimes(nil)
	if mcpErr != nil {
		t.Fatalf("toolListRuntimes error = %v", mcpErr)
	}
	var got []bfruntime.Descriptor
	if err := json.Unmarshal([]byte(resultText(t, raw)), &got); err != nil {
		t.Fatalf("decode list_runtimes text: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("runtime count = %d, want 3: %#v", len(got), got)
	}
	if got[0].ID != bfruntime.BrowseForgeChromium || got[0].Enabled {
		t.Fatalf("first runtime = %+v, want disabled BrowseForge Chromium descriptor", got[0])
	}
	if got[1].ID != bfruntime.Camoufox || got[1].BinaryPath != "/opt/camoufox" {
		t.Fatalf("second runtime = %+v, want Camoufox with configured binary path", got[1])
	}
	if got[2].ID != bfruntime.CloakBrowser || got[2].BinaryPath != "/opt/cloakbrowser" {
		t.Fatalf("third runtime = %+v, want CloakBrowser with configured binary path", got[2])
	}
	if got[1].Capabilities.SupportsAgentWebSessions || !got[2].Capabilities.SupportsAgentWebSessions {
		t.Fatalf("agent web session capabilities = Camoufox:%v CloakBrowser:%v", got[1].Capabilities.SupportsAgentWebSessions, got[2].Capabilities.SupportsAgentWebSessions)
	}
}

func TestToolListProxyRegionsReturnsPresetValuesAndLabels(t *testing.T) {
	s := NewServer(nil, nil, humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolListProxyRegions(map[string]any{})
	if mcpErr != nil {
		t.Fatalf("toolListProxyRegions error = %v", mcpErr)
	}
	res, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	regions, ok := res["regions"].([]map[string]string)
	if !ok {
		t.Fatalf("regions type = %T", res["regions"])
	}
	if len(regions) < 200 {
		t.Fatalf("regions len = %d, want global preset catalog", len(regions))
	}
	var sawTaiwan, sawTaipei bool
	for _, region := range regions {
		switch region["value"] {
		case "tw":
			sawTaiwan = region["label"] == "Taiwan"
		case "tw-taipei":
			sawTaipei = region["label"] == "Taiwan — Taipei"
		}
	}
	if !sawTaiwan || !sawTaipei {
		t.Fatalf("Taiwan presets not exposed correctly: sawTaiwan=%v sawTaipei=%v", sawTaiwan, sawTaipei)
	}
	if res["total"] != len(regions) {
		t.Fatalf("total = %v, want %d", res["total"], len(regions))
	}
}

func TestToolCreateProfileAcceptsRuntimeID(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"cloakbrowser": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Cloaked",
		"runtime_id": "cloakbrowser",
	})
	if mcpErr != nil {
		t.Fatalf("toolCreateProfile error = %v", mcpErr)
	}
	text := resultText(t, raw)
	if !strings.Contains(text, "runtime: cloakbrowser") {
		t.Fatalf("create_profile text = %s", text)
	}
	profiles := store.List("", "")
	if len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want 1", len(profiles))
	}
	if profiles[0].RuntimeID != "cloakbrowser" {
		t.Fatalf("stored runtime_id = %q, want cloakbrowser", profiles[0].RuntimeID)
	}
}

func TestToolCreateProfileStoresProxyRegion(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"cloakbrowser": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Proxy Profile",
		"runtime_id": "cloakbrowser",
		"proxy": map[string]any{
			"type":     " HTTP ",
			"host":     " proxy.example.com ",
			"port":     float64(8080),
			"username": "user",
			"password": "pass",
			"region":   " us-ny ",
		},
	})
	if mcpErr != nil {
		t.Fatalf("toolCreateProfile error = %v", mcpErr)
	}
	if !strings.Contains(resultText(t, raw), "runtime: cloakbrowser") {
		t.Fatalf("create_profile result = %#v", raw)
	}
	profiles := store.List("", "")
	if len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want 1", len(profiles))
	}
	got := profiles[0].Proxy
	if got == nil || got.Type != "http" || got.Host != "proxy.example.com" || got.Port != 8080 || got.Username != "user" || got.Password != "pass" || got.Region != "us-ny" {
		t.Fatalf("stored proxy = %+v", got)
	}
}

func TestToolCreateProfileRejectsInvalidProxy(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Invalid Proxy",
		"runtime_id": "camoufox",
		"proxy": map[string]any{
			"type": "ssh",
			"host": "proxy.example.com",
			"port": float64(1080),
		},
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "unsupported proxy type") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy validation", mcpErr)
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after proxy rejection", len(profiles))
	}
}

func TestToolCreateProfileRejectsInvalidBrowseForgeProxyRegion(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Bad Region",
		"runtime_id": "browseforge-chromium",
		"proxy": map[string]any{
			"type":   "http",
			"host":   "proxy.example.com",
			"port":   float64(1080),
			"region": "za-gauteng",
		},
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "supported presets") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy_region validation", mcpErr)
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after region rejection", len(profiles))
	}
}

func TestToolCreateProfileNormalizesBrowseForgeProxyRegion(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Good Region",
		"runtime_id": "browseforge-chromium",
		"proxy": map[string]any{
			"type":   "http",
			"host":   "proxy.example.com",
			"port":   float64(1080),
			"region": " US-NY ",
		},
	})
	if mcpErr != nil {
		t.Fatalf("toolCreateProfile error = %v", mcpErr)
	}
	if !strings.Contains(resultText(t, raw), "runtime: browseforge-chromium") {
		t.Fatalf("create_profile result = %#v", raw)
	}
	profiles := store.List("", "")
	if len(profiles) != 1 || profiles[0].Proxy == nil || profiles[0].Proxy.Region != "us-ny" {
		t.Fatalf("stored profiles = %+v", profiles)
	}
}

func TestCreateProfileSchemaDoesNotRequireOptionalGroup(t *testing.T) {
	var createProfile map[string]any
	for _, tool := range tools {
		if tool["name"] == "create_profile" {
			createProfile = tool
			break
		}
	}
	if createProfile == nil {
		t.Fatal("create_profile tool schema not found")
	}
	schema, ok := createProfile["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema type = %T", createProfile["inputSchema"])
	}
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatalf("required type = %T", schema["required"])
	}
	if slices.Contains(required, "group") {
		t.Fatalf("required = %v, group must remain optional", required)
	}
	for _, want := range []string{"name", "runtime_id"} {
		if !slices.Contains(required, want) {
			t.Fatalf("required = %v, missing %s", required, want)
		}
	}
}

func TestToolCreateProfileRejectsDisabledRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	disabled := false
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox": {Enabled: &disabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Disabled",
		"runtime_id": "camoufox",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, `runtime "camoufox" is disabled`) {
		t.Fatalf("mcpErr = %+v, want -32602 disabled runtime", mcpErr)
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after disabled runtime rejection", len(profiles))
	}
}

func TestToolUpdateProfileRejectsDisabledRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "cloakbrowser"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	disabled := false
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox":     {Enabled: &disabled},
		"cloakbrowser": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"runtime_id": "camoufox",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, `runtime "camoufox" is disabled`) {
		t.Fatalf("mcpErr = %+v, want -32602 disabled runtime", mcpErr)
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.RuntimeID != "cloakbrowser" {
		t.Fatalf("stored runtime_id = %q, want unchanged cloakbrowser", got.RuntimeID)
	}
}

func TestToolUpdateProfileStoresAndClearsProxyRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"proxy": map[string]any{
			"type":   "socks5",
			"host":   " proxy.example.com ",
			"port":   float64(1080),
			"region": " tw-taipei ",
		},
	})
	if mcpErr != nil {
		t.Fatalf("toolUpdateProfile set proxy error = %v", mcpErr)
	}
	if !strings.Contains(resultText(t, raw), "Updated profile") {
		t.Fatalf("update_profile result = %#v", raw)
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.Proxy == nil || got.Proxy.Host != "proxy.example.com" || got.Proxy.Region != "tw-taipei" {
		t.Fatalf("stored proxy = %+v", got.Proxy)
	}

	raw, mcpErr = s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"proxy":      nil,
	})
	if mcpErr != nil {
		t.Fatalf("toolUpdateProfile clear proxy error = %v", mcpErr)
	}
	if !strings.Contains(resultText(t, raw), "Updated profile") {
		t.Fatalf("clear proxy result = %#v", raw)
	}
	got, err = store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing after clear: %v", err)
	}
	if got.Proxy != nil {
		t.Fatalf("stored proxy after clear = %+v, want nil", got.Proxy)
	}
}

func TestToolUpdateProfileRejectsInvalidBrowseForgeProxyRegion(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "browseforge-chromium"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"proxy": map[string]any{
			"type":   "socks5",
			"host":   "proxy.example.com",
			"port":   float64(1080),
			"region": "192_0_2_1",
		},
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "supported presets") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy_region validation", mcpErr)
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.Proxy != nil {
		t.Fatalf("stored proxy after rejected update = %+v, want nil", got.Proxy)
	}
}

func TestToolCreateProfileRejectsDeprecatedEngine(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Legacy",
		"runtime_id": "camoufox",
		"engine":     "firefox",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "engine was removed in v2") {
		t.Fatalf("mcpErr = %+v, want -32602 deprecated field", mcpErr)
	}
}

func TestToolUpdateProfileRejectsDeprecatedEngine(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"engine":     "firefox",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "engine was removed in v2") {
		t.Fatalf("mcpErr = %+v, want -32602 deprecated field", mcpErr)
	}
}

func TestToolUpdateProfileRejectsNonStringRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{}), humanize.Config{}, nil, "", "test")

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"runtime_id": float64(42),
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "runtime_id") {
		t.Fatalf("mcpErr = %+v, want -32602 runtime_id validation", mcpErr)
	}
}

func TestSessionPoolRejectsUnsupportedRuntimeByCapability(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Camoufox Agent Session", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sp := &SessionPool{
		mgr:   testManagerWithRuntimeConfig(t, &config.Config{}),
		store: store,
		pools: map[string]*ProfileSessionPool{},
	}

	_, err = sp.CreateSession(p.ID)
	if err == nil {
		t.Fatal("expected unsupported runtime to reject agent web session")
	}
	if !strings.Contains(err.Error(), "runtime camoufox does not support agent web sessions") {
		t.Fatalf("error = %q, want capability-based runtime rejection", err.Error())
	}
	if strings.Contains(err.Error(), "Chromium profile") {
		t.Fatalf("error = %q, want runtime capability rejection rather than legacy engine rejection", err.Error())
	}
}

func TestDefaultProfileUsesBrowseForgeChromiumPriority(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sp := &SessionPool{
		mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
			"browseforge-chromium": {Enabled: &enabled},
			"cloakbrowser":         {Enabled: &enabled},
		}}),
		store: store,
		pools: map[string]*ProfileSessionPool{},
	}

	id, err := sp.GetOrCreateDefaultProfile()
	if err != nil {
		t.Fatalf("GetOrCreateDefaultProfile: %v", err)
	}
	again, err := sp.GetOrCreateDefaultProfile()
	if err != nil {
		t.Fatalf("GetOrCreateDefaultProfile again: %v", err)
	}
	if again != id {
		t.Fatalf("second default profile ID = %q, want %q", again, id)
	}
	profiles := store.List("", "")
	if len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want 1", len(profiles))
	}
	if profiles[0].ID != id || profiles[0].Name != defaultProfileName || profiles[0].RuntimeID != string(bfruntime.BrowseForgeChromium) {
		t.Fatalf("default profile = %+v, want id %q name %q runtime %s", profiles[0], id, defaultProfileName, bfruntime.BrowseForgeChromium)
	}
}

func TestDefaultProfileRejectsUnsupportedExistingDefault(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: defaultProfileName, RuntimeID: string(bfruntime.Camoufox)}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	sp := &SessionPool{
		mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
			"browseforge-chromium": {Enabled: &enabled},
		}}),
		store: store,
		pools: map[string]*ProfileSessionPool{},
	}

	id, err := sp.GetOrCreateDefaultProfile()
	if err == nil {
		t.Fatalf("GetOrCreateDefaultProfile returned id %q, want unsupported existing default error", id)
	}
	if !strings.Contains(err.Error(), "default profile") || !strings.Contains(err.Error(), "camoufox") || !strings.Contains(err.Error(), "agent web session") {
		t.Fatalf("error = %q, want explicit unsupported default profile runtime", err.Error())
	}
	if profiles := store.List("", ""); len(profiles) != 1 || profiles[0].ID != p.ID {
		t.Fatalf("stored profiles = %+v, want original invalid default preserved", profiles)
	}
}

func TestDefaultProfileCreationIsIdempotentUnderConcurrency(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sp := &SessionPool{
		mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
			"cloakbrowser": {Enabled: &enabled},
		}}),
		store: store,
		pools: map[string]*ProfileSessionPool{},
	}

	const workers = 16
	start := make(chan struct{})
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, err := sp.GetOrCreateDefaultProfile()
			if err != nil {
				errs <- err
				return
			}
			ids <- id
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	close(errs)

	for err := range errs {
		t.Fatalf("GetOrCreateDefaultProfile concurrent error: %v", err)
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
			continue
		}
		if id != first {
			t.Fatalf("concurrent default profile ID = %q, want %q", id, first)
		}
	}
	profiles := store.List("", "")
	if len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want 1", len(profiles))
	}
	if profiles[0].Name != defaultProfileName || profiles[0].RuntimeID != string(bfruntime.CloakBrowser) {
		t.Fatalf("default profile = %+v, want singleton %q runtime %s", profiles[0], defaultProfileName, bfruntime.CloakBrowser)
	}
}

func TestToolUpdateGroupProxyReportsRestartOnlyWhenActive(t *testing.T) {
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil, nil, humanize.Config{}, nil, "", "test", groupStore)

	raw, mcpErr := s.toolUpdateGroupProxy(map[string]any{
		"group":      "Client A",
		"proxy_mode": groups.ProxyModeEnforced,
		"proxy": map[string]any{
			"type":   "socks5",
			"host":   "proxy.example.com",
			"port":   float64(1080),
			"region": " us-ny ",
		},
	})
	if mcpErr != nil {
		t.Fatalf("toolUpdateGroupProxy error = %v", mcpErr)
	}
	res, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if res["restart_required"] != false {
		t.Fatalf("restart_required = %v", res["restart_required"])
	}
	if res["active_sessions"] != 0 {
		t.Fatalf("active_sessions = %v", res["active_sessions"])
	}
	g, ok := res["group"].(*groups.Group)
	if !ok || g.Proxy == nil || g.Proxy.Host != "proxy.example.com" || g.Proxy.Region != "us-ny" {
		t.Fatalf("group result = %#v", res["group"])
	}
}

func TestToolCreateProfileRejectsGroupProxyMissingBrowseForgeRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGroupStore: %v", err)
	}
	if _, err := groupStore.Upsert("Client A", &profile.ProxyConfig{Type: "http", Host: "proxy.example.com", Port: 1080}, groups.ProxyModeDefault); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	enabled := true
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test", groupStore)

	raw, mcpErr := s.toolCreateProfile(map[string]any{
		"name":       "Grouped BFC",
		"runtime_id": "browseforge-chromium",
		"group":      "Client A",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "proxy_region is required") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy_region required", mcpErr)
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after group proxy rejection", len(profiles))
	}
}

func TestToolUpdateProfileRejectsGroupProxyMissingBrowseForgeRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGroupStore: %v", err)
	}
	if _, err := groupStore.Upsert("Client A", &profile.ProxyConfig{Type: "http", Host: "proxy.example.com", Port: 1080}, groups.ProxyModeDefault); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	p := &profile.Profile{Name: "BFC", RuntimeID: "browseforge-chromium"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test", groupStore)

	raw, mcpErr := s.toolUpdateProfile(map[string]any{
		"profile_id": p.ID,
		"group":      "Client A",
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "proxy_region is required") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy_region required", mcpErr)
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.Group != "" {
		t.Fatalf("stored group = %q, want unchanged empty group", got.Group)
	}
}

func TestToolUpdateGroupProxyRejectsMissingRegionForBrowseForgeProfiles(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGroupStore: %v", err)
	}
	p := &profile.Profile{Name: "Grouped BFC", RuntimeID: "browseforge-chromium", Group: "Client A"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	s := NewServer(store, testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}}), humanize.Config{}, nil, "", "test", groupStore)

	raw, mcpErr := s.toolUpdateGroupProxy(map[string]any{
		"group":      "Client A",
		"proxy_mode": groups.ProxyModeEnforced,
		"proxy": map[string]any{
			"type": "http",
			"host": "proxy.example.com",
			"port": float64(1080),
		},
	})
	if raw != nil {
		t.Fatalf("raw result = %#v, want nil", raw)
	}
	if mcpErr == nil || mcpErr.Code != -32602 || !strings.Contains(mcpErr.Message, "proxy_region is required") {
		t.Fatalf("mcpErr = %+v, want -32602 proxy_region required", mcpErr)
	}
	if groups := groupStore.List(); len(groups) != 0 {
		t.Fatalf("stored groups = %+v, want none after rejected group proxy", groups)
	}
}

func TestToolDeleteGroupUngroupsProfilesAndClearsProxy(t *testing.T) {
	profileStore, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{Name: "Profile A", RuntimeID: "camoufox", Group: "Client A"}
	if err := profileStore.Create(p); err != nil {
		t.Fatal(err)
	}
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groupStore.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "proxy.example.com", Port: 1080}, groups.ProxyModeDefault); err != nil {
		t.Fatal(err)
	}
	s := NewServer(profileStore, nil, humanize.Config{}, nil, "", "test", groupStore)

	raw, mcpErr := s.toolDeleteGroup(map[string]any{"group": "Client A"})
	if mcpErr != nil {
		t.Fatalf("toolDeleteGroup error = %v", mcpErr)
	}
	res, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if res["profiles_ungrouped"] != 1 {
		t.Fatalf("profiles_ungrouped = %v", res["profiles_ungrouped"])
	}
	updated, err := profileStore.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Group != "" {
		t.Fatalf("profile group = %q, want empty", updated.Group)
	}
	if g, ok := groupStore.Get("Client A"); ok {
		t.Fatalf("group proxy still exists = %+v", g)
	}
}

func TestActiveGroupDeleteErrorIsStructured(t *testing.T) {
	err := activeGroupDeleteError("Client A", 2)
	if err.Code != -32000 {
		t.Fatalf("code = %d", err.Code)
	}
	data, ok := err.Data.(map[string]any)
	if !ok {
		t.Fatalf("data type = %T", err.Data)
	}
	if data["code"] != "GROUP_HAS_ACTIVE_SESSIONS" || data["group"] != "Client A" || data["active_sessions"] != 2 || data["restart_required"] != true {
		t.Fatalf("data = %#v", data)
	}
}

func TestParseWorkflowArgsRequiresWorkflow(t *testing.T) {
	_, err := parseWorkflowArgs(map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "workflow or yaml is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseWorkflowArgsFromObject(t *testing.T) {
	wf, err := parseWorkflowArgs(map[string]any{
		"workflow": map[string]any{
			"name": "test workflow",
			"steps": []any{
				map[string]any{"name": "sleep", "action": "sleep", "params": map[string]any{"seconds": 1}},
			},
		},
	})
	if err != nil {
		t.Fatalf("parseWorkflowArgs: %v", err)
	}
	if wf.Name != "test workflow" || len(wf.Steps) != 1 || wf.Steps[0].Action != "sleep" {
		t.Fatalf("workflow = %+v", wf)
	}
}

func TestResolveArtifactPathStaysInProfileArtifacts(t *testing.T) {
	got, err := resolveArtifactPath("/tmp/profile", "shots/home", ".jpg")
	if err != nil {
		t.Fatalf("resolveArtifactPath: %v", err)
	}
	if got != "/tmp/profile/artifacts/shots/home.jpg" {
		t.Fatalf("path = %q", got)
	}

	if _, err := resolveArtifactPath("/tmp/profile", "../escape.jpg", ".jpg"); err == nil {
		t.Fatal("expected traversal error")
	}
	if _, err := resolveArtifactPath("/tmp/profile", "/tmp/escape.jpg", ".jpg"); err == nil {
		t.Fatal("expected absolute path error")
	}
}

func TestFinishScreenshotWithoutBaseURLDefaultsToImageBlock(t *testing.T) {
	s := &Server{}
	res, mcpErr := s.finishScreenshotResult(map[string]any{}, "prof_stdio", []byte("png bytes"), "image/png", ".png", "")
	if mcpErr != nil {
		t.Fatalf("finishScreenshotResult error = %+v", mcpErr)
	}
	content := res["content"].([]map[string]any)
	if content[0]["type"] != "image" {
		t.Fatalf("content type = %v, want image", content[0]["type"])
	}
	if content[0]["data"] == "" {
		t.Fatal("image delivery should include base64 image data")
	}
	if _, ok := res["screenshot_url"]; ok {
		t.Fatal("image delivery should not include screenshot_url")
	}
}

func TestFinishScreenshotURLDeliveryReturnsTTLLinkWithoutImageData(t *testing.T) {
	s := &Server{}

	res, mcpErr := s.finishScreenshotResult(map[string]any{"delivery": "url", "url_ttl_seconds": float64(120)}, "prof_url", []byte("png bytes"), "image/png", ".png", "https://bf.example.com/root")
	if mcpErr != nil {
		t.Fatalf("finishScreenshotResult error = %+v", mcpErr)
	}
	if got := res["screenshot_url"]; got == nil || !strings.HasPrefix(got.(string), "https://bf.example.com/root/api/screenshots/") {
		t.Fatalf("screenshot_url = %v", got)
	}
	if got := res["ttl_seconds"]; got != 120 {
		t.Fatalf("ttl_seconds = %v, want 120", got)
	}
	if res["expires_at"] == "" {
		t.Fatal("expires_at is empty")
	}
	content := res["content"].([]map[string]any)
	if content[0]["type"] != "text" {
		t.Fatalf("content type = %v, want text", content[0]["type"])
	}
	if _, ok := content[0]["data"]; ok {
		t.Fatal("URL delivery should not include base64 image data")
	}
	id, _ := res["artifact_id"].(string)
	req := httptest.NewRequest(http.MethodGet, "/api/screenshots/"+id, nil)
	rec := httptest.NewRecorder()
	s.ServeScreenshotArtifact(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifact status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "png bytes" {
		t.Fatalf("artifact body = %q", rec.Body.String())
	}
}

func TestScreenshotURLArtifactPersistsAcrossServerProcesses(t *testing.T) {
	dir := t.TempDir()
	writer := &Server{}
	writer.SetScreenshotArtifactDir(dir)
	res, mcpErr := writer.finishScreenshotResult(map[string]any{"delivery": "url"}, "prof_stdio", []byte("shared png bytes"), "image/png", ".png", "http://localhost:19280")
	if mcpErr != nil {
		t.Fatalf("finishScreenshotResult error = %+v", mcpErr)
	}
	id, _ := res["artifact_id"].(string)
	if id == "" {
		t.Fatalf("artifact_id = %q", id)
	}

	reader := &Server{}
	reader.SetScreenshotArtifactDir(dir)
	req := httptest.NewRequest(http.MethodGet, "/api/screenshots/"+id, nil)
	rec := httptest.NewRecorder()
	reader.ServeScreenshotArtifact(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifact status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "shared png bytes" {
		t.Fatalf("artifact body = %q", rec.Body.String())
	}
}

func TestScreenshotArtifactExpires(t *testing.T) {
	s := &Server{}
	id, _, err := s.screenshotArtifactStore().save([]byte("expired"), "image/png", ".png", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/screenshots/"+id, nil)
	rec := httptest.NewRecorder()
	s.ServeScreenshotArtifact(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestScreenshotDownloadURLEscapesArtifactID(t *testing.T) {
	got := screenshotDownloadURL("https://bf.example.com/root/", "id with space")
	want := "https://bf.example.com/root/api/screenshots/id%20with%20space"
	if got != want {
		t.Fatalf("screenshotDownloadURL = %q, want %q", got, want)
	}
}

func TestPublicBaseURLFromRequestUsesForwardedHeaders(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "http://internal:19280/mcp", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "bf.example.com")
	if got := s.publicBaseURLFromRequest(req); got != "https://bf.example.com" {
		t.Fatalf("publicBaseURLFromRequest = %q", got)
	}
}

func TestPublicBaseURLFromRequestNormalizesUnspecifiedHost(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "http://0.0.0.0:19280/mcp", nil)
	if got := s.publicBaseURLFromRequest(req); got != "http://localhost:19280" {
		t.Fatalf("publicBaseURLFromRequest = %q", got)
	}
}

func TestConfiguredPublicBaseURLOverridesRequest(t *testing.T) {
	s := &Server{}
	s.SetPublicBaseURL("https://configured.example.com/root/")
	req := httptest.NewRequest(http.MethodPost, "http://internal:19280/mcp", nil)
	if got := s.publicBaseURLFromRequest(req); got != "https://configured.example.com/root" {
		t.Fatalf("publicBaseURLFromRequest = %q", got)
	}
}

func TestConfiguredPublicBaseURLNormalizesUnspecifiedHost(t *testing.T) {
	s := &Server{}
	s.SetPublicBaseURL("http://0.0.0.0:19280/root/")
	req := httptest.NewRequest(http.MethodPost, "http://internal:19280/mcp", nil)
	if got := s.publicBaseURLFromRequest(req); got != "http://localhost:19280/root" {
		t.Fatalf("publicBaseURLFromRequest = %q", got)
	}
}

func TestResolveDownloadPathRequiresFileName(t *testing.T) {
	got, name, err := resolveDownloadPath("/tmp/profile", map[string]any{"name": "report.csv"})
	if err != nil {
		t.Fatalf("resolveDownloadPath: %v", err)
	}
	if name != "report.csv" || got != "/tmp/profile/downloads/report.csv" {
		t.Fatalf("path=%q name=%q", got, name)
	}
	if _, _, err := resolveDownloadPath("/tmp/profile", map[string]any{"name": "../report.csv"}); err == nil {
		t.Fatal("expected traversal error")
	}
}

func resultText(t *testing.T, raw any) string {
	t.Helper()

	res, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	content, ok := res["content"].([]map[string]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %#v", res["content"])
	}
	text, ok := content[0]["text"].(string)
	if !ok {
		t.Fatalf("content text type = %T", content[0]["text"])
	}
	return text
}

func testManagerWithRuntimeConfig(t *testing.T, cfg *config.Config) *browser.Manager {
	t.Helper()

	mgr := &browser.Manager{}
	field := reflect.ValueOf(mgr).Elem().FieldByName("runtimes")
	if !field.IsValid() {
		t.Fatal("browser.Manager.runtimes field missing")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(bfruntime.NewRegistry(cfg)))
	return mgr
}
