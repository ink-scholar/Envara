package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/go-chi/chi/v5"
)

func TestListRuntimesReturnsRuntimeDescriptors(t *testing.T) {
	h := &handler{mgr: testManagerWithRuntimeConfig(t, &config.Config{
		DefaultRuntimeID: "cloakbrowser",
		Runtimes: map[string]config.RuntimeConfig{
			"camoufox":     {BinaryPath: "/opt/camoufox"},
			"cloakbrowser": {BinaryPath: "/opt/cloakbrowser"},
		},
	})}

	rec := httptest.NewRecorder()
	h.listRuntimes(rec, httptest.NewRequest(http.MethodGet, "/api/runtimes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Data             []bfruntime.Descriptor `json:"data"`
		DefaultRuntimeID string                 `json:"default_runtime_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode runtimes response: %v", err)
	}
	if body.DefaultRuntimeID != "cloakbrowser" {
		t.Fatalf("default_runtime_id = %q, want cloakbrowser", body.DefaultRuntimeID)
	}
	if len(body.Data) != 3 {
		t.Fatalf("runtime count = %d, want 3: %#v", len(body.Data), body.Data)
	}
	if body.Data[0].ID != bfruntime.BrowseForgeChromium || body.Data[0].Enabled {
		t.Fatalf("first runtime = %+v, want disabled BrowseForge Chromium descriptor", body.Data[0])
	}
	if body.Data[1].ID != bfruntime.Camoufox || body.Data[1].BinaryPath != "/opt/camoufox" {
		t.Fatalf("second runtime = %+v, want Camoufox with configured binary path", body.Data[1])
	}
	if body.Data[2].ID != bfruntime.CloakBrowser || body.Data[2].BinaryPath != "/opt/cloakbrowser" {
		t.Fatalf("third runtime = %+v, want CloakBrowser with configured binary path", body.Data[2])
	}
	if body.Data[1].Capabilities.SupportsAgentWebSessions {
		t.Fatalf("Camoufox should not advertise agent web sessions: %+v", body.Data[1].Capabilities)
	}
	if !body.Data[2].Capabilities.SupportsAgentWebSessions {
		t.Fatalf("CloakBrowser should advertise agent web sessions: %+v", body.Data[2].Capabilities)
	}
}

func TestCreateProfileAcceptsRuntimeID(t *testing.T) {
	enabled := true
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"cloakbrowser": {Enabled: &enabled},
	}})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Cloaked","runtime_id":"cloakbrowser"}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Data profile.Profile `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode create profile response: %v", err)
	}
	if body.Data.RuntimeID != "cloakbrowser" {
		t.Fatalf("response runtime_id = %q, want cloakbrowser", body.Data.RuntimeID)
	}
	got, err := store.Get(body.Data.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.RuntimeID != "cloakbrowser" {
		t.Fatalf("stored runtime_id = %q, want cloakbrowser", got.RuntimeID)
	}
}

func TestCreateProfileRejectsDisabledRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	disabled := false
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox": {Enabled: &disabled},
	}})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Disabled","runtime_id":"camoufox"}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) || !strings.Contains(rec.Body.String(), `runtime \"camoufox\" is disabled`) {
		t.Fatalf("body missing disabled INVALID_RUNTIME: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after disabled runtime rejection", len(profiles))
	}
}

func TestCreateProfileRejectsInvalidBrowseForgeProxyRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	enabled := true
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Bad Region","runtime_id":"browseforge-chromium","proxy":{"type":"http","host":"proxy.example.com","port":1080,"region":"za-gauteng"}}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_PROXY_REGION"`) || !strings.Contains(rec.Body.String(), "supported presets") {
		t.Fatalf("body missing INVALID_PROXY_REGION: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after invalid proxy region rejection", len(profiles))
	}
}

func TestCreateProfileNormalizesBrowseForgeProxyRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	enabled := true
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Good Region","runtime_id":"browseforge-chromium","proxy":{"type":"http","host":"proxy.example.com","port":1080,"region":" US-NY "}}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	profiles := store.List("", "")
	if len(profiles) != 1 || profiles[0].Proxy == nil || profiles[0].Proxy.Region != "us-ny" {
		t.Fatalf("stored profiles = %+v", profiles)
	}
}

func TestUpdateProfileRejectsDisabledRuntimeID(t *testing.T) {
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
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox":     {Enabled: &disabled},
		"cloakbrowser": {Enabled: &enabled},
	}})}

	req := requestWithProfileID(http.MethodPatch, "/api/profiles/"+p.ID, p.ID, strings.NewReader(`{"runtime_id":"camoufox"}`))
	rec := httptest.NewRecorder()
	h.updateProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) || !strings.Contains(rec.Body.String(), `runtime \"camoufox\" is disabled`) {
		t.Fatalf("body missing disabled INVALID_RUNTIME: %s", rec.Body.String())
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.RuntimeID != "cloakbrowser" {
		t.Fatalf("stored runtime_id = %q, want unchanged cloakbrowser", got.RuntimeID)
	}
}

func TestUpdateProfileRejectsInvalidBrowseForgeProxyRegion(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "browseforge-chromium"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := requestWithProfileID(http.MethodPatch, "/api/profiles/"+p.ID, p.ID, strings.NewReader(`{"proxy":{"type":"http","host":"proxy.example.com","port":1080,"region":"192_0_2_1"}}`))
	rec := httptest.NewRecorder()
	h.updateProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_PROXY_REGION"`) || !strings.Contains(rec.Body.String(), "supported presets") {
		t.Fatalf("body missing INVALID_PROXY_REGION: %s", rec.Body.String())
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.Proxy != nil {
		t.Fatalf("stored proxy = %+v, want nil after rejected update", got.Proxy)
	}
}

func TestDuplicateProfileRejectsDisabledRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Disabled Runtime Source", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	disabled := false
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox": {Enabled: &disabled},
	}})}

	req := requestWithProfileID(http.MethodPost, "/api/profiles/"+p.ID+"/duplicate", p.ID, nil)
	rec := httptest.NewRecorder()
	h.duplicateProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) || !strings.Contains(rec.Body.String(), `runtime \"camoufox\" is disabled`) {
		t.Fatalf("body missing disabled INVALID_RUNTIME: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want original only after disabled runtime duplicate rejection", len(profiles))
	}
}

func TestImportProfileRejectsDisabledRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	disabled := false
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox": {Enabled: &disabled},
	}})}
	body, contentType := multipartZipUpload(t, map[string][]byte{
		"profile.json": []byte(`{"id":"legacy","name":"Legacy Import","runtime_id":"camoufox"}`),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/profiles/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.importProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) || !strings.Contains(rec.Body.String(), `runtime \"camoufox\" is disabled`) {
		t.Fatalf("body missing disabled INVALID_RUNTIME: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after disabled runtime import rejection", len(profiles))
	}
}

func TestRestoreRejectsDisabledRuntimeIDWithoutCreatingProfiles(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	existing := &profile.Profile{Name: "Existing", RuntimeID: "cloakbrowser"}
	if err := store.Create(existing); err != nil {
		t.Fatalf("Create existing profile: %v", err)
	}
	enabled := true
	disabled := false
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"camoufox":     {Enabled: &disabled},
		"cloakbrowser": {Enabled: &enabled},
	}})}
	body, contentType := multipartZipUpload(t, map[string][]byte{
		"disabled/profile.json": []byte(`{"id":"disabled","name":"Disabled Restore","runtime_id":"camoufox"}`),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.restore(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) || !strings.Contains(rec.Body.String(), `runtime \"camoufox\" is disabled`) {
		t.Fatalf("body missing disabled INVALID_RUNTIME: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 1 {
		t.Fatalf("stored profiles = %d, want original only after disabled runtime restore rejection", len(profiles))
	}
	if _, err := store.Get(existing.ID); err != nil {
		t.Fatalf("existing profile missing after rejected restore: %v", err)
	}
}

func TestCreateProfileRejectsDeprecatedEngine(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Legacy","engine":"firefox","runtime_id":"camoufox"}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"DEPRECATED_FIELD"`) {
		t.Fatalf("body missing DEPRECATED_FIELD: %s", rec.Body.String())
	}
}

func TestUpdateProfileRejectsDeprecatedEngine(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{})}

	req := requestWithProfileID(http.MethodPatch, "/api/profiles/"+p.ID, p.ID, strings.NewReader(`{"engine":"firefox"}`))
	rec := httptest.NewRecorder()
	h.updateProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"DEPRECATED_FIELD"`) {
		t.Fatalf("body missing DEPRECATED_FIELD: %s", rec.Body.String())
	}
}

func TestUpdateProfileRejectsNonStringRuntimeID(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := &profile.Profile{Name: "Runtime Profile", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h := &handler{store: store, mgr: testManagerWithRuntimeConfig(t, &config.Config{})}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "null", body: `{"runtime_id":null}`},
		{name: "number", body: `{"runtime_id":42}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithProfileID(http.MethodPut, "/api/profiles/"+p.ID, p.ID, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.updateProfile(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"code":"INVALID_RUNTIME"`) {
				t.Fatalf("body missing INVALID_RUNTIME: %s", rec.Body.String())
			}
		})
	}
}

func TestGroupProxyAPI(t *testing.T) {
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{groupStore: groupStore}

	req := requestWithGroupName(http.MethodPut, "/api/groups/Client%20A", "Client A", strings.NewReader(`{
		"proxy_mode": "enforced",
		"proxy": {"type": "socks5", "host": "proxy.example.com", "port": 1080}
	}`))
	rec := httptest.NewRecorder()
	h.upsertGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	data := result["data"].(map[string]any)
	if data["name"] != "Client A" || data["proxy_mode"] != groups.ProxyModeEnforced {
		t.Fatalf("group response = %#v", data)
	}

	req = requestWithGroupName(http.MethodDelete, "/api/groups/Client%20A/proxy", "Client A", nil)
	rec = httptest.NewRecorder()
	h.clearGroupProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d body=%s", rec.Code, rec.Body.String())
	}
	if g, ok := groupStore.Get("Client A"); ok {
		t.Fatalf("cleared group still exists = %+v", g)
	}
}

func TestGroupProxyAPIRequiresProxyOnPut(t *testing.T) {
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{groupStore: groupStore}

	req := requestWithGroupName(http.MethodPut, "/api/groups/Client%20A", "Client A", strings.NewReader(`{"proxy_mode":"default"}`))
	rec := httptest.NewRecorder()
	h.upsertGroup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "MISSING_PROXY") {
		t.Fatalf("body missing MISSING_PROXY: %s", rec.Body.String())
	}
}

func TestCreateProfileRejectsGroupProxyMissingBrowseForgeRegion(t *testing.T) {
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
	h := &handler{store: store, groupStore: groupStore, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Grouped BFC","runtime_id":"browseforge-chromium","group":"Client A"}`))
	rec := httptest.NewRecorder()
	h.createProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_PROXY_REGION"`) || !strings.Contains(rec.Body.String(), "proxy_region is required") {
		t.Fatalf("body missing INVALID_PROXY_REGION: %s", rec.Body.String())
	}
	if profiles := store.List("", ""); len(profiles) != 0 {
		t.Fatalf("stored profiles = %d, want 0 after group proxy rejection", len(profiles))
	}
}

func TestGroupProxyRejectsMissingRegionForBrowseForgeProfiles(t *testing.T) {
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
	h := &handler{store: store, groupStore: groupStore, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := requestWithGroupName(http.MethodPut, "/api/groups/Client%20A", "Client A", strings.NewReader(`{
		"proxy_mode": "enforced",
		"proxy": {"type": "http", "host": "proxy.example.com", "port": 1080}
	}`))
	rec := httptest.NewRecorder()
	h.upsertGroup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_PROXY_REGION"`) || !strings.Contains(rec.Body.String(), "proxy_region is required") {
		t.Fatalf("body missing INVALID_PROXY_REGION: %s", rec.Body.String())
	}
}

func TestUpdateProfileRejectsGroupProxyMissingBrowseForgeRegion(t *testing.T) {
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
	h := &handler{store: store, groupStore: groupStore, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := requestWithProfileID(http.MethodPatch, "/api/profiles/"+p.ID, p.ID, strings.NewReader(`{"group":"Client A"}`))
	rec := httptest.NewRecorder()
	h.updateProfile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"INVALID_PROXY_REGION"`) || !strings.Contains(rec.Body.String(), "proxy_region is required") {
		t.Fatalf("body missing INVALID_PROXY_REGION: %s", rec.Body.String())
	}
	got, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("stored profile missing: %v", err)
	}
	if got.Group != "" {
		t.Fatalf("stored group = %q, want unchanged empty group", got.Group)
	}
}

func TestGroupProxyNormalizesRegionForBrowseForgeProfiles(t *testing.T) {
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
	h := &handler{store: store, groupStore: groupStore, mgr: testManagerWithRuntimeConfig(t, &config.Config{Runtimes: map[string]config.RuntimeConfig{
		"browseforge-chromium": {Enabled: &enabled},
	}})}

	req := requestWithGroupName(http.MethodPut, "/api/groups/Client%20A", "Client A", strings.NewReader(`{
		"proxy_mode": "enforced",
		"proxy": {"type": "http", "host": "proxy.example.com", "port": 1080, "region": " TW "}
	}`))
	rec := httptest.NewRecorder()
	h.upsertGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	g, ok := groupStore.Get("Client A")
	if !ok || g.Proxy == nil || g.Proxy.Region != "tw" {
		t.Fatalf("group proxy = %+v ok=%v", g, ok)
	}
}

func TestDeleteGroupUngroupsProfilesAndClearsProxy(t *testing.T) {
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
	h := &handler{store: profileStore, groupStore: groupStore}

	req := requestWithGroupName(http.MethodDelete, "/api/groups/Client%20A", "Client A", nil)
	rec := httptest.NewRecorder()
	h.deleteGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
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
	if !strings.Contains(rec.Body.String(), `"profiles_ungrouped":1`) {
		t.Fatalf("response missing ungroup count: %s", rec.Body.String())
	}
}

func TestBackupIncludesGroupPolicies(t *testing.T) {
	profileStore, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	groupStore, err := groups.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groupStore.Upsert("Client A", &profile.ProxyConfig{Type: "socks5", Host: "proxy.example.com", Port: 1080}, groups.ProxyModeEnforced); err != nil {
		t.Fatal(err)
	}
	h := &handler{store: profileStore, groupStore: groupStore}

	rec := httptest.NewRecorder()
	h.backup(rec, httptest.NewRequest(http.MethodPost, "/api/backup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("backup status = %d body=%s", rec.Code, rec.Body.String())
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != "groups.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "proxy.example.com") {
			t.Fatalf("groups.json missing policy: %s", data)
		}
		return
	}
	t.Fatal("groups.json not found in backup")
}

func multipartZipUpload(t *testing.T, files map[string][]byte) ([]byte, string) {
	t.Helper()

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for name, data := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "profiles.zip")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write(zipBuf.Bytes()); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return body.Bytes(), mw.FormDataContentType()
}

func requestWithGroupName(method, target, name string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("name", name)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}

func requestWithProfileID(method, target, id string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
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
