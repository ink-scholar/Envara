package runtime

import (
	"fmt"
	goruntime "runtime"
	"sort"

	"browseforge/internal/config"
	"browseforge/internal/profile"
)

// ID identifies a concrete browser runtime provider.
type ID string

const (
	Camoufox            ID = "camoufox"
	CloakBrowser        ID = "cloakbrowser"
	BrowseForgeChromium ID = "browseforge-chromium"
)

// Family identifies the browser engine family exposed by a runtime.
type Family string

const (
	FamilyFirefox  Family = "firefox"
	FamilyChromium Family = "chromium"
)

// Capabilities describe integration-level behavior that callers should check
// instead of hard-coding runtime IDs or legacy engine strings.
type Capabilities struct {
	Family                    Family `json:"family"`
	SupportsPersistentContext bool   `json:"supports_persistent_context"`
	SupportsPlaywrightBind    bool   `json:"supports_playwright_bind"`
	SupportsAgentWebSessions  bool   `json:"supports_agent_web_sessions"`
	SupportsSeedFingerprint   bool   `json:"supports_seed_fingerprint"`
	SupportsStructuredConfig  bool   `json:"supports_structured_config"`
	SupportsNativeProxy       bool   `json:"supports_native_proxy"`
	SupportsWebRTCMasking     bool   `json:"supports_webrtc_masking"`
	RequiresExternalBinary    bool   `json:"requires_external_binary"`
}

// Descriptor is the stable, serializable runtime metadata exposed to API, MCP,
// dashboard, and future installer/probe surfaces.
type Descriptor struct {
	ID                 ID           `json:"id"`
	DisplayName        string       `json:"display_name"`
	Family             Family       `json:"family"`
	FingerprintPoolKey string       `json:"fingerprint_pool_key,omitempty"`
	BinaryPath         string       `json:"binary_path,omitempty"`
	Enabled            bool         `json:"enabled"`
	PlatformSupported  bool         `json:"platform_supported"`
	UnsupportedReason  string       `json:"unsupported_reason,omitempty"`
	Capabilities       Capabilities `json:"capabilities"`
}

// Registry resolves runtime IDs to concrete runtime descriptors.
type Registry struct {
	byID      map[ID]Descriptor
	defaultID ID
}

func platformSupported(id ID, goos, goarch string) (bool, string) {
	support := RuntimeSupportFor(string(id), goos, goarch)
	return support.PlatformSupported, support.UnsupportedReason
}

func applyPlatformSupport(desc Descriptor) Descriptor {
	desc.PlatformSupported, desc.UnsupportedReason = platformSupported(desc.ID, goruntime.GOOS, goruntime.GOARCH)
	if !desc.PlatformSupported {
		desc.Enabled = false
		desc.BinaryPath = ""
	}
	return desc
}

// NewRegistry builds the default BrowseForge runtime registry from the v2
// runtimes config map.
func NewRegistry(cfg *config.Config) *Registry {
	if cfg == nil {
		cfg = &config.Config{}
	}
	camoufox := Descriptor{
		ID:                 Camoufox,
		DisplayName:        "Camoufox",
		Family:             FamilyFirefox,
		BinaryPath:         runtimeBinaryPath(cfg, Camoufox),
		Enabled:            false,
		FingerprintPoolKey: "firefox",
		Capabilities: Capabilities{
			Family:                    FamilyFirefox,
			SupportsPersistentContext: true,
			SupportsPlaywrightBind:    true,
			SupportsStructuredConfig:  true,
			SupportsNativeProxy:       true,
			SupportsWebRTCMasking:     true,
			RequiresExternalBinary:    true,
		},
	}
	cloak := Descriptor{
		ID:          CloakBrowser,
		DisplayName: "CloakBrowser",
		Family:      FamilyChromium,
		BinaryPath:  runtimeBinaryPath(cfg, CloakBrowser),
		Enabled:     false,
		Capabilities: Capabilities{
			Family:                    FamilyChromium,
			SupportsPersistentContext: true,
			SupportsPlaywrightBind:    true,
			SupportsAgentWebSessions:  true,
			SupportsSeedFingerprint:   true,
			SupportsNativeProxy:       true,
			SupportsWebRTCMasking:     true,
			RequiresExternalBinary:    true,
		},
	}
	browseForgeChromium := Descriptor{
		ID:          BrowseForgeChromium,
		DisplayName: "BrowseForge Chromium",
		Family:      FamilyChromium,
		BinaryPath:  runtimeBinaryPath(cfg, BrowseForgeChromium),
		Enabled:     false,
		Capabilities: Capabilities{
			Family:                    FamilyChromium,
			SupportsPersistentContext: true,
			SupportsPlaywrightBind:    true,
			SupportsAgentWebSessions:  true,
			SupportsSeedFingerprint:   true,
			SupportsStructuredConfig:  true,
			SupportsNativeProxy:       true,
			SupportsWebRTCMasking:     true,
			RequiresExternalBinary:    true,
		},
	}
	reg := &Registry{
		byID: map[ID]Descriptor{
			BrowseForgeChromium: applyPlatformSupport(applyRuntimeConfig(browseForgeChromium, cfg.Runtimes[string(BrowseForgeChromium)])),
			Camoufox:            applyPlatformSupport(applyRuntimeConfig(camoufox, cfg.Runtimes[string(Camoufox)])),
			CloakBrowser:        applyPlatformSupport(applyRuntimeConfig(cloak, cfg.Runtimes[string(CloakBrowser)])),
		},
		defaultID: Camoufox,
	}
	if cfg.DefaultRuntimeID != "" {
		if id, err := reg.ResolveID(cfg.DefaultRuntimeID); err == nil {
			reg.defaultID = id
		}
	}
	if desc, ok := reg.byID[reg.defaultID]; !ok || !desc.Enabled {
		for _, id := range []ID{BrowseForgeChromium, Camoufox, CloakBrowser} {
			if candidate := reg.byID[id]; candidate.Enabled {
				reg.defaultID = id
				break
			}
		}
	}
	return reg
}

func runtimeBinaryPath(cfg *config.Config, id ID) string {
	if cfg == nil || cfg.Runtimes == nil {
		return ""
	}
	return cfg.Runtimes[string(id)].BinaryPath
}

func applyRuntimeConfig(desc Descriptor, raw config.RuntimeConfig) Descriptor {
	if raw.DisplayName != "" {
		desc.DisplayName = raw.DisplayName
	}
	if raw.BinaryPath != "" {
		desc.BinaryPath = raw.BinaryPath
	}
	if raw.Family != "" {
		desc.Family = Family(raw.Family)
		desc.Capabilities.Family = desc.Family
	}
	if raw.Enabled != nil {
		desc.Enabled = *raw.Enabled
	} else if raw.BinaryPath != "" {
		desc.Enabled = true
	}
	return desc
}

func (r *Registry) List() []Descriptor {
	if r == nil {
		return nil
	}
	out := make([]Descriptor, 0, len(r.byID))
	for _, desc := range r.byID {
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) DefaultID() ID {
	if r == nil {
		return ""
	}
	return r.defaultID
}

func (r *Registry) Get(id ID) (Descriptor, bool) {
	if r == nil {
		return Descriptor{}, false
	}
	desc, ok := r.byID[id]
	return desc, ok
}

func (r *Registry) ResolveID(runtimeID string) (ID, error) {
	if r == nil {
		return "", fmt.Errorf("runtime registry is not configured")
	}
	if runtimeID == "" {
		return "", fmt.Errorf("runtime_id is required")
	}
	id := ID(runtimeID)
	if _, ok := r.byID[id]; !ok {
		return "", fmt.Errorf("unsupported runtime_id %q", runtimeID)
	}
	return id, nil
}

func (r *Registry) ResolveProfile(p *profile.Profile) (Descriptor, error) {
	if p == nil {
		return Descriptor{}, fmt.Errorf("profile is nil")
	}
	id, err := r.ResolveID(p.RuntimeID)
	if err != nil {
		return Descriptor{}, err
	}
	desc, ok := r.Get(id)
	if !ok {
		return Descriptor{}, fmt.Errorf("runtime %q is not registered", id)
	}
	return desc, nil
}

// ApplyProfileDefaults validates and normalizes the concrete v2 runtime_id.
func (r *Registry) ApplyProfileDefaults(p *profile.Profile) (Descriptor, error) {
	desc, err := r.ResolveProfile(p)
	if err != nil {
		return Descriptor{}, err
	}
	p.RuntimeID = string(desc.ID)
	return desc, nil
}
