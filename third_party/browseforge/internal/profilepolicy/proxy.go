// Package profilepolicy contains the shared profile rules used by REST and
// MCP. Wire decoding, response shapes and browser admission stay with their
// existing owners; these helpers never start or stop a session.
package profilepolicy

import (
	"fmt"
	"strings"

	"browseforge/internal/browser"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

// ValidateProxyRegion preserves the normalized value on an accepted profile or
// group draft, and preserves the caller's original value on every refusal.
func ValidateProxyRegion(runtimeID bfruntime.ID, proxy *profile.ProxyConfig) error {
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

// ValidateProfileProxy accepts each adapter's resolver so its legacy fallback
// host handling stays unchanged. Resolution runs after the explicit proxy has
// been validated and normalized; inherited configuration is checked on a copy.
func ValidateProfileProxy(runtimeID bfruntime.ID, p *profile.Profile, resolve func(*profile.Profile) groups.EffectiveProxy) error {
	if runtimeID != bfruntime.BrowseForgeChromium || p == nil {
		return nil
	}
	if p.Proxy != nil {
		if err := ValidateProxyRegion(runtimeID, p.Proxy); err != nil {
			return err
		}
	}
	effective := resolve(p)
	if effective.Proxy == nil || effective.Source == "profile" {
		return nil
	}
	proxy := *effective.Proxy
	return ValidateProxyRegion(runtimeID, &proxy)
}

func ValidateGroupProxyRegion(groupName string, proxy *profile.ProxyConfig, store *profile.Store, manager *browser.Manager) error {
	if proxy == nil || store == nil || manager == nil {
		return nil
	}
	for _, p := range store.List(groupName, "") {
		draft := *p
		desc, err := manager.RuntimeRegistry().ApplyProfileDefaults(&draft)
		if err == nil && desc.ID == bfruntime.BrowseForgeChromium {
			return ValidateProxyRegion(desc.ID, proxy)
		}
	}
	return nil
}

func ActiveSessionsForGroup(groupName string, store *profile.Store, manager *browser.Manager) int {
	groupName = strings.TrimSpace(groupName)
	if manager == nil || store == nil || groupName == "" {
		return 0
	}
	count := 0
	for _, session := range manager.ListSessions() {
		p, err := store.Get(session.ProfileID)
		if err == nil && strings.TrimSpace(p.Group) == groupName {
			count++
		}
	}
	return count
}
