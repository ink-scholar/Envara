package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"browseforge/internal/profile"
	"github.com/playwright-community/playwright-go"
)

var ErrSessionLinkChanged = errors.New("selected browser launch or route has changed")

// Unicode case mapping differs between Go and JavaScript. Fold only ASCII in
// this shared digest contract, preserving the other host bytes exactly.
func sessionRouteDigestHost(host string) string {
	value := []byte(strings.Trim(host, "[]"))
	for i, character := range value {
		if character >= 'A' && character <= 'Z' {
			value[i] = character + ('a' - 'A')
		}
	}
	return string(value)
}

// SessionRouteDigest binds a launch to its effective proxy without publishing
// credentials. The length-prefixed UTF-8 contract is shared with the desktop.
func SessionRouteDigest(proxy *profile.ProxyConfig) string {
	fields := []string{"direct", "", "0", "", ""}
	if proxy != nil {
		fields = []string{strings.ToLower(proxy.Type), sessionRouteDigestHost(proxy.Host), strconv.Itoa(proxy.Port), proxy.Username, proxy.Password}
	}
	h := sha256.New()
	h.Write([]byte("envara-browser-route-v1\x00"))
	for _, field := range fields {
		fmt.Fprintf(h, "%d:", len([]byte(field)))
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type SessionLinkIdentity struct {
	InstanceID  string `json:"instance_id"`
	RouteDigest string `json:"route_digest"`
}

// LinkIdentity is private authenticated control data, never a profile/export.
func (m *Manager) LinkIdentity(id string) (SessionLinkIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.sessions[id]
	if m.closing {
		return SessionLinkIdentity{}, ErrManagerClosing
	}
	if s == nil || s.closed.Load() || s.InstanceID == "" || s.routeDigest == "" {
		return SessionLinkIdentity{}, ErrSessionLinkChanged
	}
	return SessionLinkIdentity{InstanceID: s.InstanceID, RouteDigest: s.routeDigest}, nil
}

// NewSessionLinkPage captures one exact launch under the registry lock, then
// operates on that context only. Close/relaunch can fail this operation, but a
// reused session ID can never redirect it into the replacement context.
func (m *Manager) NewSessionLinkPage(id, instanceID, routeDigest string) (playwright.Page, error) {
	m.mu.RLock()
	s := m.sessions[id]
	closing := m.closing
	valid := s != nil && !s.closed.Load() && s.Context != nil && instanceID != "" && routeDigest != "" && s.InstanceID == instanceID && s.routeDigest == routeDigest
	m.mu.RUnlock()
	if closing {
		return nil, ErrManagerClosing
	}
	if !valid {
		return nil, ErrSessionLinkChanged
	}
	page, err := s.Context.NewPage()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	valid = !m.closing && m.sessions[id] == s && !s.closed.Load()
	if valid {
		s.Page = page
	}
	m.mu.Unlock()
	if !valid {
		_ = page.Close()
		return nil, ErrSessionLinkChanged
	}
	return page, nil
}
