package browser

import (
	"context"
	"errors"
	"time"

	"github.com/playwright-community/playwright-go"
)

var ErrRuntimeVerificationUnsupported = errors.New("background observation unavailable for this runtime")

func runtimeTargetInfo(session playwright.CDPSession) (map[string]any, error) {
	value, err := session.Send("Target.getTargetInfo", nil)
	if err != nil {
		return nil, err
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, ErrSessionLinkChanged
	}
	info, ok := result["targetInfo"].(map[string]any)
	if !ok {
		return nil, ErrSessionLinkChanged
	}
	return info, nil
}

// NewRuntimeVerificationPage owns one blank page in the exact running context.
// It deliberately does not change Session.Page or focus the new page. The caller
// must close only this page, including on timeout and cancellation.
func (m *Manager) NewRuntimeVerificationPage(id, instanceID, routeDigest string, contexts ...context.Context) (playwright.Page, error) {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	s := m.sessions[id]
	closing := m.closing
	valid := s != nil && !s.closed.Load() && s.Context != nil && instanceID != "" && routeDigest != "" && s.InstanceID == instanceID && s.routeDigest == routeDigest && routeDigest != SessionRouteDigest(nil)
	m.mu.RUnlock()
	if closing {
		return nil, ErrManagerClosing
	}
	if !valid {
		return nil, ErrSessionLinkChanged
	}
	if s.RuntimeID != "cloakbrowser" && s.RuntimeID != "browseforge-chromium" {
		return nil, ErrRuntimeVerificationUnsupported
	}
	var existing playwright.Page
	knownPages := make(map[playwright.Page]bool)
	for _, page := range s.Context.Pages() {
		knownPages[page] = true
		if existing == nil && !page.IsClosed() {
			existing = page
		}
	}
	if existing == nil {
		return nil, ErrSessionLinkChanged
	}
	control, err := s.Context.NewCDPSession(existing)
	if err != nil {
		return nil, ErrRuntimeVerificationUnsupported
	}
	defer control.Detach()
	info, err := runtimeTargetInfo(control)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := map[string]any{"url": "about:blank", "background": true}
	if contextID, ok := info["browserContextId"].(string); ok && contextID != "" {
		args["browserContextId"] = contextID
	}
	created, err := control.Send("Target.createTarget", args)
	if err != nil {
		return nil, err
	}
	result, ok := created.(map[string]any)
	if !ok {
		return nil, ErrSessionLinkChanged
	}
	targetID, ok := result["targetId"].(string)
	if !ok || targetID == "" {
		return nil, ErrSessionLinkChanged
	}
	transferred := false
	defer func() {
		// Creation returns the exact owned target ID. Even if page attachment
		// times out, only that target is closed, never a list-difference guess.
		if !transferred {
			_, _ = control.Send("Target.closeTarget", map[string]any{"targetId": targetID})
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m.mu.RLock()
		valid = !m.closing && m.sessions[id] == s && !s.closed.Load()
		m.mu.RUnlock()
		if !valid {
			return nil, ErrSessionLinkChanged
		}
		for _, page := range s.Context.Pages() {
			if knownPages[page] || page.IsClosed() {
				continue
			}
			candidate, err := s.Context.NewCDPSession(page)
			if err != nil {
				continue
			}
			pageInfo, err := runtimeTargetInfo(candidate)
			_ = candidate.Detach()
			if err != nil || pageInfo["targetId"] != targetID {
				continue
			}
			m.mu.RLock()
			valid = !m.closing && m.sessions[id] == s && !s.closed.Load()
			m.mu.RUnlock()
			if !valid {
				return nil, ErrSessionLinkChanged
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			transferred = true
			return page, nil
		}
		if time.Now().After(deadline) {
			return nil, ErrSessionLinkChanged
		}
		time.Sleep(20 * time.Millisecond)
	}
}
