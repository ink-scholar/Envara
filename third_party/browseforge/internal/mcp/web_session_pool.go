package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"browseforge/internal/browser"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

const (
	defaultSessionIdleTTL        = 5 * time.Minute
	defaultSessionSweepEvery     = 1 * time.Minute
	defaultMaxSessionsPerProfile = 10
	defaultProfileName           = "browseforge_default"
)

// SessionPool manages agent web_search/web_explore sessions.
//
// Design:
//   - browser.Manager owns one browser runtime per profile.
//   - Agent session support is selected by runtime capability, not legacy engine name.
//   - SessionPool connects to that endpoint and creates one independent Page per agent session.
//   - GC only closes per-agent pages; it never closes the profile browser.
type SessionPool struct {
	mu            sync.RWMutex
	mgr           *browser.Manager
	store         *profile.Store
	pw            *playwright.Playwright
	pools         map[string]*ProfileSessionPool // profileID -> pool
	idleTTL       time.Duration
	maxPerProfile int
}

// ProfileSessionPool holds remote Playwright state and agent pages for one profile browser.
type ProfileSessionPool struct {
	mu         sync.RWMutex
	profileID  string
	browserID  string
	connectURL string
	browser    playwright.Browser
	sessions   map[string]*WebSession // sessionID -> session
}

// WebSession represents one agent session: fixed profile + independent page.
type WebSession struct {
	mu           sync.Mutex
	ID           string
	ProfileID    string
	BrowserID    string
	Page         playwright.Page
	CreatedAt    time.Time
	LastAccessed time.Time
	Closed       bool
}

// SessionInfo is returned by list_sessions and GC diagnostics.
type SessionInfo struct {
	ID           string    `json:"id"`
	ProfileID    string    `json:"profile_id"`
	BrowserID    string    `json:"browser_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	IdleSeconds  int64     `json:"idle_seconds"`
}

// NewSessionPool creates a page-level session pool backed by browser.Manager profile browsers.
func NewSessionPool(mgr *browser.Manager, store *profile.Store) (*SessionPool, error) {
	if mgr == nil {
		return nil, fmt.Errorf("browser manager is required")
	}
	if store == nil {
		return nil, fmt.Errorf("profile store is required")
	}
	pw := mgr.Playwright()
	if pw == nil {
		return nil, fmt.Errorf("playwright driver is not available")
	}

	return &SessionPool{
		mgr:           mgr,
		store:         store,
		pw:            pw,
		pools:         make(map[string]*ProfileSessionPool),
		idleTTL:       defaultSessionIdleTTL,
		maxPerProfile: defaultMaxSessionsPerProfile,
	}, nil
}

// SweepInterval returns the recommended GC sweep interval.
func (sp *SessionPool) SweepInterval() time.Duration {
	return defaultSessionSweepEvery
}

// StartGC starts background GC and returns a function that stops it.
func (sp *SessionPool) StartGC(interval time.Duration) func() {
	if interval <= 0 {
		interval = defaultSessionSweepEvery
	}
	stop := make(chan struct{})
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				closed := sp.GC()
				if closed > 0 {
					slog.Info("web session GC completed", "closed", closed)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

// CreateSession creates a new agent page session for a runtime that supports it.
func (sp *SessionPool) CreateSession(profileID string) (*WebSession, error) {
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}
	_, pool, err := sp.ensureProfilePool(profileID)
	if err != nil {
		return nil, err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.sessions) >= sp.maxPerProfile {
		return nil, fmt.Errorf("max sessions (%d) reached for profile %s", sp.maxPerProfile, profileID)
	}

	page, err := pool.browser.NewPage()
	if err != nil {
		return nil, fmt.Errorf("create agent page: %w", err)
	}

	now := time.Now()
	s := &WebSession{
		ID:           newWebSessionID(),
		ProfileID:    profileID,
		BrowserID:    pool.browserID,
		Page:         page,
		CreatedAt:    now,
		LastAccessed: now,
	}
	pool.sessions[s.ID] = s
	slog.Info("web session created", "session", s.ID, "profile", profileID, "browser", pool.browserID)
	return s, nil
}

// GetOrCreateSession returns an existing session by sessionID, or creates a new one for profileID.
func (sp *SessionPool) GetOrCreateSession(profileID, sessionID string) (*WebSession, bool, error) {
	if sessionID != "" {
		s, err := sp.GetSession(sessionID)
		if err != nil {
			return nil, false, err
		}
		if profileID != "" && profileID != s.ProfileID {
			return nil, false, fmt.Errorf("session %s belongs to profile %s, not %s", sessionID, s.ProfileID, profileID)
		}
		return s, false, nil
	}
	if profileID == "" {
		return nil, false, fmt.Errorf("profile_id is required when session_id is not provided")
	}
	s, err := sp.CreateSession(profileID)
	return s, true, err
}

// GetSession returns an existing agent session by ID.
func (sp *SessionPool) GetSession(sessionID string) (*WebSession, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	sp.mu.RLock()
	pools := make([]*ProfileSessionPool, 0, len(sp.pools))
	for _, pool := range sp.pools {
		pools = append(pools, pool)
	}
	sp.mu.RUnlock()

	for _, pool := range pools {
		pool.mu.RLock()
		s, ok := pool.sessions[sessionID]
		pool.mu.RUnlock()
		if ok {
			return s, nil
		}
	}
	return nil, fmt.Errorf("session not found: %s", sessionID)
}

// DestroySession closes an agent page and removes it from the pool.
func (sp *SessionPool) DestroySession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	sp.mu.RLock()
	pools := make([]*ProfileSessionPool, 0, len(sp.pools))
	for _, pool := range sp.pools {
		pools = append(pools, pool)
	}
	sp.mu.RUnlock()

	for _, pool := range pools {
		pool.mu.Lock()
		s, ok := pool.sessions[sessionID]
		if ok {
			delete(pool.sessions, sessionID)
		}
		pool.mu.Unlock()
		if ok {
			s.closePage("destroy_session")
			slog.Info("web session destroyed", "session", sessionID, "profile", s.ProfileID, "browser", s.BrowserID, "reason", "destroy_session")
			return nil
		}
	}
	return fmt.Errorf("session not found: %s", sessionID)
}

// DestroyProfileSessions closes all agent pages for a profile and removes its profile pool.
// It intentionally does not close the browser.Manager-owned profile browser.
func (sp *SessionPool) DestroyProfileSessions(profileID string) int {
	if profileID == "" {
		return 0
	}

	sp.mu.Lock()
	pool, ok := sp.pools[profileID]
	if ok {
		delete(sp.pools, profileID)
	}
	sp.mu.Unlock()
	if !ok {
		return 0
	}

	closed := pool.closeAllPages("profile_sessions_destroyed")
	slog.Info("web profile sessions destroyed", "profile", profileID, "closed_sessions", closed)
	return closed
}

// ListSessions lists active agent sessions. If profileID is non-empty, only that profile is listed.
func (sp *SessionPool) ListSessions(profileID string) []SessionInfo {
	sp.mu.RLock()
	pools := make([]*ProfileSessionPool, 0, len(sp.pools))
	for id, pool := range sp.pools {
		if profileID == "" || profileID == id {
			pools = append(pools, pool)
		}
	}
	sp.mu.RUnlock()

	now := time.Now()
	infos := []SessionInfo{}
	for _, pool := range pools {
		pool.mu.RLock()
		for _, s := range pool.sessions {
			s.mu.Lock()
			info := SessionInfo{
				ID:           s.ID,
				ProfileID:    s.ProfileID,
				BrowserID:    s.BrowserID,
				CreatedAt:    s.CreatedAt,
				LastAccessed: s.LastAccessed,
				IdleSeconds:  int64(now.Sub(s.LastAccessed).Seconds()),
			}
			s.mu.Unlock()
			infos = append(infos, info)
		}
		pool.mu.RUnlock()
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].CreatedAt.Before(infos[j].CreatedAt) })
	return infos
}

// GC closes idle pages and enforces the per-profile session cap.
func (sp *SessionPool) GC() int {
	sp.mu.RLock()
	pools := make([]*ProfileSessionPool, 0, len(sp.pools))
	for _, pool := range sp.pools {
		pools = append(pools, pool)
	}
	sp.mu.RUnlock()

	closed := 0
	now := time.Now()
	for _, pool := range pools {
		type closeCandidate struct {
			session *WebSession
			reason  string
			idle    time.Duration
		}
		var toClose []closeCandidate
		pool.mu.Lock()
		for id, s := range pool.sessions {
			s.mu.Lock()
			idle := now.Sub(s.LastAccessed)
			s.mu.Unlock()
			if idle >= sp.idleTTL {
				delete(pool.sessions, id)
				toClose = append(toClose, closeCandidate{session: s, reason: "idle_ttl", idle: idle})
			}
		}
		if len(pool.sessions) > sp.maxPerProfile {
			remaining := make([]*WebSession, 0, len(pool.sessions))
			for _, s := range pool.sessions {
				remaining = append(remaining, s)
			}
			sort.Slice(remaining, func(i, j int) bool { return remaining[i].CreatedAt.Before(remaining[j].CreatedAt) })
			over := len(pool.sessions) - sp.maxPerProfile
			for i := 0; i < over; i++ {
				s := remaining[i]
				delete(pool.sessions, s.ID)
				toClose = append(toClose, closeCandidate{session: s, reason: "max_sessions"})
			}
		}
		pool.mu.Unlock()

		for _, c := range toClose {
			c.session.closePage("gc_" + c.reason)
			slog.Info("web session GC closed session", "session", c.session.ID, "profile", c.session.ProfileID, "browser", c.session.BrowserID, "reason", c.reason, "idle_seconds", int64(c.idle.Seconds()))
			closed++
		}
	}
	return closed
}

// CloseAll closes all agent pages and drops SessionPool metadata.
// It never closes browser.Manager browser sessions or connected browser handles.
// Playwright Go exposes Browser.Close() on Bind-connected handles, but Close may
// close the remote profile browser itself; until a safe non-closing disconnect
// API is available/verified, SessionPool only drops those non-owning handles.
func (sp *SessionPool) CloseAll() {
	sp.mu.Lock()
	pools := make([]*ProfileSessionPool, 0, len(sp.pools))
	for _, pool := range sp.pools {
		pools = append(pools, pool)
	}
	sp.pools = make(map[string]*ProfileSessionPool)
	sp.mu.Unlock()

	for _, pool := range pools {
		pool.closeAllPages("session_pool_close_all")
	}
	slog.Info("web session pool closed", "closed_sessions", len(pools))
}

func (pool *ProfileSessionPool) closeAllPages(reason string) int {
	pool.mu.Lock()
	sessions := make([]*WebSession, 0, len(pool.sessions))
	for _, s := range pool.sessions {
		sessions = append(sessions, s)
	}
	pool.sessions = make(map[string]*WebSession)
	pool.browser = nil
	pool.mu.Unlock()

	for _, s := range sessions {
		s.closePage(reason)
	}
	return len(sessions)
}

func (sp *SessionPool) ensureProfilePool(profileID string) (*profile.Profile, *ProfileSessionPool, error) {
	p, err := sp.store.Get(profileID)
	if err != nil {
		return nil, nil, err
	}
	desc, err := sp.mgr.RuntimeRegistry().ResolveProfile(p)
	if err != nil {
		return nil, nil, err
	}
	if !desc.Capabilities.SupportsAgentWebSessions || !desc.Capabilities.SupportsPlaywrightBind {
		return nil, nil, fmt.Errorf("profile %s runtime %s does not support agent web sessions", profileID, desc.ID)
	}

	browserSession, ok := sp.mgr.GetSession("sess_" + profileID)
	if !ok {
		browserSession, err = sp.mgr.LaunchSession(p)
		if err != nil {
			return nil, nil, fmt.Errorf("launch profile browser: %w", err)
		}
	}
	if browserSession.RuntimeID != "" && browserSession.RuntimeID != string(desc.ID) {
		return nil, nil, fmt.Errorf("browser session %s runtime %s does not match profile runtime %s", browserSession.ID, browserSession.RuntimeID, desc.ID)
	}
	if browserSession.ConnectURL == "" {
		return nil, nil, fmt.Errorf("browser session %s has no Playwright bind endpoint", browserSession.ID)
	}

	sp.mu.RLock()
	pool, ok := sp.pools[profileID]
	if ok && pool.connectURL == browserSession.ConnectURL && pool.browser != nil {
		sp.mu.RUnlock()
		return p, pool, nil
	}
	sp.mu.RUnlock()

	sp.mu.Lock()
	pool, ok = sp.pools[profileID]
	if ok && pool.connectURL == browserSession.ConnectURL && pool.browser != nil {
		sp.mu.Unlock()
		return p, pool, nil
	}
	oldPool := pool
	// Do not call pool.browser.Close() here: with a Playwright Bind connection,
	// Close may close the remote profile browser owned by browser.Manager.
	// Playwright Go does not currently provide a verified non-closing disconnect
	// path for this handle in BrowseForge, so dropping the handle is safer;
	// GC/CloseAll only close agent pages.

	pw := sp.mgr.Playwright()
	if pw == nil {
		sp.mu.Unlock()
		return nil, nil, fmt.Errorf("playwright driver is not available")
	}
	connected, err := pw.Chromium.Connect(browserSession.ConnectURL)
	if err != nil {
		sp.mu.Unlock()
		return nil, nil, fmt.Errorf("connect to profile browser bind endpoint: %w", err)
	}
	pool = &ProfileSessionPool{
		profileID:  profileID,
		browserID:  browserSession.ID,
		connectURL: browserSession.ConnectURL,
		browser:    connected,
		sessions:   make(map[string]*WebSession),
	}
	sp.pools[profileID] = pool
	sp.mu.Unlock()
	if oldPool != nil {
		closed := oldPool.closeAllPages("profile_pool_replaced")
		if closed > 0 {
			slog.Info("old web profile pool closed", "profile", profileID, "closed_sessions", closed)
		}
	}
	slog.Info("web profile pool connected", "profile", profileID, "browser", browserSession.ID)
	return p, pool, nil
}

func (s *WebSession) closePage(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Closed = true
	if s.Page != nil {
		if err := s.Page.Close(); err != nil {
			slog.Warn("web session page close failed", "session", s.ID, "profile", s.ProfileID, "browser", s.BrowserID, "reason", reason, "error", err)
		} else {
			slog.Info("web session page closed", "session", s.ID, "profile", s.ProfileID, "browser", s.BrowserID, "reason", reason)
		}
		s.Page = nil
	}
}

func (s *WebSession) ensurePageOpenLocked() error {
	if s.Closed || s.Page == nil {
		return fmt.Errorf("session is closed: %s", s.ID)
	}
	return nil
}

// GetOrCreateDefaultProfile returns the profile ID of the system default profile.
// The default is named "browseforge_default" and must use an enabled Chromium
// runtime with agent web session and Playwright bind support.
func (sp *SessionPool) GetOrCreateDefaultProfile() (string, error) {
	if sp == nil || sp.store == nil || sp.mgr == nil {
		return "", fmt.Errorf("session pool is not initialized")
	}

	sp.mu.Lock()
	defer sp.mu.Unlock()

	for _, p := range sp.store.List("", "") {
		if p.Name != defaultProfileName {
			continue
		}
		if err := sp.validateDefaultProfileRuntime(p); err != nil {
			return "", err
		}
		return p.ID, nil
	}

	runtimeID := sp.findAgentCapableRuntime()
	if runtimeID == "" {
		return "", fmt.Errorf("no enabled Chromium runtime with agent web session and Playwright bind support is available; cannot create default profile")
	}

	p := &profile.Profile{
		Name:      defaultProfileName,
		RuntimeID: runtimeID,
	}
	if _, err := sp.mgr.RuntimeRegistry().ApplyProfileDefaults(p); err != nil {
		return "", fmt.Errorf("apply defaults for default profile: %w", err)
	}
	if err := sp.store.Create(p); err != nil {
		return "", fmt.Errorf("create default profile: %w", err)
	}
	slog.Info("created system default profile", "id", p.ID, "name", defaultProfileName, "runtime", runtimeID)
	return p.ID, nil
}

func (sp *SessionPool) validateDefaultProfileRuntime(p *profile.Profile) error {
	if p == nil {
		return fmt.Errorf("default profile %q is invalid: profile is nil", defaultProfileName)
	}
	reg := sp.mgr.RuntimeRegistry()
	if reg == nil {
		return fmt.Errorf("default profile %q (%s) cannot be validated: runtime registry is not configured", defaultProfileName, p.ID)
	}
	desc, err := reg.ResolveProfile(p)
	if err != nil {
		return fmt.Errorf("default profile %q (%s) has invalid runtime %q: %w", defaultProfileName, p.ID, p.RuntimeID, err)
	}
	if !runtimeSupportsDefaultAgentSessions(desc) {
		return fmt.Errorf("default profile %q (%s) runtime %s is not an enabled Chromium runtime with agent web session and Playwright bind support", defaultProfileName, p.ID, desc.ID)
	}
	return nil
}

// findAgentCapableRuntime returns the first enabled Chromium runtime ID that
// supports agent web sessions. Priority: browseforge-chromium > cloakbrowser.
func (sp *SessionPool) findAgentCapableRuntime() string {
	reg := sp.mgr.RuntimeRegistry()
	if reg == nil {
		return ""
	}
	for _, id := range []bfruntime.ID{bfruntime.BrowseForgeChromium, bfruntime.CloakBrowser} {
		desc, ok := reg.Get(id)
		if ok && runtimeSupportsDefaultAgentSessions(desc) {
			return string(desc.ID)
		}
	}
	return ""
}

func runtimeSupportsDefaultAgentSessions(desc bfruntime.Descriptor) bool {
	return desc.Enabled &&
		desc.Family == bfruntime.FamilyChromium &&
		desc.Capabilities.SupportsAgentWebSessions &&
		desc.Capabilities.SupportsPlaywrightBind
}

func newWebSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess_search_%d", time.Now().UnixNano())
	}
	return "sess_search_" + hex.EncodeToString(b)
}
