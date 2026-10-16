package browser

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"browseforge/internal/config"
	"browseforge/internal/groups"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"

	"github.com/mxschmitt/playwright-go"
)

// Session represents a running browser profile
type Session struct {
	ID             string
	ProfileID      string
	RuntimeID      string
	Browser        playwright.Browser
	Context        playwright.BrowserContext
	Page           playwright.Page
	relay          *SOCKS5Relay
	ConnectURL     string // Bind endpoint for external Playwright clients
	ProfileDir     string
	UserDataDir    string
	ExecutablePath string
	Privacy        *PrivacyState
	closed         atomic.Bool
	resourcesOnce  sync.Once
}

var ErrSessionNotFound = errors.New("session not found")
var ErrManagerClosing = errors.New("browser manager is closing")

// Manager handles browser instances (multi-instance: one process per profile)
type Manager struct {
	cfg                     *config.Config
	groupStore              *groups.Store
	runtimes                *bfruntime.Registry
	pw                      *playwright.Playwright
	mu                      sync.RWMutex
	driverMu                sync.RWMutex
	sessions                map[string]*Session // sessionID → Session
	profileLocks            map[string]*sync.Mutex
	operations              sync.WaitGroup
	activeOperations        int
	closing                 bool
	closeDone               chan struct{}
	launchProfileOverride   func(*profile.Profile) (*Session, error)
	endpointHealthTimeoutMS float64
	bindSessionEndpoint     func(*Session) (string, error)
	endpointHealthCheck     func(string, float64) error
}

// InstallPlaywrightDriver installs the Playwright control driver without
// downloading Playwright-managed browsers. BrowseForge manages browser binaries
// separately, but the Go client still needs playwright-core and Node.js to
// connect to those browsers.
func InstallPlaywrightDriver() error {
	return playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})
}

func startPlaywrightDriver(install func() error, run func() (*playwright.Playwright, error)) (*playwright.Playwright, error) {
	// Envara prepares and verifies its read-only driver bundle when packaging.
	// Run still checks the installed version before starting the driver and
	// refuses missing or incompatible resources without downloading replacements.
	// Standalone BrowseForge keeps its existing install-on-start behavior.
	if os.Getenv("ENVARA_DESKTOP_BUNDLED_DRIVER") != "1" {
		if err := install(); err != nil {
			return nil, fmt.Errorf("playwright.Install: %w", err)
		}
	}

	pw, err := run()
	if err != nil {
		return nil, fmt.Errorf("playwright.Run: %w", err)
	}
	return pw, nil
}

func NewManager(cfg *config.Config, groupStores ...*groups.Store) (*Manager, error) {
	pw, err := startPlaywrightDriver(InstallPlaywrightDriver, func() (*playwright.Playwright, error) {
		return playwright.Run()
	})
	if err != nil {
		return nil, err
	}

	var groupStore *groups.Store
	if len(groupStores) > 0 {
		groupStore = groupStores[0]
	}
	m := &Manager{
		cfg:                     cfg,
		groupStore:              groupStore,
		runtimes:                bfruntime.NewRegistry(cfg),
		pw:                      pw,
		sessions:                make(map[string]*Session),
		endpointHealthTimeoutMS: defaultEndpointHealthTimeoutMS,
	}
	slog.Info("session recovery: starting clean")
	return m, nil
}

// Playwright returns the underlying Playwright driver instance.
// Used by integration components that need to reuse the same Playwright process.
func (m *Manager) Playwright() *playwright.Playwright {
	m.driverMu.RLock()
	defer m.driverMu.RUnlock()
	return m.pw
}

func (m *Manager) RuntimeRegistry() *bfruntime.Registry {
	return m.runtimes
}

func (m *Manager) LaunchSession(p *profile.Profile) (*Session, error) {
	if p == nil {
		return nil, fmt.Errorf("profile is nil")
	}
	if err := validateManagedProxyLaunch(p); err != nil {
		return nil, err
	}
	release, err := m.reserveProfile(p.ID)
	if err != nil {
		return nil, err
	}
	defer release()

	for _, s := range m.ListSessions() {
		if s.ProfileID != p.ID {
			continue
		}
		m.driverMu.RLock()
		healthErr := m.validateSessionEndpoint(p, s, "existing")
		m.driverMu.RUnlock()
		if healthErr == nil && !s.closed.Load() {
			m.mu.RLock()
			closing := m.closing
			m.mu.RUnlock()
			if closing {
				return nil, ErrManagerClosing
			}
			return s, nil
		} else {
			slog.Warn("session endpoint unhealthy; closing stale session", "session", s.ID, "profile", p.ID, "runtime_id", s.RuntimeID, "connectURL", s.ConnectURL, "error", healthErr)
			m.removeSession(s)
			m.closeSessionResources(s, "stale endpoint")
		}
	}

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		m.driverMu.RLock()
		var session *Session
		var err error
		if m.launchProfileOverride != nil {
			session, err = m.launchProfileOverride(p)
		} else {
			session, err = m.launchProfile(p)
		}
		if err == nil {
			if session != nil {
				m.observeSession(session)
			}
			err = m.prepareSessionEndpoint(p, session, attempt)
		}
		m.driverMu.RUnlock()
		if err == nil {
			m.mu.Lock()
			if m.closing || session.closed.Load() || m.liveSessionPageLocked(session) == nil {
				closing := m.closing
				m.mu.Unlock()
				m.closeSessionResources(session, "launch closed before registration")
				if closing {
					return nil, ErrManagerClosing
				}
				return nil, codedError{code: "BROWSER_PROCESS_EXITED", err: fmt.Errorf("browser closed during launch")}
			}
			if m.sessions == nil {
				m.sessions = make(map[string]*Session)
			}
			m.sessions[session.ID] = session
			m.mu.Unlock()
			slog.Info("session launched", "session", session.ID, "profile", p.ID, "runtime_id", session.RuntimeID, "connectURL", session.ConnectURL, "profileDir", session.ProfileDir, "userDataDir", session.UserDataDir, "executablePath", session.ExecutablePath)
			return session, nil
		}

		lastErr = err
		if session != nil {
			m.closeSessionResources(session, "failed launch attempt")
		}
		if attempt == 1 && shouldRetryLaunchAttempt(err) {
			slog.Warn("browser launch endpoint failed; retrying", "profile", p.ID, "runtime_id", p.RuntimeID, "attempt", attempt, "code", ErrorCode(err), "error", err)
			if restartErr := m.restartPlaywright(); restartErr != nil {
				return nil, fmt.Errorf("%w; playwright restart failed: %v", err, restartErr)
			}
			continue
		}
		break
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("launch session failed")
}

// reserveProfile serializes changes to one profile while allowing other browser
// operations to progress. Add happens under mu before shutdown starts waiting.
func (m *Manager) reserveProfile(profileID string) (func(), error) {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return nil, ErrManagerClosing
	}
	if m.profileLocks == nil {
		m.profileLocks = make(map[string]*sync.Mutex)
	}
	lock := m.profileLocks[profileID]
	if lock == nil {
		lock = &sync.Mutex{}
		m.profileLocks[profileID] = lock
	}
	m.activeOperations++
	m.operations.Add(1)
	m.mu.Unlock()
	lock.Lock()
	release := func() {
		lock.Unlock()
		m.mu.Lock()
		m.activeOperations--
		m.mu.Unlock()
		m.operations.Done()
	}
	m.mu.RLock()
	closing := m.closing
	m.mu.RUnlock()
	if closing {
		release()
		return nil, ErrManagerClosing
	}
	return release, nil
}

func (m *Manager) removeSession(session *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[session.ID] != session {
		return false
	}
	delete(m.sessions, session.ID)
	return true
}

func (m *Manager) observeSession(session *Session) {
	if session.Context == nil {
		return
	}
	session.Context.OnClose(func(playwright.BrowserContext) {
		session.closed.Store(true)
		// Never wait for a profile reservation on the Playwright event thread.
		go m.removeClosedSession(session)
	})
	watchPage := func(page playwright.Page) {
		page.OnClose(func(playwright.Page) {
			go m.handlePageClose(session)
		})
	}
	session.Context.OnPage(watchPage)
	for _, page := range session.Context.Pages() {
		watchPage(page)
	}
}

// handlePageClose also handles macOS browsers that keep their process alive
// after the final window is closed. Only a context with no live tabs is stopped.
func (m *Manager) handlePageClose(session *Session) {
	release, err := m.reserveProfile(session.ProfileID)
	if err != nil {
		return
	}
	defer release()
	m.mu.Lock()
	if m.sessions[session.ID] != session {
		m.mu.Unlock()
		return
	}
	if m.liveSessionPageLocked(session) != nil {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, session.ID)
	m.mu.Unlock()
	m.closeSessionResources(session, "last browser page closed")
}

func (m *Manager) removeClosedSession(session *Session) {
	release, err := m.reserveProfile(session.ProfileID)
	if err != nil {
		return
	}
	defer release()
	if !m.removeSession(session) {
		return
	}
	m.closeSessionResources(session, "browser context closed")
	slog.Info("session context closed", "session", session.ID, "profile", session.ProfileID)
}

func (m *Manager) launchProfile(p *profile.Profile) (*Session, error) {
	if err := validateManagedProxyLaunch(p); err != nil {
		return nil, err
	}
	desc, err := m.runtimes.ResolveProfile(p)
	if err != nil {
		return nil, err
	}
	if !desc.Enabled {
		return nil, fmt.Errorf("runtime %q is disabled", desc.ID)
	}
	switch desc.ID {
	case bfruntime.CloakBrowser, bfruntime.BrowseForgeChromium:
		return m.launchChromium(p)
	case bfruntime.Camoufox:
		return m.launchFirefox(p)
	default:
		return nil, fmt.Errorf("runtime %q is registered but has no launcher", desc.ID)
	}
}

func validateManagedProxyLaunch(p *profile.Profile) error {
	if p != nil && p.ManagedProxyRequired && p.SessionProxy == nil {
		return codedError{code: "MANAGED_PROXY_REQUIRED", err: fmt.Errorf("this profile requires an Envara-managed proxy; start it through Envara so its managed node is connected")}
	}
	return nil
}

const defaultEndpointHealthTimeoutMS = 5000

func (m *Manager) prepareSessionEndpoint(p *profile.Profile, session *Session, attempt int) error {
	if session == nil {
		return codedError{code: "LAUNCH_FAILED", err: fmt.Errorf("browser launcher returned nil session")}
	}
	endpoint, err := m.bindExternalEndpoint(session)
	if err != nil {
		wrapped := codedError{code: "BROWSER_BIND_FAILED", err: fmt.Errorf("bind Playwright endpoint: %w", err)}
		slog.Warn("session endpoint bind failed", "session", session.ID, "profile", p.ID, "runtime_id", session.RuntimeID, "attempt", attempt, "profileDir", session.ProfileDir, "userDataDir", session.UserDataDir, "executablePath", session.ExecutablePath, "error", wrapped)
		return wrapped
	}
	session.ConnectURL = endpoint
	slog.Info("session endpoint bound", "session", session.ID, "profile", p.ID, "runtime_id", session.RuntimeID, "attempt", attempt, "connectURL", endpoint, "profileDir", session.ProfileDir, "userDataDir", session.UserDataDir, "executablePath", session.ExecutablePath)
	return m.validateSessionEndpoint(p, session, "launch")
}

func (m *Manager) bindExternalEndpoint(session *Session) (string, error) {
	if m.bindSessionEndpoint != nil {
		return m.bindSessionEndpoint(session)
	}
	if session.Context == nil {
		return "", fmt.Errorf("browser context is nil")
	}
	browser := session.Context.Browser()
	if browser == nil {
		return "", fmt.Errorf("browser is nil")
	}
	result, err := browser.Bind("browseforge-"+session.ID, playwright.BrowserBindOptions{
		Host: playwright.String(m.cfg.Host),
		Port: playwright.Int(0),
	})
	if err != nil {
		return "", err
	}
	return result.Endpoint, nil
}

func (m *Manager) validateSessionEndpoint(p *profile.Profile, session *Session, stage string) error {
	if session.ConnectURL == "" {
		return codedError{code: "ENDPOINT_UNHEALTHY", err: fmt.Errorf("session %s has no Playwright endpoint", session.ID)}
	}
	timeoutMS := m.endpointHealthTimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultEndpointHealthTimeoutMS
	}
	if err := m.checkEndpointHealth(session, timeoutMS); err != nil {
		code := classifyEndpointHealthError(err)
		wrapped := codedError{code: code, err: fmt.Errorf("Playwright endpoint health check failed: %w", err)}
		slog.Warn("session endpoint health failed", "session", session.ID, "profile", p.ID, "runtime_id", session.RuntimeID, "stage", stage, "connectURL", session.ConnectURL, "timeoutMS", timeoutMS, "code", code, "profileDir", session.ProfileDir, "userDataDir", session.UserDataDir, "executablePath", session.ExecutablePath, "error", wrapped)
		return wrapped
	}
	slog.Info("session endpoint healthy", "session", session.ID, "profile", p.ID, "runtime_id", session.RuntimeID, "stage", stage, "connectURL", session.ConnectURL, "timeoutMS", timeoutMS)
	return nil
}

func (m *Manager) checkEndpointHealth(session *Session, timeoutMS float64) error {
	if m.endpointHealthCheck != nil {
		return m.endpointHealthCheck(session.ConnectURL, timeoutMS)
	}
	if m.pw == nil {
		return fmt.Errorf("playwright driver is not running")
	}
	var (
		connected playwright.Browser
		err       error
	)
	options := playwright.BrowserTypeConnectOptions{Timeout: playwright.Float(timeoutMS)}
	if session.RuntimeID == string(bfruntime.Camoufox) {
		connected, err = m.pw.Firefox.Connect(session.ConnectURL, options)
	} else {
		connected, err = m.pw.Chromium.Connect(session.ConnectURL, options)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer connected.Close()
	page, err := connected.NewPage(endpointHealthNewPageOptions(session.RuntimeID)...)
	if err != nil {
		return fmt.Errorf("new page: %w", err)
	}
	defer page.Close()
	return nil
}

func endpointHealthNewPageOptions(runtimeID string) []playwright.BrowserNewPageOptions {
	if runtimeID != string(bfruntime.Camoufox) {
		return nil
	}
	return []playwright.BrowserNewPageOptions{{
		NoViewport: playwright.Bool(true),
	}}
}

func (m *Manager) closeSessionResources(s *Session, reason string) {
	if s == nil {
		return
	}
	s.resourcesOnce.Do(func() {
		s.closed.Store(true)
		if s.Context != nil {
			if err := s.Context.Close(); err != nil {
				slog.Warn("session context close failed", "session", s.ID, "reason", reason, "error", err)
			}
		}
		if s.Browser != nil {
			if err := s.Browser.Close(); err != nil {
				slog.Warn("session browser close failed", "session", s.ID, "reason", reason, "error", err)
			}
		}
		if s.relay != nil {
			s.relay.Close()
		}
		slog.Info("session resources closed", "session", s.ID, "reason", reason, "profile", s.ProfileID, "runtime_id", s.RuntimeID, "connectURL", s.ConnectURL)
	})
}

func (m *Manager) effectiveProxy(p *profile.Profile) groups.EffectiveProxy {
	// The desktop adapter has already resolved group policy before creating a
	// managed bridge. Reapplying the stored policy would bypass that bridge.
	if p != nil && p.SessionProxy != nil {
		return groups.EffectiveProxy{Proxy: p.SessionProxy, Source: "session", Mode: groups.ProxyModeDefault}
	}
	if m.groupStore != nil {
		return m.groupStore.EffectiveProxy(p)
	}
	if p != nil && p.Proxy != nil && p.Proxy.Host != "" {
		return groups.EffectiveProxy{Proxy: p.Proxy, Source: "profile", Mode: groups.ProxyModeDefault}
	}
	return groups.EffectiveProxy{Source: "none", Mode: groups.ProxyModeDefault}
}

func (m *Manager) restartPlaywright() error {
	// A local retry is safer than stopping the shared driver while another
	// profile is running or launching. The attempt's read lease is released by
	// LaunchSession before this helper runs; nested GPU fallback keeps its lease.
	if !m.driverMu.TryLock() {
		slog.Warn("keeping Playwright driver in use; retrying browser locally")
		return nil
	}
	defer m.driverMu.Unlock()
	m.mu.RLock()
	closing := m.closing
	busy := len(m.sessions) > 0 || m.activeOperations > 1
	m.mu.RUnlock()
	if closing {
		return ErrManagerClosing
	}
	if busy {
		slog.Warn("keeping Playwright driver for other profiles; retrying browser locally")
		return nil
	}
	if m.pw != nil {
		if err := m.pw.Stop(); err != nil {
			slog.Warn("playwright stop during restart failed", "error", err)
		}
		m.pw = nil
	}
	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("playwright.Run: %w", err)
	}
	m.pw = pw
	return nil
}

func (m *Manager) GetSession(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Session
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// FocusSession brings an existing page to the foreground without creating a tab.
func (m *Manager) FocusSession(id string) error {
	session, ok := m.GetSession(id)
	if !ok {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	release, err := m.reserveProfile(session.ProfileID)
	if err != nil {
		return err
	}
	defer release()
	page, err := m.SessionPage(id)
	if err != nil {
		return err
	}
	return page.BringToFront()
}

// SessionPage returns the active live tab and repairs selection after user closure.
func (m *Manager) SessionPage(id string) (playwright.Page, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil, ErrManagerClosing
	}
	session, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	page := m.liveSessionPageLocked(session)
	if page == nil {
		return nil, fmt.Errorf("session %s has no open browser page", id)
	}
	return page, nil
}

func (m *Manager) liveSessionPageLocked(session *Session) playwright.Page {
	if session.Page != nil && !session.Page.IsClosed() {
		return session.Page
	}
	session.Page = nil
	if session.Context != nil {
		for _, candidate := range session.Context.Pages() {
			if !candidate.IsClosed() {
				session.Page = candidate
				break
			}
		}
	}
	return session.Page
}

// SetSessionPage changes active-tab selection under the same lock as close events.
func (m *Manager) SetSessionPage(id string, page playwright.Page) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return ErrManagerClosing
	}
	session, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	if page == nil || page.IsClosed() {
		return fmt.Errorf("session %s cannot select a closed browser page", id)
	}
	session.Page = page
	return nil
}

func (m *Manager) CloseSession(id string) error {
	s, ok := m.GetSession(id)
	profileID := strings.TrimPrefix(id, "sess_")
	if ok {
		profileID = s.ProfileID
	} else if profileID == id {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	release, err := m.reserveProfile(profileID)
	if err != nil {
		return err
	}
	defer release()
	s, ok = m.GetSession(id)
	if !ok {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	m.removeSession(s)
	m.closeSessionResources(s, "explicit session close")
	slog.Info("session closed", "session", id)
	return nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	if m.closing {
		done := m.closeDone
		m.mu.Unlock()
		<-done
		return
	}
	m.closing = true
	m.closeDone = make(chan struct{})
	m.mu.Unlock()
	m.operations.Wait()
	m.driverMu.Lock()
	defer m.driverMu.Unlock()
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()
	for _, s := range sessions {
		m.closeSessionResources(s, "manager shutdown")
	}
	if m.pw != nil {
		m.pw.Stop()
		m.pw = nil
	}
	close(m.closeDone)
}
