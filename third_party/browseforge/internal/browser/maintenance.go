package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
)

const maxMaintenanceProfiles = 500

func maintenanceError(code string) error {
	message := "browser profile maintenance is unavailable"
	switch code {
	case "CACHE_MAINTENANCE_INVALID":
		message = "invalid profile maintenance request"
	case "CACHE_MAINTENANCE_BUSY":
		message = "browser profile is in use or under maintenance"
	case "CACHE_MAINTENANCE_TOKEN_INVALID":
		message = "profile maintenance authorization is unavailable"
	case "UPDATE_MAINTENANCE_BUSY":
		message = "browser manager is in use or reserved for update"
	case "UPDATE_MAINTENANCE_INVALID":
		message = "invalid update maintenance request"
	}
	return codedError{code: code, err: errors.New(message)}
}

func validMaintenanceProfileID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// AcquireProfileMaintenance serializes admission with every browser launch and
// close, including REST and MCP callers. All requested profiles are admitted
// together, after earlier native operations have released their profile locks.
//
// A granted token has no timer: a delayed/crashed owner must not allow a browser
// to open files while maintenance may still be in progress. Only its exact token
// releases it; otherwise it remains until this Manager's process exits. Granted
// leases do not keep operations pending, so manager shutdown can still clean up.
func (m *Manager) AcquireProfileMaintenance(ctx context.Context, profileIDs []string) (string, error) {
	if ctx == nil || len(profileIDs) < 1 || len(profileIDs) > maxMaintenanceProfiles {
		return "", maintenanceError("CACHE_MAINTENANCE_INVALID")
	}
	ids := append([]string(nil), profileIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !validMaintenanceProfileID(id) || i > 0 && id == ids[i-1] {
			return "", maintenanceError("CACHE_MAINTENANCE_INVALID")
		}
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", maintenanceError("CACHE_MAINTENANCE_UNAVAILABLE")
	}
	token := hex.EncodeToString(nonce[:])
	releases := make([]func(), 0, len(ids))
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		release, err := m.reserveProfile(id)
		if err != nil {
			return "", err
		}
		releases = append(releases, release)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if m.closing {
		return "", ErrManagerClosing
	}
	if len(m.maintenanceLeases) >= 128 {
		return "", maintenanceError("CACHE_MAINTENANCE_BUSY")
	}
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if m.maintenanceProfiles[id] != "" {
			return "", maintenanceError("CACHE_MAINTENANCE_BUSY")
		}
		selected[id] = true
	}
	for _, session := range m.sessions {
		if selected[session.ProfileID] {
			return "", maintenanceError("CACHE_MAINTENANCE_BUSY")
		}
	}
	if m.maintenanceLeases == nil {
		m.maintenanceLeases = make(map[string][]string)
		m.maintenanceProfiles = make(map[string]string)
	}
	if _, exists := m.maintenanceLeases[token]; exists {
		return "", maintenanceError("CACHE_MAINTENANCE_UNAVAILABLE")
	}
	m.maintenanceLeases[token] = ids
	for _, id := range ids {
		m.maintenanceProfiles[id] = token
	}
	return token, nil
}

// ReleaseProfileMaintenance never takes a profile operation lock or checks
// closing: cleanup is allowed while shutdown or another launch is waiting.
func (m *Manager) ReleaseProfileMaintenance(token string) error {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != token {
		return maintenanceError("CACHE_MAINTENANCE_TOKEN_INVALID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, exists := m.maintenanceLeases[token]
	if !exists {
		return maintenanceError("CACHE_MAINTENANCE_TOKEN_INVALID")
	}
	for _, id := range ids {
		if m.maintenanceProfiles[id] != token {
			return maintenanceError("CACHE_MAINTENANCE_TOKEN_INVALID")
		}
	}
	for _, id := range ids {
		delete(m.maintenanceProfiles, id)
	}
	delete(m.maintenanceLeases, token)
	return nil
}

// Caller holds the same profile reservation used for maintenance admission.
func (m *Manager) profileMaintenanceActive(profileID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maintenanceProfiles[profileID] != ""
}

// ReserveProfileMutation is installed on the profile Store, so REST, MCP and
// group edits share the same admission boundary as launches and maintenance.
// It must be called before Store.mu; browser launch code never writes the Store
// while holding its own reservation.
func (m *Manager) ReserveProfileMutation(profileID string) (func(), error) {
	if !validMaintenanceProfileID(profileID) {
		return nil, maintenanceError("CACHE_MAINTENANCE_INVALID")
	}
	release, err := m.reserveProfile(profileID)
	if err != nil {
		return nil, err
	}
	if m.profileMaintenanceActive(profileID) {
		release()
		return nil, maintenanceError("CACHE_MAINTENANCE_BUSY")
	}
	return release, nil
}

// ReserveUpdateOperation covers an entire REST/MCP operation, including work
// after its final browser session closes. It holds no profile or Store mutex,
// so handlers can use the ordinary profile reservations without recursive locks.
// Reads that cannot start a browser or write state do not need a reservation.
// These requests must not join Close's native-operation wait group: closing a
// browser may be what unblocks an in-flight evaluation or page wait.
func (m *Manager) ReserveUpdateOperation() (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil, ErrManagerClosing
	}
	if m.updateMaintenanceToken != "" {
		return nil, maintenanceError("UPDATE_MAINTENANCE_BUSY")
	}
	m.updateOperations++
	return func() {
		m.mu.Lock()
		m.updateOperations--
		m.mu.Unlock()
	}, nil
}

// AcquireUpdateMaintenance never waits for user work to finish and never stops
// a browser. Admission and every operation counter share mu. Store mutations
// reserve their profile before taking Store.mu, so a zero counter also excludes
// a profile write waiting on that mutex. Driver installation happens before the
// server starts; desktop-owned installers require the desktop's separate gate.
// A granted lease has no timeout and survives Close until its exact release.
func (m *Manager) AcquireUpdateMaintenance(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", maintenanceError("UPDATE_MAINTENANCE_INVALID")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", maintenanceError("CACHE_MAINTENANCE_UNAVAILABLE")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if m.closing {
		return "", ErrManagerClosing
	}
	if m.updateMaintenanceToken != "" || m.updateCleanupUncertain || len(m.sessions) != 0 || m.activeOperations != 0 || m.updateOperations != 0 || len(m.maintenanceLeases) != 0 {
		return "", maintenanceError("UPDATE_MAINTENANCE_BUSY")
	}
	m.updateMaintenanceToken = hex.EncodeToString(nonce[:])
	return m.updateMaintenanceToken, nil
}

// Update and profile leases have separate release methods. A cache token can
// never release global admission, and an old update token cannot release a new one.
func (m *Manager) ReleaseUpdateMaintenance(token string) error {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != token {
		return maintenanceError("CACHE_MAINTENANCE_TOKEN_INVALID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateMaintenanceToken == "" || m.updateMaintenanceToken != token {
		return maintenanceError("CACHE_MAINTENANCE_TOKEN_INVALID")
	}
	m.updateMaintenanceToken = ""
	return nil
}
