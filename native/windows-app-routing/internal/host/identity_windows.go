//go:build windows

package host

import (
	"errors"
	"sync"
	"unsafe"

	"envara.io/windows-app-routing/internal/ownership"
	"golang.org/x/sys/windows"
)

const identityUnknown = 0
const identityUnowned = 1
const identityOwned = 2
const identityBlocked = 3
const maxRetainedIdentities = 1024

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

type processIdentity struct {
	pid          uint32
	creationTime uint64
}
type nativeSessionSnapshot struct {
	job                              windows.Handle
	routeTag, sessionTag, generation uint64
	revoked                          bool
	sessionID                        ownership.SessionID
	owner                            ownership.OwnerID
	jobID                            ownership.JobID
}
type retainedIdentity struct {
	process    windows.Handle
	sessionTag uint64
}

// This lock is intentionally independent of engine.mu. Capture may call back
// from its SOCKET thread while an engine command is inside a DLL call. Neither
// the callback nor this table ever calls the DLL or waits for engine.mu.
type identitySnapshot struct {
	mu         sync.Mutex
	sessions   map[uint64]nativeSessionSnapshot
	identities map[processIdentity]retainedIdentity
	closed     bool
	policy     *ownership.Registry
}

func newIdentitySnapshot(policy *ownership.Registry) *identitySnapshot {
	return &identitySnapshot{sessions: map[uint64]nativeSessionSnapshot{}, identities: map[processIdentity]retainedIdentity{}, policy: policy}
}
func actualIdentity(process windows.Handle) (processIdentity, error) {
	pid, err := windows.GetProcessId(process)
	if err != nil || pid == 0 {
		return processIdentity{}, errors.New("process identity unavailable")
	}
	var creation, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &creation, &exit, &kernel, &user) != nil || exit.LowDateTime != 0 || exit.HighDateTime != 0 {
		return processIdentity{}, errors.New("process is unavailable or exited")
	}
	birth := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if birth == 0 {
		return processIdentity{}, errors.New("process creation time unavailable")
	}
	return processIdentity{pid, birth}, nil
}
func memberOfJob(process, job windows.Handle) (bool, error) {
	var member uint32
	result, _, err := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if result == 0 {
		return false, err
	}
	return member != 0, nil
}
func retainActualProcess(_ windows.Handle, identity processIdentity) (windows.Handle, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, identity.pid)
	if err != nil {
		return 0, err
	}
	checked, err := actualIdentity(handle)
	if err != nil || checked != identity {
		_ = windows.CloseHandle(handle)
		return 0, errors.New("process identity changed")
	}
	return handle, nil
}
func (snapshot *identitySnapshot) registerRoot(process, job windows.Handle, routeTag, sessionTag, generation uint64, sessionID ownership.SessionID, owner ownership.OwnerID, jobID ownership.JobID) error {
	identity, err := actualIdentity(process)
	if err != nil {
		return err
	}
	member, err := memberOfJob(process, job)
	if err != nil || !member {
		return errors.New("root is not in retained environment job")
	}
	retained, err := retainActualProcess(process, identity)
	if err != nil {
		return err
	}
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if snapshot.closed || routeTag == 0 || sessionTag == 0 || generation == 0 || len(snapshot.identities) >= maxRetainedIdentities || len(snapshot.sessions) >= 64 {
		_ = windows.CloseHandle(retained)
		return errors.New("owned identity registration unavailable")
	}
	if _, exists := snapshot.sessions[sessionTag]; exists {
		_ = windows.CloseHandle(retained)
		return errors.New("session identity already registered")
	}
	if _, exists := snapshot.identities[identity]; exists {
		_ = windows.CloseHandle(retained)
		return errors.New("process identity already registered")
	}
	if snapshot.policy == nil || snapshot.policy.RegisterRoot(ownership.ProcessIdentity{PID: identity.pid, CreationTime: identity.creationTime}, sessionID) != nil {
		_ = windows.CloseHandle(retained)
		return errors.New("owned policy root registration failed")
	}
	snapshot.sessions[sessionTag] = nativeSessionSnapshot{job: job, routeTag: routeTag, sessionTag: sessionTag, generation: generation, sessionID: sessionID, owner: owner, jobID: jobID}
	snapshot.identities[identity] = retainedIdentity{process: retained, sessionTag: sessionTag}
	return nil
}
func (snapshot *identitySnapshot) revokeSession(tag uint64) {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if session, ok := snapshot.sessions[tag]; ok {
		session.revoked = true
		snapshot.sessions[tag] = session
		_ = snapshot.policy.RevokeSession(session.sessionID, session.owner)
	}
}

// Clear the borrowed Job before the engine closes it. Exact identity tombstones
// remain retained and can never be rewritten into UNOWNED or a new route.
func (snapshot *identitySnapshot) releaseJob(tag uint64) {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if session, ok := snapshot.sessions[tag]; ok {
		session.revoked = true
		session.job = 0
		snapshot.sessions[tag] = session
	}
}

// Exit observations release active PID claims, but never delete tombstones.
// Retained SYNCHRONIZE handles refer to the exact process object, not a reused PID.
func (snapshot *identitySnapshot) reapExitedLocked() {
	for identity, retained := range snapshot.identities {
		if retained.process == 0 {
			continue
		}
		state, err := windows.WaitForSingleObject(retained.process, 0)
		if err == nil && state == windows.WAIT_OBJECT_0 {
			_ = snapshot.policy.RevokeProcess(ownership.ProcessIdentity{PID: identity.pid, CreationTime: identity.creationTime})
			_ = windows.CloseHandle(retained.process)
			retained.process = 0
			snapshot.identities[identity] = retained
		}
	}
}
func (snapshot *identitySnapshot) reapExited() {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if !snapshot.closed {
		snapshot.reapExitedLocked()
	}
}

func (snapshot *identitySnapshot) needsDrain() bool {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	// Leave headroom for unrelated processes while the service revokes and
	// quiesces its Jobs. Never evict an owned tombstone to gain permission.
	return len(snapshot.identities) >= maxRetainedIdentities-64
}
func (snapshot *identitySnapshot) resolve(actual windows.Handle, wanted processIdentity) captureIdentityResult {
	result := captureIdentityResult{Size: uint32(unsafe.Sizeof(captureIdentityResult{})), Version: captureABI, Decision: identityUnknown}
	identity, err := actualIdentity(actual)
	if err != nil || identity != wanted {
		return result
	}
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if snapshot.closed {
		return result
	}
	snapshot.reapExitedLocked()
	key := ownership.ProcessIdentity{PID: identity.pid, CreationTime: identity.creationTime}
	retained, cached := snapshot.identities[identity]
	if cached {
		checked, err := actualIdentity(retained.process)
		if retained.process == 0 || err != nil || checked != identity {
			return result
		}
		if retained.sessionTag != 0 {
			session, ok := snapshot.sessions[retained.sessionTag]
			if !ok {
				return result
			}
			result.RouteTag, result.SessionTag, result.Generation = session.routeTag, session.sessionTag, session.generation
			if session.revoked {
				result.Decision = identityBlocked
				return result
			}
			if session.job == 0 {
				return captureIdentityResult{Size: result.Size, Version: result.Version}
			}
			member, err := memberOfJob(actual, session.job)
			if err != nil || !member {
				return captureIdentityResult{Size: result.Size, Version: result.Version}
			}
			if snapshot.policy.DecideProcess(key, ownership.TCP, false).Action != ownership.ActionProxy {
				result.Decision = identityBlocked
				return result
			}
			result.Decision = identityOwned
			return result
		}
	}
	// Cached unrelated identities must still be excluded from every currently
	// retained Job. A prior unowned observation is not permanent authorization.
	var found *nativeSessionSnapshot
	for _, session := range snapshot.sessions {
		if session.job == 0 {
			continue
		}
		member, err := memberOfJob(actual, session.job)
		if err != nil {
			return result
		}
		if member {
			if found != nil {
				return result
			}
			copy := session
			found = &copy
		}
	}
	if found == nil {
		if !cached {
			if len(snapshot.identities) >= maxRetainedIdentities {
				return result
			}
			handle, err := retainActualProcess(actual, identity)
			if err != nil {
				return result
			}
			if snapshot.policy.ConfirmUnowned(key, snapshot.policy.Generation()) != nil {
				_ = windows.CloseHandle(handle)
				return result
			}
			snapshot.identities[identity] = retainedIdentity{process: handle}
		}
		if snapshot.policy.DecideProcess(key, ownership.TCP, false).Action == ownership.ActionDirect {
			result.Decision = identityUnowned
		}
		return result
	}
	// An earlier unrelated binding cannot be rewritten into an owned route.
	// The launching root is always registered suspended before it can connect.
	if cached {
		result.Decision = identityBlocked
		return result
	}
	if len(snapshot.identities) >= maxRetainedIdentities {
		return result
	}
	handle, err := retainActualProcess(actual, identity)
	if err != nil {
		return result
	}
	snapshot.identities[identity] = retainedIdentity{process: handle, sessionTag: found.sessionTag}
	result.RouteTag, result.SessionTag, result.Generation = found.routeTag, found.sessionTag, found.generation
	err = snapshot.policy.RegisterJobMember(key, found.sessionID, found.jobID)
	if err != nil || found.revoked || snapshot.policy.DecideProcess(key, ownership.TCP, false).Action != ownership.ActionProxy {
		result.Decision = identityBlocked
		return result
	}
	result.Decision = identityOwned
	return result
}

// Relay lookup must verify the retained exact process object and current Job,
// not merely accept opaque tags returned by another layer.
func (snapshot *identitySnapshot) verifyRelay(result captureRelayResult) bool {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if snapshot.closed {
		return false
	}
	identity := processIdentity{result.PID, result.CreationTime}
	retained, ok := snapshot.identities[identity]
	if !ok || retained.process == 0 || retained.sessionTag != result.SessionTag {
		return false
	}
	session, ok := snapshot.sessions[result.SessionTag]
	if !ok || session.revoked || session.job == 0 || session.routeTag != result.RouteTag || session.generation != result.Generation {
		return false
	}
	checked, err := actualIdentity(retained.process)
	if err != nil || checked != identity {
		return false
	}
	member, err := memberOfJob(retained.process, session.job)
	return err == nil && member && snapshot.policy.DecideProcess(ownership.ProcessIdentity{PID: identity.pid, CreationTime: identity.creationTime}, ownership.TCP, false).Action == ownership.ActionProxy
}
func (snapshot *identitySnapshot) callback(_ uintptr, request *captureIdentityRequest, output *captureIdentityResult) (code uintptr) {
	code = 1
	defer func() {
		if recover() != nil {
			code = 1
		}
	}()
	if request == nil || output == nil {
		return 1
	}
	*output = captureIdentityResult{Size: uint32(unsafe.Sizeof(*output)), Version: captureABI}
	if request.Size != uint32(unsafe.Sizeof(*request)) || request.Version != captureABI || request.Reserved != 0 || request.PID == 0 || request.CreationTime == 0 || request.ProcessHandle == 0 {
		return 1
	}
	*output = snapshot.resolve(windows.Handle(request.ProcessHandle), processIdentity{request.PID, request.CreationTime})
	return 0
}
func (snapshot *identitySnapshot) close() {
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	snapshot.closed = true
	for identity, retained := range snapshot.identities {
		if retained.process != 0 {
			_ = windows.CloseHandle(retained.process)
		}
		delete(snapshot.identities, identity)
	}
	for tag, session := range snapshot.sessions {
		session.revoked = true
		session.job = 0
		snapshot.sessions[tag] = session
	}
}
