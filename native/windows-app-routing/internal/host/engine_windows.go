//go:build windows

package host

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"envara.io/windows-app-routing/internal/dnsbroker"
	"envara.io/windows-app-routing/internal/ownership"
	"envara.io/windows-app-routing/internal/protocol"
	"envara.io/windows-app-routing/internal/socks5"
	"golang.org/x/sys/windows"
)

type application struct {
	ID             string `json:"id"`
	Identity       string `json:"identity"`
	Path           string `json:"path"`
	ExecutablePath string `json:"executablePath"`
	ProfileID      string `json:"profileId"`
}
type workspace struct {
	CWD            string          `json:"cwd"`
	Timezone       string          `json:"timezone"`
	TimezoneSource string          `json:"timezoneSource"`
	Geolocation    json.RawMessage `json:"geolocation"`
	Privacy        json.RawMessage `json:"privacy"`
}
type prepareParams struct {
	Application application  `json:"application"`
	Workspace   workspace    `json:"workspace"`
	Route       socks5.Route `json:"route"`
}
type launchParams struct {
	RouteID     string            `json:"routeId"`
	Application application       `json:"application"`
	Args        []string          `json:"args"`
	CWD         string            `json:"cwd"`
	Env         map[string]string `json:"env"`
}
type routeState struct {
	id          string
	tag         uint64
	owner       string
	application application
	workspace   workspace
	route       socks5.Route
	active      bool
	dns         *dnsbroker.Broker
}
type sessionState struct {
	id           string
	owner        string
	routeID      string
	kernelID     uint64
	process      windows.Handle
	job          windows.Handle
	pid          uint32
	active       bool
	revoked      bool
	generation   uint64
	creationTime uint64
	exitCode     *int
	connections  map[net.Conn]bool
	// LookupRelay is a one-shot native claim. Retain its already verified
	// provenance only while this admitted connection lives; querying it again
	// would not establish the original identity or later revocation.
	relayRecords map[net.Conn]captureRelayResult
}

type engine struct {
	mu             sync.Mutex
	capture        *captureDriver
	captureFault   string
	identities     *identitySnapshot
	policy         *ownership.Registry
	listener4      *net.TCPListener
	listener6      *net.TCPListener
	port           uint16
	routes         map[string]*routeState
	sessions       map[string]*sessionState
	kernelSessions map[uint64]*sessionState
	closed         chan struct{}
	once           sync.Once
	relaySlots     chan struct{}
}

func newEngine() *engine {
	engine := &engine{routes: map[string]*routeState{}, sessions: map[string]*sessionState{}, kernelSessions: map[uint64]*sessionState{}, closed: make(chan struct{}), relaySlots: make(chan struct{}, 256)}
	engine.policy, _ = ownership.NewRegistry(ownership.DefaultLimits(), ownership.Generation{Core: 1, Adapter: 1})
	engine.identities = newIdentitySnapshot(engine.policy)
	// SCM service construction and status/setup must not implicitly activate a
	// network driver. Protected launch remains gated by real native acceptance.
	go engine.watch()
	return engine
}

func (engine *engine) startCaptureLocked() error {
	if engine.captureFault != "" {
		return errors.New("capture instance is drained; a new quiesced service instance is required")
	}
	if engine.capture != nil {
		return errors.New("capture already active")
	}
	capture, err := loadCapture(engine.identities.callback)
	if err != nil {
		return err
	}
	listener4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		capture.close()
		return err
	}
	port := uint16(listener4.Addr().(*net.TCPAddr).Port)
	listener6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6zero, Port: int(port)})
	if err != nil {
		_ = listener4.Close()
		capture.close()
		return err
	}
	startErr := capture.activate(port)
	statusErr := capture.refresh()
	if startErr != nil || statusErr != nil || !capture.status.Running || !capture.status.SocketReady || !capture.status.NetworkReady {
		_ = listener4.Close()
		_ = listener6.Close()
		capture.close()
		return fmt.Errorf("capture setup did not produce healthy handles (start=%v, status=%v, native error=%d)", startErr, statusErr, capture.status.LastError)
	}
	engine.capture, engine.listener4, engine.listener6, engine.port = capture, listener4, listener6, port
	go engine.accept(listener4)
	go engine.accept(listener6)
	return nil
}

func (engine *engine) statusLocked(owner string) protocol.Status {
	status := protocol.MissingStatus("Windows shared DNS attribution and full native acceptance are not yet available; application launch is disabled.")
	status.Authorized = true
	bundle, err := inspectCaptureBundle()
	if bundle != nil {
		captureStatus := bundle.status
		status.Capture = &captureStatus
		bundle.close()
	}
	if err == nil {
		status.Installed = true
	} else if status.Capture != nil {
		status.Capture.Reason = err.Error()
	}
	if engine.capture != nil {
		if engine.capture.refresh() == nil {
			captureStatus := engine.capture.status
			status.Capture = &captureStatus
			status.Capabilities.TCP = captureStatus.TCPCapture
			status.Capabilities.ChildProcesses = captureStatus.IdentityCallback
		} else {
			status.Reason = "Capture health is unavailable; native acceptance remains unverified."
		}
	}
	status.Capabilities.DNS = false
	status.Capabilities.UDP = false
	status.Capabilities.FailClosed = false
	// No file, environment variable, build flag, or RPC can assert acceptance.
	// Capability and verification must come from real platform self-tests once
	// shared DNS attribution is implemented. Source compilation is not a pass.
	status.Ready = false
	if engine.captureFault != "" {
		status.Reason = engine.captureFault
	}
	for _, session := range engine.sessions {
		if session.owner == owner {
			state := "stopped"
			if session.active {
				state = "running"
			}
			status.Sessions = append(status.Sessions, protocol.Session{SessionID: session.id, PID: session.pid, Status: state, ExitCode: session.exitCode})
		}
	}
	return status
}

func (engine *engine) observeCaptureLocked() {
	err := engine.capture.refresh()
	if err == nil && engine.capture.status.Running && engine.capture.status.SocketReady && engine.capture.status.NetworkReady {
		return
	}
	engine.drainCaptureLocked("Capture health failed; owned Jobs are revoked and routing acceptance remains unavailable.")
}

func (engine *engine) drainCaptureLocked(reason string) {
	engine.captureFault = reason
	// Capture failure revokes all owned routes before terminating their Jobs.
	// The independent service keeps capture open while stopping owned processes.
	for _, route := range engine.routes {
		route.active = false
		_ = engine.policy.RevokeRoute(ownership.RouteID(route.id), ownership.OwnerID(route.owner))
		if route.dns != nil {
			route.dns.Close()
		}
	}
	for _, session := range engine.sessions {
		if session.active {
			_ = engine.stopLocked(session)
		}
	}
	for _, session := range engine.sessions {
		if session.active {
			return
		}
	}
	// Official WinDivert cleanup can reinject original queued packets. Stop is
	// permitted only after the owned process trees are verified quiescent.
	if engine.listener4 != nil {
		_ = engine.listener4.Close()
		engine.listener4 = nil
	}
	if engine.listener6 != nil {
		_ = engine.listener6.Close()
		engine.listener6 = nil
	}
	if engine.capture != nil {
		engine.capture.close()
		engine.capture = nil
	}
	engine.port = 0
}

func (engine *engine) dispatch(request protocol.Request, client caller) protocol.Response {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	select {
	case <-engine.closed:
		return protocol.Failure(request, "SERVICE_STOPPING", "Windows routing service is stopping.")
	default:
	}
	switch request.Method {
	case "status", "setup":
		return protocol.Success(request, engine.statusLocked(client.sid))
	case "prepareRoute":
		if !engine.statusLocked(client.sid).CanLaunch() {
			return protocol.Failure(request, "ROUTING_NOT_READY", "Complete DNS isolation and Windows routing acceptance are required before attaching an application.")
		}
		var params prepareParams
		if decodeParams(request.Params, &params) != nil || params.Route.Validate() != nil || params.Route.UDPPolicy != "block" {
			return protocol.Failure(request, "UNSUPPORTED_ROUTE", "An authenticated managed SOCKS5 route with explicit UDP blocking is required.")
		}
		path, err := localExecutable(params.Application)
		if err != nil {
			return protocol.Failure(request, "INVALID_APPLICATION", "Select an existing local executable.")
		}
		cwd, err := localDirectory(params.Workspace.CWD)
		if err != nil {
			return protocol.Failure(request, "INVALID_DIRECTORY", "Select an existing local working directory.")
		}
		if params.Workspace.Timezone == "" || (params.Workspace.TimezoneSource != "proxy" && params.Workspace.TimezoneSource != "proxy-egress") {
			return protocol.Failure(request, "EGRESS_REQUIRED", "A verified proxy egress timezone is required.")
		}
		id, err := randomID()
		if err != nil {
			return protocol.Failure(request, "NATIVE_ERROR", "Route creation failed.")
		}
		params.Application.ExecutablePath = path
		params.Workspace.CWD = cwd
		tag, err := kernelID()
		if err != nil {
			return protocol.Failure(request, "NATIVE_ERROR", "Route identity allocation failed.")
		}
		if err = authenticateManagedRoute(params.Route); err != nil {
			return protocol.Failure(request, "PROXY_UNAVAILABLE", "The authenticated managed route is unavailable.")
		}
		dnsTransport, err := dnsbroker.NewManagedDoH(params.Route)
		if err != nil {
			return protocol.Failure(request, "DNS_ROUTE_UNAVAILABLE", "The owned DNS transport could not be prepared.")
		}
		if err = engine.policy.RegisterRoute(ownership.RouteSpec{ID: ownership.RouteID(id), Owner: ownership.OwnerID(client.sid), Generation: engine.policy.Generation(), UDPPolicy: ownership.UDPBlock, Health: ownership.RouteHealth{ProxyReady: true}}); err != nil {
			dnsTransport.Close()
			return protocol.Failure(request, "NATIVE_ERROR", "Owned route registration failed.")
		}
		engine.routes[id] = &routeState{id: id, tag: tag, owner: client.sid, application: params.Application, workspace: params.Workspace, route: params.Route, active: true, dns: dnsbroker.New(dnsTransport)}
		status := engine.statusLocked(client.sid)
		return protocol.Success(request, map[string]any{"routeId": id, "ready": status.Ready, "failClosed": status.Capabilities.FailClosed, "capabilities": status.Capabilities, "verification": status.Verification})
	case "launch":
		if !engine.statusLocked(client.sid).CanLaunch() {
			return protocol.Failure(request, "ROUTING_NOT_READY", "Windows routing is not ready; no application was started.")
		}
		var params launchParams
		if decodeParams(request.Params, &params) != nil {
			return protocol.Failure(request, "INVALID_REQUEST", "Invalid launch request.")
		}
		route := engine.routes[params.RouteID]
		if route == nil || !route.active || route.owner != client.sid {
			return protocol.Failure(request, "ROUTE_NOT_FOUND", "The prepared application route is unavailable.")
		}
		path, err := localExecutable(params.Application)
		if err != nil || !strings.EqualFold(path, route.application.ExecutablePath) || params.Application.ID != route.application.ID || params.Application.ProfileID != route.application.ProfileID {
			return protocol.Failure(request, "APPLICATION_MISMATCH", "The selected application does not match the prepared route.")
		}
		cwd, err := localDirectory(params.CWD)
		if err != nil || !strings.EqualFold(cwd, route.workspace.CWD) {
			return protocol.Failure(request, "DIRECTORY_MISMATCH", "The working directory does not match the prepared environment.")
		}
		session, err := engine.launchLocked(client, route, params)
		if err != nil {
			return protocol.Failure(request, "NATIVE_LAUNCH_FAILED", "The application could not be started with enforced networking.")
		}
		return protocol.Success(request, map[string]any{"sessionId": session.id, "pid": session.pid, "startedAt": time.Now().UTC().Format(time.RFC3339Nano)})
	case "stop":
		var params struct {
			SessionID string `json:"sessionId"`
			RouteID   string `json:"routeId"`
		}
		if decodeParams(request.Params, &params) != nil || (params.SessionID == "") == (params.RouteID == "") {
			return protocol.Failure(request, "INVALID_REQUEST", "Specify one owned session or route.")
		}
		found := false
		for _, session := range engine.sessions {
			if session.owner == client.sid && ((params.SessionID != "" && session.id == params.SessionID) || (params.RouteID != "" && session.routeID == params.RouteID)) {
				found = true
				if err := engine.stopLocked(session); err != nil {
					return protocol.Failure(request, "STOP_FAILED", "The entire owned application process tree has not stopped.")
				}
			}
		}
		if params.RouteID != "" {
			route := engine.routes[params.RouteID]
			found = found || (route != nil && route.owner == client.sid)
		}
		if !found {
			return protocol.Failure(request, "SESSION_NOT_FOUND", "The owned application session is unavailable.")
		}
		return protocol.Success(request, map[string]bool{"stopped": true})
	case "revoke":
		var params struct {
			RouteID string `json:"routeId"`
		}
		if decodeParams(request.Params, &params) != nil {
			return protocol.Failure(request, "INVALID_REQUEST", "Invalid route revocation request.")
		}
		route := engine.routes[params.RouteID]
		if route == nil || route.owner != client.sid {
			return protocol.Failure(request, "ROUTE_NOT_FOUND", "The owned route is unavailable.")
		}
		route.active = false
		_ = engine.policy.RevokeRoute(ownership.RouteID(route.id), ownership.OwnerID(route.owner))
		if route.dns != nil {
			route.dns.Close()
		}
		for _, session := range engine.sessions {
			if session.routeID == route.id && session.owner == client.sid {
				if err := engine.stopLocked(session); err != nil {
					return protocol.Failure(request, "STOP_FAILED", "The owned process tree must stop before its route can be released.")
				}
			}
		}
		// Credentials remain exclusively in memory, then are discarded at revoke.
		route.route.Username = ""
		route.route.Password = ""
		delete(engine.routes, route.id)
		return protocol.Success(request, map[string]bool{"revoked": true})
	}
	return protocol.Failure(request, "INVALID_METHOD", "Unknown native routing method.")
}

func decodeParams(data []byte, value any) error {
	if len(data) == 0 {
		return errors.New("parameters missing")
	}
	// Extra context fields can be supplied by newer desktop clients; the strict
	// top-level RPC envelope, identity comparisons and allowlists remain enforced.
	return json.Unmarshal(data, value)
}

func localExecutable(app application) (string, error) {
	path := app.ExecutablePath
	if path == "" {
		path = app.Path
	}
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || !strings.EqualFold(filepath.Ext(path), ".exe") || app.ID == "" || app.ProfileID == "" {
		return "", errors.New("local executable required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || strings.HasPrefix(resolved, `\\`) {
		return "", errors.New("local executable required")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("executable missing")
	}
	return filepath.Clean(resolved), nil
}

func localDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return "", errors.New("local directory required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || strings.HasPrefix(resolved, `\\`) {
		return "", errors.New("local directory required")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("directory missing")
	}
	return filepath.Clean(resolved), nil
}

func randomID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}
func kernelID() (uint64, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return 0, err
	}
	value := binary.LittleEndian.Uint64(data[:])
	if value == 0 {
		return kernelID()
	}
	return value, nil
}

func (engine *engine) launchLocked(client caller, route *routeState, params launchParams) (*sessionState, error) {
	if engine.capture == nil || engine.port == 0 || !engine.capture.status.Running || !engine.capture.status.SocketReady || !engine.capture.status.NetworkReady {
		return nil, errors.New("capture is not active")
	}
	if len(params.Args) > 128 {
		return nil, errors.New("too many arguments")
	}
	for _, arg := range params.Args {
		if len(arg) > 8192 || strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("argument invalid")
		}
	}
	environment, err := childEnvironment(client.token, params.Env, route.workspace.Timezone)
	if err != nil {
		return nil, err
	}
	appName, err := windows.UTF16PtrFromString(route.application.ExecutablePath)
	if err != nil {
		return nil, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{route.application.ExecutablePath}, params.Args...)))
	if err != nil {
		return nil, err
	}
	cwd, err := windows.UTF16PtrFromString(route.workspace.CWD)
	if err != nil {
		return nil, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: windows.StringToUTF16Ptr(`winsta0\default`)}
	var process windows.ProcessInformation
	// The interactive caller's primary token is mandatory. Never launch as the
	// privileged service account, inherit its environment, or run before routing.
	err = windows.CreateProcessAsUser(client.token, appName, commandLine, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT, &environment[0], cwd, &startup, &process)
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	success := false
	defer func() {
		windows.CloseHandle(process.Thread)
		if !success {
			_ = windows.TerminateProcess(process.Process, 1)
			windows.CloseHandle(process.Process)
			windows.CloseHandle(job)
		}
	}()
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return nil, err
	}
	kernelID, err := kernelID()
	if err != nil {
		return nil, err
	}
	sessionID, err := randomID()
	if err != nil {
		return nil, err
	}
	identity, err := actualIdentity(process.Process)
	if err != nil {
		return nil, err
	}
	generation := engine.policy.Generation()
	jobID := ownership.JobID(sessionID)
	if err = engine.policy.RegisterSession(ownership.SessionSpec{ID: ownership.SessionID(sessionID), Owner: ownership.OwnerID(client.sid), RouteID: ownership.RouteID(route.id), JobID: jobID, Generation: generation}); err != nil {
		return nil, err
	}
	if err = engine.identities.registerRoot(process.Process, job, route.tag, kernelID, generation.Adapter, ownership.SessionID(sessionID), ownership.OwnerID(client.sid), jobID); err != nil {
		_ = engine.policy.RevokeSession(ownership.SessionID(sessionID), ownership.OwnerID(client.sid))
		return nil, err
	}
	session := &sessionState{id: sessionID, owner: client.sid, routeID: route.id, kernelID: kernelID, generation: generation.Adapter, creationTime: identity.creationTime, process: process.Process, job: job, pid: process.ProcessId, active: true, connections: map[net.Conn]bool{}}
	engine.sessions[session.id] = session
	engine.kernelSessions[kernelID] = session
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		delete(engine.sessions, session.id)
		delete(engine.kernelSessions, kernelID)
		engine.identities.revokeSession(kernelID)
		_ = engine.capture.revoke(kernelID, generation.Adapter)
		engine.identities.releaseJob(kernelID)
		return nil, err
	}
	success = true
	return session, nil
}

func childEnvironment(token windows.Token, owned map[string]string, timezone string) ([]uint16, error) {
	base, err := token.Environ(false)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	allowBase := map[string]bool{"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATH": true, "PATHEXT": true, "TEMP": true, "TMP": true, "USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true, "APPDATA": true, "LOCALAPPDATA": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true, "PROGRAMDATA": true}
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		if ok && allowBase[strings.ToUpper(key)] {
			values[strings.ToUpper(key)] = value
		}
	}
	allowOwned := map[string]bool{"HOME": true, "USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true, "CLAUDE_CONFIG_DIR": true, "ENVARA_ENVIRONMENT_ID": true, "TZ": true, "PATH": true, "TEMP": true, "TMP": true}
	if len(owned) > 32 {
		return nil, errors.New("environment invalid")
	}
	for key, value := range owned {
		key = strings.ToUpper(key)
		if !allowOwned[key] || len(value) > 32768 || strings.ContainsAny(key+value, "\x00") {
			return nil, errors.New("environment invalid")
		}
		values[key] = value
	}
	values["TZ"] = timezone // Scope to this process tree; never change Windows timezone.
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var block []uint16
	for _, key := range keys {
		block = append(block, utf16.Encode([]rune(key+"="+values[key]))...)
		block = append(block, 0)
	}
	return append(block, 0), nil
}

type jobAccounting struct {
	TotalUserTime       int64
	TotalKernelTime     int64
	PeriodUserTime      int64
	PeriodKernelTime    int64
	PageFaults          uint32
	TotalProcesses      uint32
	ActiveProcesses     uint32
	TerminatedProcesses uint32
}

func jobActive(job windows.Handle) (uint32, error) {
	var accounting jobAccounting
	var returned uint32
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), &returned)
	return accounting.ActiveProcesses, err
}

func (engine *engine) stopLocked(session *sessionState) error {
	if !session.active {
		return nil
	}
	// Revoke first; if termination fails, living process tombstones still block.
	session.revoked = true
	engine.identities.revokeSession(session.kernelID)
	var revokeErr error
	if engine.capture != nil {
		revokeErr = engine.capture.revoke(session.kernelID, session.generation)
	}
	for connection := range session.connections {
		_ = connection.Close()
	}
	if err := windows.TerminateJobObject(session.job, 1); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		active, err := jobActive(session.job)
		if err != nil {
			return err
		}
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("owned processes still active")
		}
		time.Sleep(20 * time.Millisecond)
	}
	engine.finishLocked(session)
	return revokeErr
}

func (engine *engine) finishLocked(session *sessionState) {
	session.revoked = true
	engine.identities.revokeSession(session.kernelID)
	if engine.capture != nil {
		_ = engine.capture.revoke(session.kernelID, session.generation)
	}
	for connection := range session.connections {
		_ = connection.Close()
	}
	var exit uint32
	if windows.GetExitCodeProcess(session.process, &exit) == nil {
		value := int(exit)
		session.exitCode = &value
	}
	session.active = false
	delete(engine.kernelSessions, session.kernelID)
	engine.identities.releaseJob(session.kernelID)
	_ = windows.CloseHandle(session.process)
	_ = windows.CloseHandle(session.job)
	session.process = 0
	session.job = 0
}

func (engine *engine) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-engine.closed:
			return
		case <-ticker.C:
			engine.identities.reapExited()
			engine.mu.Lock()
			if engine.capture != nil {
				if engine.captureFault != "" {
					engine.drainCaptureLocked(engine.captureFault)
				} else if engine.identities.needsDrain() {
					engine.drainCaptureLocked("Identity capacity is approaching its bound; owned Jobs are revoked before capture shutdown. This service instance cannot reactivate routing.")
				} else {
					engine.observeCaptureLocked()
				}
			}
			for _, session := range engine.sessions {
				if !session.active {
					continue
				}
				active, err := jobActive(session.job)
				if err != nil {
					_ = engine.stopLocked(session)
					continue
				}
				if active == 0 {
					engine.finishLocked(session)
					continue
				}
				if engine.capture == nil {
					_ = engine.stopLocked(session)
				}
			}
			engine.mu.Unlock()
		}
	}
}

func (engine *engine) accept(listener *net.TCPListener) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case engine.relaySlots <- struct{}{}:
			go func() { defer func() { <-engine.relaySlots }(); engine.relay(conn) }()
		default:
			conn.Close()
		}
	}
}

func authenticateManagedRoute(route socks5.Route) error {
	if err := route.Validate(); err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", route.Address(), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return socks5.Authenticate(conn, route)
}
func captureAddrPort(endpoint captureEndpoint) (netip.AddrPort, error) {
	if endpoint.Reserved != 0 || endpoint.Port == 0 {
		return netip.AddrPort{}, errors.New("capture endpoint invalid")
	}
	var address netip.Addr
	switch endpoint.Family {
	case 4:
		for _, value := range endpoint.Address[4:] {
			if value != 0 {
				return netip.AddrPort{}, errors.New("capture IPv4 padding invalid")
			}
		}
		var bytes [4]byte
		copy(bytes[:], endpoint.Address[:4])
		address = netip.AddrFrom4(bytes)
	case 6:
		address = netip.AddrFrom16(endpoint.Address)
	default:
		return netip.AddrPort{}, errors.New("capture address family invalid")
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return netip.AddrPort{}, errors.New("capture address invalid")
	}
	return netip.AddrPortFrom(address.Unmap(), endpoint.Port), nil
}
func trustedFlow(result captureRelayResult) (ownership.FlowInstance, error) {
	for _, value := range result.Original.Reserved {
		if value != 0 {
			return ownership.FlowInstance{}, errors.New("capture tuple padding invalid")
		}
	}
	source, err := captureAddrPort(result.Original.Source)
	if err != nil {
		return ownership.FlowInstance{}, err
	}
	destination, err := captureAddrPort(result.Original.Destination)
	if err != nil {
		return ownership.FlowInstance{}, err
	}
	flow := ownership.FlowInstance{Key: ownership.FlowKey{Source: source, Destination: destination, Protocol: ownership.TCP}, Token: result.FlowID}
	if !flow.Key.Valid() || destination.Port() == 53 {
		return ownership.FlowInstance{}, errors.New("flow requires a verified DNS adapter")
	}
	return flow, nil
}
func (engine *engine) relayAllowedLocked(session *sessionState, route *routeState, flow ownership.FlowInstance) bool {
	if session == nil || route == nil || !session.active || session.revoked || !route.active || session.owner != route.owner {
		return false
	}
	decision := engine.policy.DecideFlowInstance(flow)
	return decision.Action == ownership.ActionProxy && decision.Binding.SessionID == ownership.SessionID(session.id) && decision.Binding.RouteID == ownership.RouteID(route.id) && decision.Binding.Owner == ownership.OwnerID(session.owner) && decision.Binding.JobID == ownership.JobID(session.id) && decision.Generation == engine.policy.Generation()
}
func (engine *engine) relay(client *net.TCPConn) {
	defer client.Close()
	engine.mu.Lock()
	capture := engine.capture
	engine.mu.Unlock()
	if capture == nil {
		return
	}
	// Only a live NAT lease from the installed capture module can authorize a
	// connection to the exposed relay listener. Ordinary direct accepts fail.
	destination, err := capture.destination(client)
	if err != nil || !engine.identities.verifyRelay(destination) {
		return
	}
	flow, err := trustedFlow(destination)
	if err != nil {
		return
	}
	engine.mu.Lock()
	session := engine.kernelSessions[destination.SessionTag]
	if session == nil || session.generation != destination.Generation {
		engine.mu.Unlock()
		return
	}
	route := engine.routes[session.routeID]
	if route == nil || route.tag != destination.RouteTag {
		engine.mu.Unlock()
		return
	}
	identity := ownership.ProcessIdentity{PID: destination.PID, CreationTime: destination.CreationTime}
	if engine.policy.BindFlowInstance(flow, identity, engine.policy.Generation()) != nil {
		engine.mu.Unlock()
		return
	}
	if !engine.relayAllowedLocked(session, route, flow) {
		engine.mu.Unlock()
		_ = engine.policy.CloseFlowInstance(flow)
		return
	}
	transport := route.route
	session.connections[client] = true
	if session.relayRecords == nil {
		session.relayRecords = map[net.Conn]captureRelayResult{}
	}
	session.relayRecords[client] = destination
	engine.mu.Unlock()
	defer func() {
		_ = engine.policy.CloseFlowInstance(flow)
		engine.mu.Lock()
		delete(session.connections, client)
		delete(session.relayRecords, client)
		engine.mu.Unlock()
	}()
	// The managed loopback core is the sole dial target. There are no redirect
	// records, environment-proxy substitution or direct destination fallback.
	upstream, err := net.DialTimeout("tcp", transport.Address(), 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	engine.mu.Lock()
	if !engine.relayAllowedLocked(session, route, flow) {
		engine.mu.Unlock()
		return
	}
	session.connections[upstream] = true
	engine.mu.Unlock()
	defer func() { engine.mu.Lock(); delete(session.connections, upstream); engine.mu.Unlock() }()
	if err = socks5.Connect(upstream, transport, net.IP(flow.Key.Destination.Addr().AsSlice()), flow.Key.Destination.Port()); err != nil {
		return
	}
	engine.mu.Lock()
	allowed := engine.relayAllowedLocked(session, route, flow)
	engine.mu.Unlock()
	if !allowed {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.CloseWrite()
	_ = client.CloseRead()
	_ = upstream.Close()
	<-done
}

func (engine *engine) close() {
	engine.once.Do(func() {
		close(engine.closed)
		engine.mu.Lock()
		defer engine.mu.Unlock()
		allStopped := true
		for _, session := range engine.sessions {
			if session.active {
				_ = engine.stopLocked(session)
				if session.active {
					allStopped = false
				}
			}
		}
		for _, route := range engine.routes {
			_ = engine.policy.RevokeRoute(ownership.RouteID(route.id), ownership.OwnerID(route.owner))
			if route.dns != nil {
				route.dns.Close()
			}
			route.route.Username = ""
			route.route.Password = ""
			route.active = false
		}
		if engine.listener4 != nil {
			_ = engine.listener4.Close()
		}
		if engine.listener6 != nil {
			_ = engine.listener6.Close()
		}
		// WinDivert shutdown can reinject queued original packets. Never stop or
		// unload capture before every owned Job is known quiescent. A failed
		// termination retains the guard and borrowed Jobs until service teardown;
		// service-crash persistence remains explicitly unverified/unsupported.
		if allStopped {
			if engine.capture != nil {
				engine.capture.close()
			}
			engine.identities.close()
		}
	})
}

// This boundary is for a future authenticated in-process resolver adapter.
// It is deliberately not exposed as a desktop RPC or routed from dnscache:
// a broker does not prove interception of arbitrary DnsQuery/getaddrinfo calls.
// PID and creation time originate from authenticate(), not caller JSON.
func (engine *engine) resolveOwnedDNS(ctx context.Context, client caller, question dnsbroker.Request) ([]byte, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, client.pid)
	if err != nil {
		return nil, errors.New("DNS requester identity unavailable")
	}
	defer windows.CloseHandle(process)
	observed := engine.identities.resolve(process, processIdentity{client.pid, client.creationTime})
	if observed.Decision != identityOwned {
		return nil, errors.New("DNS requester is not an active owned process")
	}
	engine.mu.Lock()
	decision := engine.policy.DecideProcess(ownership.ProcessIdentity{PID: client.pid, CreationTime: client.creationTime}, ownership.TCP, true)
	if decision.Action != ownership.ActionProxy || decision.Binding.Owner != ownership.OwnerID(client.sid) {
		engine.mu.Unlock()
		return nil, errors.New("verified owned DNS adapter unavailable")
	}
	session := engine.sessions[string(decision.Binding.SessionID)]
	if session == nil || !session.active || session.revoked || session.owner != client.sid {
		engine.mu.Unlock()
		return nil, errors.New("owned DNS session unavailable")
	}
	route := engine.routes[session.routeID]
	if route == nil || !route.active || route.owner != client.sid || route.dns == nil {
		engine.mu.Unlock()
		return nil, errors.New("owned DNS route unavailable")
	}
	broker := route.dns
	engine.mu.Unlock()
	return broker.Resolve(ctx, question)
}
