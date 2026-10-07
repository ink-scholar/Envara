//go:build windows

package host

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"envara.io/windows-app-routing/internal/dnsbroker"
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
	owner       string
	application application
	workspace   workspace
	route       socks5.Route
	active      bool
	dns         *dnsbroker.Broker
}
type sessionState struct {
	id          string
	owner       string
	routeID     string
	kernelID    uint64
	process     windows.Handle
	job         windows.Handle
	pid         uint32
	active      bool
	exitCode    *int
	connections map[net.Conn]bool
}

type engine struct {
	mu             sync.Mutex
	driver         *driver
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
	engine.driver, _ = openDriver()
	if engine.driver != nil {
		engine.listener4, _ = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if engine.listener4 != nil {
			engine.port = uint16(engine.listener4.Addr().(*net.TCPAddr).Port)
			engine.listener6, _ = net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: int(engine.port)})
		}
		if engine.listener4 == nil || engine.listener6 == nil {
			if engine.listener4 != nil {
				engine.listener4.Close()
			}
			if engine.listener6 != nil {
				engine.listener6.Close()
			}
			engine.driver.close()
			engine.driver = nil
			engine.port = 0
		} else {
			go engine.accept(engine.listener4)
			go engine.accept(engine.listener6)
		}
	}
	go engine.watch()
	return engine
}

func (engine *engine) statusLocked(owner string) protocol.Status {
	status := protocol.MissingStatus("Windows shared DNS attribution and full native acceptance are not yet available; application launch is disabled.")
	status.Authorized = true
	if engine.driver != nil {
		engine.observeDriverLocked()
		status.Installed = true
		status.Capabilities = engine.driver.capabilities
		health := engine.driver.enforcement
		status.Enforcement = &health
		if !health.FilteringReady {
			status.Capabilities.FailClosed = false
			status.Reason = "Windows BFE filtering is unavailable; routes are revoked and application launch is disabled."
		}
	}
	// No file, environment variable, build flag, or RPC can assert acceptance.
	// Capability and verification must come from real platform self-tests once
	// shared DNS attribution is implemented. Source compilation is not a pass.
	status.Ready = false
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

func (engine *engine) observeDriverLocked() {
	previous := engine.driver.enforcement.Generation
	err := engine.driver.refresh()
	if err == nil && engine.driver.enforcement.FilteringReady && (previous == 0 || previous == engine.driver.enforcement.Generation) {
		return
	}
	// A new BFE epoch invalidates even otherwise healthy prepared routes. Never
	// restart an old application or silently resume its captured connections.
	for _, route := range engine.routes {
		route.active = false
		if route.dns != nil {
			route.dns.Close()
		}
	}
	for _, session := range engine.sessions {
		if session.active {
			_ = engine.stopLocked(session)
		}
	}
	if err != nil {
		engine.driver.enforcement.FilteringReady = false
	}
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
		dnsTransport, err := dnsbroker.NewManagedDoH(params.Route)
		if err != nil {
			return protocol.Failure(request, "DNS_ROUTE_UNAVAILABLE", "The owned DNS transport could not be prepared.")
		}
		engine.routes[id] = &routeState{id: id, owner: client.sid, application: params.Application, workspace: params.Workspace, route: params.Route, active: true, dns: dnsbroker.New(dnsTransport)}
		status := engine.statusLocked(client.sid)
		return protocol.Success(request, map[string]any{"routeId": id, "ready": true, "failClosed": true, "capabilities": status.Capabilities, "verification": status.Verification})
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
	if err = engine.driver.register(process, kernelID, engine.port); err != nil {
		return nil, err
	}
	sessionID, err := randomID()
	if err != nil {
		_ = engine.driver.control(ioctlRevokeRoute, kernelID)
		return nil, err
	}
	session := &sessionState{id: sessionID, owner: client.sid, routeID: route.id, kernelID: kernelID, process: process.Process, job: job, pid: process.ProcessId, active: true, connections: map[net.Conn]bool{}}
	engine.sessions[session.id] = session
	engine.kernelSessions[kernelID] = session
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		delete(engine.sessions, session.id)
		delete(engine.kernelSessions, kernelID)
		_ = engine.driver.control(ioctlRevokeRoute, kernelID)
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
	if engine.driver != nil {
		_ = engine.driver.control(ioctlRevokeRoute, session.kernelID)
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
	return nil
}

func (engine *engine) finishLocked(session *sessionState) {
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
			engine.mu.Lock()
			if engine.driver != nil {
				engine.observeDriverLocked()
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
				if engine.driver == nil || engine.driver.control(ioctlHeartbeat, session.kernelID) != nil {
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

func (engine *engine) relay(client *net.TCPConn) {
	defer client.Close()
	destination, err := redirectedDestination(client)
	if err != nil {
		return
	}
	engine.mu.Lock()
	session := engine.kernelSessions[destination.routeID]
	if session == nil || !session.active {
		engine.mu.Unlock()
		return
	}
	route := engine.routes[session.routeID]
	if route == nil || !route.active {
		engine.mu.Unlock()
		return
	}
	transport := route.route
	session.connections[client] = true
	engine.mu.Unlock()
	defer func() { engine.mu.Lock(); delete(session.connections, client); engine.mu.Unlock() }()
	dialer := net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var recordErr error
		err := raw.Control(func(fd uintptr) { recordErr = setRedirectRecords(fd, destination.records) })
		if err != nil {
			return err
		}
		return recordErr
	}}
	upstream, err := dialer.Dial("tcp", transport.Address())
	if err != nil {
		return
	}
	defer upstream.Close()
	engine.mu.Lock()
	if !session.active || !route.active {
		engine.mu.Unlock()
		return
	}
	session.connections[upstream] = true
	engine.mu.Unlock()
	defer func() { engine.mu.Lock(); delete(session.connections, upstream); engine.mu.Unlock() }()
	if err = socks5.Connect(upstream, transport, destination.ip, destination.port); err != nil {
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
	// The reverse copy may still be blocked in client.Read after upstream EOF.
	// Closing only upstream does not wake that read and would leak a relay slot.
	_ = client.CloseRead()
	_ = upstream.Close()
	<-done
}

func (engine *engine) close() {
	engine.once.Do(func() {
		close(engine.closed)
		engine.mu.Lock()
		defer engine.mu.Unlock()
		for _, session := range engine.sessions {
			if session.active {
				_ = engine.stopLocked(session)
				if session.active {
					_ = windows.CloseHandle(session.job)
				}
			}
		}
		for _, route := range engine.routes {
			if route.dns != nil {
				route.dns.Close()
			}
			route.route.Username = ""
			route.route.Password = ""
			route.active = false
		}
		if engine.listener4 != nil {
			engine.listener4.Close()
		}
		if engine.listener6 != nil {
			engine.listener6.Close()
		}
		engine.driver.close()
	})
}

// This boundary is for a future authenticated in-process resolver adapter.
// It is deliberately not exposed as a desktop RPC or routed from dnscache:
// a broker does not prove interception of arbitrary DnsQuery/getaddrinfo calls.
// PID and creation time originate from authenticate(), not caller JSON.
func (engine *engine) resolveOwnedDNS(ctx context.Context, client caller, question dnsbroker.Request) ([]byte, error) {
	engine.mu.Lock()
	if engine.driver == nil {
		engine.mu.Unlock()
		return nil, errors.New("owned DNS routing unavailable")
	}
	engine.observeDriverLocked()
	if !engine.driver.enforcement.FilteringReady {
		engine.mu.Unlock()
		return nil, errors.New("owned DNS filtering unavailable")
	}
	kernelID, err := engine.driver.processRoute(client.pid, client.creationTime)
	if err != nil {
		engine.mu.Unlock()
		return nil, errors.New("DNS requester is not an owned process")
	}
	session := engine.kernelSessions[kernelID]
	if session == nil || !session.active || session.owner != client.sid {
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
