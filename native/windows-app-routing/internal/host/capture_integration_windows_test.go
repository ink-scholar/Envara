//go:build windows

package host

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"envara.io/windows-app-routing/internal/ownership"
	"envara.io/windows-app-routing/internal/socks5"
	"golang.org/x/sys/windows"
)

// This opt-in component lab installs/opens the signed WinDivert driver through
// the existing private lifecycle. Ordinary go/npm tests never activate it.
// It cannot set production readiness or bypass an RPC launch gate.
const captureLabGate = "ENVARA_WINDOWS_CAPTURE_LAB"

var captureFixturePath = flag.String("envara-capture-fixture", "", "private native capture fixture specification")
var captureFixtureRole = flag.String("envara-capture-role", "", "private native capture fixture role")
var captureFixtureChild = flag.Bool("envara-capture-lab-child", false, "loopback-only native test fixture child")

type captureLabSpec struct {
	Version int    `json:"version"`
	Target  string `json:"target"`
	UDP     string `json:"udp"`
	Nonce   string `json:"nonce"`
}
type captureLabRecord struct {
	PID          uint32 `json:"pid"`
	Birth        uint64 `json:"birth"`
	Role         string `json:"role"`
	Echo         bool   `json:"echo"`
	CoreClosed   bool   `json:"coreClosed"`
	PreCloseEcho bool   `json:"preCloseEcho"`
	PreCloseDone bool   `json:"preCloseDone"`
	RetryEcho    bool   `json:"retryEcho"`
	UDPSent      bool   `json:"udpSent"`
	InitComplete bool   `json:"initComplete"`
	Error        string `json:"error,omitempty"`
}
type captureLabCase struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}
type captureLabReport struct {
	Schema             int              `json:"schema"`
	Probe              string           `json:"probe"`
	Cases              []captureLabCase `json:"cases"`
	Ready              bool             `json:"ready"`
	DNS                bool             `json:"dns"`
	FailClosed         bool             `json:"failClosed"`
	VerificationPassed bool             `json:"verificationPassed"`
	TestFailed         bool             `json:"testFailed"`
}

func labFrameWrite(conn net.Conn, value string) error {
	if len(value) == 0 || len(value) > 4096 {
		return errors.New("fixture frame invalid")
	}
	data := make([]byte, len(value)+2)
	binary.BigEndian.PutUint16(data, uint16(len(value)))
	copy(data[2:], value)
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func labFrameRead(conn net.Conn) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	size := binary.BigEndian.Uint16(header[:])
	if size == 0 || size > 4096 {
		return "", errors.New("fixture frame invalid")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(conn, data)
	return string(data), err
}
func labEcho(conn net.Conn, value string) bool {
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if labFrameWrite(conn, value) != nil {
		return false
	}
	answer, err := labFrameRead(conn)
	return err == nil && answer == value
}

type labEchoServer struct {
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]bool
	accepted    int
}

func startLabEcho(t *testing.T) *labEchoServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &labEchoServer{listener: listener, connections: map[net.Conn]bool{}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.connections[conn] = true
			server.accepted++
			server.mu.Unlock()
			go func() {
				defer func() { _ = conn.Close(); server.mu.Lock(); delete(server.connections, conn); server.mu.Unlock() }()
				for {
					value, err := labFrameRead(conn)
					if err != nil {
						return
					}
					if labFrameWrite(conn, value) != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(server.close)
	return server
}
func (server *labEchoServer) close() {
	_ = server.listener.Close()
	server.mu.Lock()
	defer server.mu.Unlock()
	for conn := range server.connections {
		_ = conn.Close()
	}
}
func (server *labEchoServer) count() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.accepted
}

type labSOCKS struct {
	listener    net.Listener
	route       socks5.Route
	target      string
	mu          sync.Mutex
	connections map[net.Conn]bool
	roles       map[string]bool
	closed      bool
}

func startLabSOCKS(t *testing.T, target string) *labSOCKS {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var secret [24]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	fixture := &labSOCKS{listener: listener, target: target, connections: map[net.Conn]bool{}, roles: map[string]bool{}, route: socks5.Route{Protocol: "socks5", Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Username: hex.EncodeToString(secret[:8]), Password: hex.EncodeToString(secret[8:]), UDPPolicy: "block"}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fixture.mu.Lock()
			if fixture.closed {
				fixture.mu.Unlock()
				_ = conn.Close()
				return
			}
			fixture.connections[conn] = true
			fixture.mu.Unlock()
			go fixture.serve(conn)
		}
	}()
	t.Cleanup(fixture.close)
	return fixture
}
func (fixture *labSOCKS) serve(conn net.Conn) {
	defer func() { _ = conn.Close(); fixture.mu.Lock(); delete(fixture.connections, conn); fixture.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var selection [3]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil || selection != [3]byte{5, 1, 2} {
		return
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil || auth[0] != 1 {
		return
	}
	username := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return
	}
	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return
	}
	if string(username) != fixture.route.Username || string(password) != fixture.route.Password {
		return
	}
	for i := range password {
		password[i] = 0
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return
	}
	var command [4]byte
	if _, err := io.ReadFull(conn, command[:]); err != nil || command != [4]byte{5, 1, 0, 1} {
		return
	}
	var destination [6]byte
	if _, err := io.ReadFull(conn, destination[:]); err != nil {
		return
	}
	address := net.JoinHostPort(net.IP(destination[:4]).String(), fmt.Sprint(binary.BigEndian.Uint16(destination[4:])))
	// The fixture forwards exactly one declared loopback destination. It cannot
	// dial any public host or act as a general unauthenticated proxy.
	if address != fixture.target {
		return
	}
	upstream, err := net.DialTimeout("tcp4", address, 4*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	fixture.mu.Lock()
	if fixture.closed {
		fixture.mu.Unlock()
		return
	}
	fixture.connections[upstream] = true
	fixture.mu.Unlock()
	defer func() { fixture.mu.Lock(); delete(fixture.connections, upstream); fixture.mu.Unlock() }()
	if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
		return
	}
	value, err := labFrameRead(conn)
	if err != nil {
		return
	}
	fixture.mu.Lock()
	fixture.roles[value] = true
	fixture.mu.Unlock()
	if labFrameWrite(upstream, value) != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); done <- struct{}{} }()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-done
}
func (fixture *labSOCKS) close() {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.closed = true
	_ = fixture.listener.Close()
	for conn := range fixture.connections {
		_ = conn.Close()
	}
}
func (fixture *labSOCKS) observed(value string) bool {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.roles[value]
}

// The only child fixture entry point is an explicitly gated test binary. It
// connects solely to a validated loopback target and never receives passwords.
func TestWinDivertProcessFixture(t *testing.T) {
	if (os.Getenv(captureLabGate) != "isolated-vm" && !*captureFixtureChild) || *captureFixturePath == "" {
		t.Skip("private Windows lab child only")
	}
	if *captureFixtureRole != "root" && *captureFixtureRole != "child" {
		t.Fatal("invalid private fixture role")
	}
	data, err := os.ReadFile(*captureFixturePath)
	var spec captureLabSpec
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &spec) != nil || spec.Version != 1 || len(spec.Nonce) != 32 {
		t.Fatal("invalid private fixture specification")
	}
	address, err := netip.ParseAddrPort(spec.Target)
	if err != nil || !address.Addr().Is4() || !address.Addr().IsLoopback() || address.Port() == 0 {
		t.Fatal("fixture target must be loopback")
	}
	udpAddress, udpErr := netip.ParseAddrPort(spec.UDP)
	if udpErr != nil || !udpAddress.Addr().Is4() || !udpAddress.Addr().IsLoopback() || udpAddress.Port() == 0 {
		t.Fatal("fixture UDP target must be loopback")
	}
	if decoded, decodeErr := hex.DecodeString(spec.Nonce); decodeErr != nil || len(decoded) != 16 {
		t.Fatal("fixture nonce invalid")
	}
	identity, err := actualIdentity(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	record := captureLabRecord{PID: identity.pid, Birth: identity.creationTime, Role: *captureFixtureRole}
	directory := filepath.Dir(*captureFixturePath)
	persist := func() {
		bytes, _ := json.Marshal(record)
		temp := filepath.Join(directory, record.Role+"-record.tmp")
		if writeErr := os.WriteFile(temp, bytes, 0600); writeErr != nil {
			t.Fatalf("fixture record write failed: %v", writeErr)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			renameErr := os.Rename(temp, filepath.Join(directory, record.Role+"-record.json"))
			if renameErr == nil {
				return
			}
			// Go's reader may temporarily omit FILE_SHARE_DELETE on Windows.
			// Publish the final result reliably instead of dropping that update.
			if (!errors.Is(renameErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(renameErr, windows.ERROR_ACCESS_DENIED)) || time.Now().After(deadline) {
				t.Fatalf("fixture record publish failed: %v", renameErr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	conn, err := net.DialTimeout("tcp4", spec.Target, 5*time.Second)
	if err != nil {
		record.Error = "initial loopback connection failed"
		persist()
		t.Fatal(record.Error)
	}
	defer conn.Close()
	record.Echo = labEcho(conn, record.Role+":"+spec.Nonce)
	persist()
	if !record.Echo {
		t.Fatal("initial fixture echo failed")
	}
	udp, udpErr := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(udpAddress))
	if udpErr == nil {
		payload := []byte(record.Role + ":" + spec.Nonce)
		written, writeErr := udp.Write(payload)
		record.UDPSent = writeErr == nil && written == len(payload)
		_ = udp.Close()
	}
	record.InitComplete = true
	persist()
	if record.Role == "root" {
		path, _ := os.Executable()
		child := exec.Command(path, "-test.run=^TestWinDivertProcessFixture$", "-envara-capture-lab-child", "-envara-capture-fixture="+*captureFixturePath, "-envara-capture-role=child")
		if err = child.Start(); err != nil {
			record.Error = "inherited Job child failed to start"
			persist()
			t.Fatal(record.Error)
		}
		go func() { _ = child.Wait() }()
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		command, _ := os.ReadFile(filepath.Join(directory, "control"))
		if record.Role == "root" && string(command) == "pre-core-check" && !record.PreCloseDone {
			record.PreCloseEcho = labEcho(conn, "preclose:"+spec.Nonce)
			record.PreCloseDone = true
			persist()
		}
		if record.Role == "root" && string(command) == "core-closed" {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var one [1]byte
			_, readErr := conn.Read(one[:])
			record.CoreClosed = readErr != nil && !isLabTimeout(readErr)
			retry, retryErr := net.DialTimeout("tcp4", spec.Target, 3*time.Second)
			if retryErr == nil {
				record.RetryEcho = labEcho(retry, "retry:"+spec.Nonce)
				_ = retry.Close()
			}
			persist()
			for time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}
func isLabTimeout(err error) bool {
	var failure net.Error
	return errors.As(err, &failure) && failure.Timeout()
}
func labUDPReachable(receiver *net.UDPConn, marker string) bool {
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return false
	}
	defer sender.Close()
	if count, writeErr := sender.Write([]byte(marker)); writeErr != nil || count != len(marker) {
		return false
	}
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer receiver.SetReadDeadline(time.Time{})
	var packet [128]byte
	count, source, readErr := receiver.ReadFromUDP(packet[:])
	return readErr == nil && string(packet[:count]) == marker && source.AddrPort() == sender.LocalAddr().(*net.UDPAddr).AddrPort()
}
func waitLabRecord(directory, role string, predicate func(captureLabRecord) bool) (captureLabRecord, bool) {
	deadline := time.Now().Add(15 * time.Second)
	var record captureLabRecord
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(directory, role+"-record.json"))
		if err == nil && len(data) < 4096 && json.Unmarshal(data, &record) == nil && predicate(record) {
			return record, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return record, false
}
func labCaller(t *testing.T) (caller, error) {
	t.Helper()
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &source); err != nil {
		return caller{}, err
	}
	defer source.Close()
	user, err := source.GetTokenUser()
	if err != nil {
		return caller{}, err
	}
	var sessionID, returned uint32
	if err = windows.GetTokenInformation(source, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sessionID)), 4, &returned); err != nil {
		return caller{}, err
	}
	if returned != 4 || sessionID == 0 || user.User.Sid.String() == "S-1-5-18" || user.User.Sid.String() == "S-1-5-19" || user.User.Sid.String() == "S-1-5-20" {
		return caller{}, errors.New("native caller-token launch requires an interactive lab user, not a service account")
	}
	var primary windows.Token
	if err = windows.DuplicateTokenEx(source, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return caller{}, err
	}
	identity, err := actualIdentity(windows.CurrentProcess())
	if err != nil {
		_ = primary.Close()
		return caller{}, err
	}
	t.Cleanup(func() { _ = primary.Close() })
	return caller{sid: user.User.Sid.String(), token: primary, sessionID: sessionID, pid: identity.pid, creationTime: identity.creationTime}, nil
}
func labAdmittedRecord(engine *engine, session *sessionState, root captureLabRecord) captureRelayResult {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	for connection, found := range session.relayRecords {
		if candidate, ok := connection.(*net.TCPConn); ok && candidate.LocalAddr().(*net.TCPAddr).Port == int(engine.port) && found.PID == root.PID && found.CreationTime == root.Birth {
			return found
		}
	}
	return captureRelayResult{}
}

func TestWinDivertCaptureLoopbackLab(t *testing.T) {
	if runtime.GOARCH != "amd64" || os.Getenv(captureLabGate) != "isolated-vm" {
		t.Skip("explicit isolated Windows x64 capture lab only")
	}
	if *captureFixturePath != "" {
		t.Fatal("controller cannot also be a child fixture")
	}
	report := captureLabReport{Schema: 1, Probe: "windivert-loopback-component"}
	defer func() {
		var artifact *os.File
		if path := os.Getenv("ENVARA_WINDOWS_CAPTURE_REPORT"); path != "" {
			if !filepath.IsAbs(path) {
				t.Error("report artifact path must be absolute")
			} else {
				var err error
				artifact, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Errorf("report artifact could not be created: %v", err)
				}
			}
		}
		report.TestFailed = t.Failed()
		data, _ := json.Marshal(report)
		if artifact != nil {
			count, writeErr := artifact.Write(data)
			closeErr := artifact.Close()
			if writeErr != nil || closeErr != nil || count != len(data) {
				t.Errorf("report artifact write failed: write=%v close=%v bytes=%d/%d", writeErr, closeErr, count, len(data))
				report.TestFailed = true
				data, _ = json.Marshal(report)
			}
		}
		t.Logf("ENVARA_NATIVE_REPORT %s", data)
	}()
	check := func(name string, passed bool, detail string) {
		report.Cases = append(report.Cases, captureLabCase{name, passed, detail})
		if !passed {
			t.Errorf("native component %s: %s", name, detail)
		}
	}
	client, err := labCaller(t)
	check("interactive-caller-token", err == nil, "actual interactive user token and process creation time; service identities refused before activation")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := startLabEcho(t)
	core := startLabSOCKS(t, target.listener.Addr().String())
	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	udpBaseline := labUDPReachable(udpTarget, "unrelated-udp-before-capture")
	check("unrelated-udp-baseline", udpBaseline, "the private receiver must observe a baseline datagram from the exact unrelated sender endpoint")
	if !udpBaseline {
		t.Fatal("private UDP sensor is unavailable before activation")
	}
	// Establish an unrelated TCP connection before any capture/event handle.
	old, err := net.DialTimeout("tcp4", target.listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if !labEcho(old, "before-capture") {
		t.Fatal("baseline unrelated connection is unavailable")
	}
	engine := newEngine()
	defer engine.close()
	engine.mu.Lock()
	err = engine.startCaptureLocked()
	engine.mu.Unlock()
	check("capture-start", err == nil, "actual installed DLL/driver Start and StatusRead")
	if err != nil {
		t.Fatalf("capture lab setup failed: %v", err)
	}
	check("unrelated-preexisting-tcp", labEcho(old, "after-capture"), "the same unrelated socket must retain working traffic after activation")
	newUnrelated, newErr := net.DialTimeout("tcp4", target.listener.Addr().String(), 5*time.Second)
	newPassed := newErr == nil
	if newPassed {
		newPassed = labEcho(newUnrelated, "new-unrelated")
		_ = newUnrelated.Close()
	}
	check("unrelated-new-tcp", newPassed, "new unrelated process-owned connection must retain its original path")
	udpUnrelatedAfter := labUDPReachable(udpTarget, "unrelated-udp-after-capture")
	check("unrelated-new-udp", udpUnrelatedAfter, "a fresh unrelated UDP sender must retain private loopback delivery while capture is active")
	if err = authenticateManagedRoute(core.route); err != nil {
		check("private-core-auth", false, "authenticated loopback core unavailable")
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	spec := captureLabSpec{Version: 1, Target: target.listener.Addr().String(), UDP: udpTarget.LocalAddr().String(), Nonce: hex.EncodeToString(nonce[:])}
	bytes, _ := json.Marshal(spec)
	specPath := filepath.Join(directory, "fixture.json")
	if err = os.WriteFile(specPath, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	executable, _ := os.Executable()
	route := &routeState{id: "native-lab-route", tag: 991, owner: client.sid, application: application{ID: "native-fixture", ProfileID: "native-lab", ExecutablePath: executable}, workspace: workspace{CWD: directory, Timezone: "UTC"}, route: core.route, active: true}
	engine.mu.Lock()
	blockedBefore := uint64(0)
	if engine.capture == nil {
		err = errors.New("capture stopped before fixture registration")
	} else if err = engine.capture.refresh(); err == nil {
		blockedBefore = engine.capture.status.Blocked
		err = engine.policy.RegisterRoute(ownership.RouteSpec{ID: ownership.RouteID(route.id), Owner: ownership.OwnerID(client.sid), Generation: engine.policy.Generation(), UDPPolicy: ownership.UDPBlock, Health: ownership.RouteHealth{ProxyReady: true}})
	}
	if err == nil {
		engine.routes[route.id] = route
	}
	var session *sessionState
	if err == nil {
		session, err = engine.launchLocked(client, route, launchParams{Args: []string{"-test.run=^TestWinDivertProcessFixture$", "-envara-capture-lab-child", "-envara-capture-fixture=" + specPath, "-envara-capture-role=root"}})
	}
	engine.mu.Unlock()
	// The fixture-only flag authorizes no capture or product launch; the child
	// entry point can only connect to the validated private loopback target.
	if err != nil {
		check("owned-root-launch", false, "actual suspended caller-token/Job launch failed")
		t.Fatal(err)
	}
	check("owned-root-launch", true, "actual suspended caller-token/Job launch completed")
	root, rootReady := waitLabRecord(directory, "root", func(record captureLabRecord) bool { return record.Echo && record.InitComplete })
	child, childReady := waitLabRecord(directory, "child", func(record captureLabRecord) bool { return record.Echo && record.InitComplete })
	check("owned-root-proxy-echo", rootReady && core.observed("root:"+spec.Nonce), "root echo requires an observed authenticated SOCKS CONNECT/payload")
	check("owned-child-proxy-echo", childReady && core.observed("child:"+spec.Nonce), "child created by root must inherit Job and reach the authenticated core")
	_ = udpTarget.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var datagram [128]byte
	_, _, udpReadErr := udpTarget.ReadFromUDP(datagram[:])
	engine.mu.Lock()
	blockedAfter := uint64(0)
	if engine.capture != nil {
		_ = engine.capture.refresh()
		blockedAfter = engine.capture.status.Blocked
	}
	engine.mu.Unlock()
	check("owned-udp-non-delivery", udpBaseline && udpUnrelatedAfter && rootReady && childReady && root.UDPSent && child.UDPSent && isLabTimeout(udpReadErr) && blockedAfter > blockedBefore, "both owned processes report successful sends but the reachable receiver observes none; global blocking-counter growth corroborates capture activity, not UDP-specific attribution")
	original := labAdmittedRecord(engine, session, root)
	targetPort := uint16(target.listener.Addr().(*net.TCPAddr).Port)
	oldFlow, oldFlowErr := trustedFlow(original)
	check("trusted-original-destination", oldFlowErr == nil && original.Original.Destination.Port == targetPort && oldFlow.Key.Destination.Addr().String() == "127.0.0.1" && original.RouteTag == route.tag && original.SessionTag == session.kernelID && original.Generation == session.generation, "first native claim admitted by relay must carry matching original destination, exact identity and opaque tags")
	check("live-relay-flow-binding", oldFlowErr == nil && engine.policy.DecideFlowInstance(oldFlow).Action == ownership.ActionProxy, "the exact admitted native tuple/token must have an active owned proxy binding")
	if childReady {
		record, exists := engine.policy.Process(ownership.ProcessIdentity{PID: child.PID, CreationTime: child.Birth})
		check("child-actual-job-binding", exists && record.Binding.SessionID == ownership.SessionID(session.id), "callback must register the exact child identity in the parent's Job/session")
	}
	if err = os.WriteFile(filepath.Join(directory, "control"), []byte("pre-core-check"), 0600); err != nil {
		t.Fatal(err)
	}
	preClose, preCloseReady := waitLabRecord(directory, "root", func(record captureLabRecord) bool { return record.PreCloseDone })
	preCloseAlive := preCloseReady && preClose.PreCloseEcho
	check("pre-core-close-live-stream", preCloseAlive, "the root's same established stream must echo immediately before the fixture core is closed")
	beforeClose := target.count()
	core.close()
	if err = os.WriteFile(filepath.Join(directory, "control"), []byte("core-closed"), 0600); err != nil {
		t.Fatal(err)
	}
	closed, closedReady := waitLabRecord(directory, "root", func(record captureLabRecord) bool { return record.CoreClosed })
	check("core-close-existing-stream", preCloseAlive && closedReady, "closing the managed core must close the stream proven live by the immediately preceding echo")
	check("core-close-no-direct-fallback", preCloseAlive && closedReady && !closed.RetryEcho && target.count() == beforeClose, "owned retry must not reach the original target after core failure")
	engine.mu.Lock()
	stopErr := engine.stopLocked(session)
	stopped := !session.active && session.job == 0 && session.process == 0
	engine.mu.Unlock()
	check("session-stop-whole-job", stopErr == nil && stopped, "revocation/termination must reach zero Job processes before handles close")
	check("closed-old-relay-flow-denied", oldFlowErr == nil && engine.policy.DecideFlowInstance(oldFlow).Action == ownership.ActionBlock, "the same native tuple/token remains denied after core closure and session stop; this does not isolate session revocation from stream closure")
	if rootReady {
		decision := engine.policy.DecideProcess(ownership.ProcessIdentity{PID: root.PID, CreationTime: root.Birth}, ownership.TCP, false)
		check("stopped-process-denied", decision.Action == ownership.ActionBlock, "old identity must remain revoked")
	}
	// Use another genuinely live session to isolate Stop from the prior core
	// failure. A normally closed flow would already be blocked even without a
	// working RevokeSession, so it cannot provide that evidence.
	stopCore := startLabSOCKS(t, target.listener.Addr().String())
	if err = authenticateManagedRoute(stopCore.route); err != nil {
		check("stop-fixture-core-auth", false, "second private authenticated core is unavailable")
		t.Fatal(err)
	}
	stopDirectory := t.TempDir()
	stopSpecPath := filepath.Join(stopDirectory, "fixture.json")
	if err = os.WriteFile(stopSpecPath, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	stopRoute := &routeState{id: "native-lab-stop-route", tag: 992, owner: client.sid, application: route.application, workspace: workspace{CWD: stopDirectory, Timezone: "UTC"}, route: stopCore.route, active: true}
	engine.mu.Lock()
	err = engine.policy.RegisterRoute(ownership.RouteSpec{ID: ownership.RouteID(stopRoute.id), Owner: ownership.OwnerID(client.sid), Generation: engine.policy.Generation(), UDPPolicy: ownership.UDPBlock, Health: ownership.RouteHealth{ProxyReady: true}})
	if err == nil {
		engine.routes[stopRoute.id] = stopRoute
	}
	var liveSession *sessionState
	if err == nil {
		liveSession, err = engine.launchLocked(client, stopRoute, launchParams{Args: []string{"-test.run=^TestWinDivertProcessFixture$", "-envara-capture-lab-child", "-envara-capture-fixture=" + stopSpecPath, "-envara-capture-role=root"}})
	}
	engine.mu.Unlock()
	check("stop-fixture-live-launch", err == nil, "another actual suspended caller-token/Job session uses an independently authenticated live core")
	if err != nil {
		t.Fatal(err)
	}
	stopRoot, stopRootReady := waitLabRecord(stopDirectory, "root", func(record captureLabRecord) bool { return record.Echo && record.InitComplete })
	stopChild, stopChildReady := waitLabRecord(stopDirectory, "child", func(record captureLabRecord) bool { return record.Echo && record.InitComplete })
	check("stop-fixture-owned-echo", stopRootReady && stopChildReady && stopCore.observed("root:"+spec.Nonce) && stopCore.observed("child:"+spec.Nonce), "both independent-session processes must echo through the still-running second core")
	stopOriginal := labAdmittedRecord(engine, liveSession, stopRoot)
	stopFlow, stopFlowErr := trustedFlow(stopOriginal)
	if err = os.WriteFile(filepath.Join(stopDirectory, "control"), []byte("pre-core-check"), 0600); err != nil {
		t.Fatal(err)
	}
	stopLive, stopLiveReady := waitLabRecord(stopDirectory, "root", func(record captureLabRecord) bool { return record.PreCloseDone })
	engine.mu.Lock()
	wasProxy := stopFlowErr == nil && stopOriginal.RouteTag == stopRoute.tag && stopOriginal.SessionTag == liveSession.kernelID && engine.policy.DecideFlowInstance(stopFlow).Action == ownership.ActionProxy
	liveStopErr := engine.stopLocked(liveSession)
	liveStopped := !liveSession.active && liveSession.job == 0 && liveSession.process == 0
	engine.mu.Unlock()
	check("session-stop-active-flow-denied", stopLiveReady && stopLive.PreCloseEcho && wasProxy && liveStopErr == nil && liveStopped && engine.policy.DecideFlowInstance(stopFlow).Action == ownership.ActionBlock, "Stop must revoke an exact native tuple/token proven proxy-authorized and echoing immediately beforehand, with its core still running")
	if stopChildReady {
		decision := engine.policy.DecideProcess(ownership.ProcessIdentity{PID: stopChild.PID, CreationTime: stopChild.Birth}, ownership.TCP, false)
		check("session-stop-child-denied", decision.Action == ownership.ActionBlock, "the second session's exact child identity must also lose routing authorization")
	}
	engine.mu.Lock()
	status := engine.statusLocked(client.sid)
	engine.mu.Unlock()
	check("production-launch-gate-remains-closed", !status.CanLaunch() && !status.Ready && !status.Capabilities.DNS && !status.Capabilities.FailClosed && !status.Verification.Passed, "component observations cannot assert product acceptance")
}
