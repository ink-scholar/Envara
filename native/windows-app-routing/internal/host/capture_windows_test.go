//go:build windows

package host

import (
	"net/netip"
	"os"
	"testing"
	"unsafe"

	"envara.io/windows-app-routing/internal/ownership"
	"golang.org/x/sys/windows"
)

func TestCaptureABILayout(t *testing.T) {
	sizes := map[string]struct{ actual, want uintptr }{
		"endpoint":         {unsafe.Sizeof(captureEndpoint{}), 20},
		"tuple":            {unsafe.Sizeof(captureTuple{}), 48},
		"identity request": {unsafe.Sizeof(captureIdentityRequest{}), 32},
		"identity result":  {unsafe.Sizeof(captureIdentityResult{}), 40},
		"config":           {unsafe.Sizeof(captureConfig{}), 32},
		"query":            {unsafe.Sizeof(captureRelayQuery{}), 56},
		"relay result":     {unsafe.Sizeof(captureRelayResult{}), 104},
		"revoke":           {unsafe.Sizeof(captureRevoke{}), 24},
	}
	for name, size := range sizes {
		if size.actual != size.want {
			t.Errorf("%s size %d, want %d", name, size.actual, size.want)
		}
	}
	if unsafe.Offsetof(captureIdentityRequest{}.ProcessHandle) != 24 || unsafe.Offsetof(captureIdentityResult{}.RouteTag) != 16 || unsafe.Offsetof(captureRelayResult{}.Original) != 56 {
		t.Fatal("C ABI offsets changed")
	}
}

// This test has no installed DLL dependency and never starts a capture driver.
func TestServiceStatusDoesNotActivateCapture(t *testing.T) {
	engine := newEngine()
	defer engine.close()
	engine.mu.Lock()
	status := engine.statusLocked("fixture-owner")
	engine.mu.Unlock()
	if engine.capture != nil || status.CanLaunch() || status.Ready || status.Capabilities.DNS || status.Capabilities.FailClosed || status.Verification.Passed {
		t.Fatal("read-only status asserted activation or acceptance")
	}
}

func TestDrainedInstanceCannotReactivate(t *testing.T) {
	engine := newEngine()
	defer engine.close()
	engine.mu.Lock()
	engine.drainCaptureLocked("fixture capacity drain")
	err := engine.startCaptureLocked()
	status := engine.statusLocked("fixture-owner")
	engine.mu.Unlock()
	if err == nil {
		t.Fatal("drained service attempted capture reactivation")
	}
	if engine.capture != nil || status.CanLaunch() || status.Reason != "fixture capacity drain" {
		t.Fatal("drained instance asserted readiness or lost its failure reason")
	}
}

func suspendedFixture(t *testing.T) (windows.ProcessInformation, processIdentity) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{path, "-test.run=^$"}))
	if err != nil {
		t.Fatal(err)
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var process windows.ProcessInformation
	if err := windows.CreateProcess(app, command, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW, nil, nil, &startup, &process); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.TerminateProcess(process.Process, 1)
		_, _ = windows.WaitForSingleObject(process.Process, 5000)
		_ = windows.CloseHandle(process.Thread)
		_ = windows.CloseHandle(process.Process)
	})
	identity, err := actualIdentity(process.Process)
	if err != nil {
		t.Fatal(err)
	}
	return process, identity
}

func testPolicy(t *testing.T) *ownership.Registry {
	t.Helper()
	policy, err := ownership.NewRegistry(ownership.DefaultLimits(), ownership.Generation{Core: 1, Adapter: 1})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// These are platform ownership tests with a suspended, network-idle child.
// The modelled ProxyReady fixture is not native routing acceptance.
func TestActualJobRootAndRevoke(t *testing.T) {
	policy := testPolicy(t)
	if err := policy.RegisterRoute(ownership.RouteSpec{ID: "route", Owner: "owner", Generation: policy.Generation(), UDPPolicy: ownership.UDPBlock, Health: ownership.RouteHealth{ProxyReady: true}}); err != nil {
		t.Fatal(err)
	}
	if err := policy.RegisterSession(ownership.SessionSpec{ID: "session", Owner: "owner", RouteID: "route", JobID: "job", Generation: policy.Generation()}); err != nil {
		t.Fatal(err)
	}
	process, identity := suspendedFixture(t)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := newIdentitySnapshot(policy)
	t.Cleanup(func() { snapshot.releaseJob(12); snapshot.close(); _ = windows.CloseHandle(job) })
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		t.Fatal(err)
	}
	if err = snapshot.registerRoot(process.Process, job, 11, 12, 1, "session", "owner", "job"); err != nil {
		t.Fatal(err)
	}
	result := snapshot.resolve(process.Process, identity)
	if result.Decision != identityOwned || result.RouteTag != 11 || result.SessionTag != 12 || result.Generation != 1 {
		t.Fatalf("actual job root: %+v", result)
	}
	lookup := captureRelayResult{PID: identity.pid, CreationTime: identity.creationTime, RouteTag: 11, SessionTag: 12, Generation: 1}
	if !snapshot.verifyRelay(lookup) {
		t.Fatal("retained process/Job rejected")
	}
	lookup.CreationTime++
	if snapshot.verifyRelay(lookup) {
		t.Fatal("PID reuse proof accepted")
	}
	snapshot.revokeSession(12)
	if result = snapshot.resolve(process.Process, identity); result.Decision != identityBlocked {
		t.Fatalf("revoked root: %+v", result)
	}
}

func TestUnownedExitReleasesPIDClaim(t *testing.T) {
	policy := testPolicy(t)
	snapshot := newIdentitySnapshot(policy)
	defer snapshot.close()
	process, identity := suspendedFixture(t)
	if result := snapshot.resolve(process.Process, identity); result.Decision != identityUnowned {
		t.Fatalf("unrelated suspended child: %+v", result)
	}
	if snapshot.identities[identity].process == 0 {
		t.Fatal("unrelated identity lacks retained exit handle")
	}
	if err := windows.TerminateProcess(process.Process, 1); err != nil {
		t.Fatal(err)
	}
	if state, err := windows.WaitForSingleObject(process.Process, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("fixture did not exit")
	}
	snapshot.reapExited()
	record, exists := policy.Process(ownership.ProcessIdentity{PID: identity.pid, CreationTime: identity.creationTime})
	if !exists || record.State != ownership.StateRevoked || snapshot.identities[identity].process != 0 {
		t.Fatal("exit did not revoke active PID claim and release retained handle")
	}
	if result := snapshot.resolve(process.Process, identity); result.Decision != identityUnknown {
		t.Fatal("exited identity allowed direct")
	}
}

func TestTrustedFlowRejectsDNSAndInvalidContext(t *testing.T) {
	result := captureRelayResult{FlowID: 3, Original: captureTuple{Protocol: 6, Source: captureEndpoint{Family: 4, Port: 5000, Address: [16]byte{192, 0, 2, 1}}, Destination: captureEndpoint{Family: 4, Port: 443, Address: [16]byte{203, 0, 113, 1}}}}
	flow, err := trustedFlow(result)
	if err != nil || flow.Token != 3 || flow.Key.Destination != netip.MustParseAddrPort("203.0.113.1:443") {
		t.Fatalf("valid trusted flow: %+v %v", flow, err)
	}
	result.Original.Destination.Port = 53
	if _, err = trustedFlow(result); err == nil {
		t.Fatal("ordinary relay accepted DNS")
	}
	result.Original.Destination.Port = 443
	result.Original.Destination.Address[15] = 1
	if _, err = trustedFlow(result); err == nil {
		t.Fatal("nonzero IPv4 padding accepted")
	}
}
