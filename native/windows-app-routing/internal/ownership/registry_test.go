package ownership

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

var testGeneration = Generation{Core: 11, Adapter: 27}

func newTestRegistry(t *testing.T, limits Limits) *Registry {
	t.Helper()
	r, err := NewRegistry(limits, testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func addSession(t *testing.T, r *Registry, suffix string, udp UDPPolicy, health RouteHealth) (RouteID, SessionID, JobID) {
	t.Helper()
	route, session, job := RouteID("route-"+suffix), SessionID("session-"+suffix), JobID("job-"+suffix)
	if err := r.RegisterRoute(RouteSpec{ID: route, Owner: "owner", Generation: r.Generation(), UDPPolicy: udp, Health: health}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterSession(SessionSpec{ID: session, Owner: "owner", RouteID: route, JobID: job, Generation: r.Generation()}); err != nil {
		t.Fatal(err)
	}
	return route, session, job
}

func healthy() RouteHealth {
	return RouteHealth{ProxyReady: true, DNSAdapterReady: true, UDPReady: true}
}

func flow(source, destination string, protocol Protocol) FlowKey {
	return FlowKey{Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort(destination), Protocol: protocol}
}

func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func requireAction(t *testing.T, got Decision, want Action) {
	t.Helper()
	if got.Action != want {
		t.Fatalf("decision = %+v, want action %s", got, want)
	}
}

func TestProcessesFromSameExecutableHaveIndependentRoutes(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	routeA, sessionA, _ := addSession(t, r, "a", UDPBlock, healthy())
	routeB, sessionB, _ := addSession(t, r, "b", UDPBlock, healthy())
	// Both are instances of the same executable. Executable names are not
	// part of the API and cannot collapse these independent process bindings.
	a := ProcessIdentity{PID: 400, CreationTime: 900}
	b := ProcessIdentity{PID: 401, CreationTime: 901}
	if err := r.RegisterRoot(a, sessionA); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterRoot(b, sessionB); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		identity ProcessIdentity
		route    RouteID
		session  SessionID
	}{{a, routeA, sessionA}, {b, routeB, sessionB}} {
		decision := r.DecideProcess(tc.identity, TCP, false)
		requireAction(t, decision, ActionProxy)
		if decision.Binding.RouteID != tc.route || decision.Binding.SessionID != tc.session {
			t.Fatalf("incorrect instance binding: %+v", decision)
		}
	}
	// A duplicate cannot overwrite route A with route B.
	requireError(t, r.RegisterRoot(a, sessionB), ErrDuplicate)
	if got := r.DecideProcess(a, TCP, false); got.Binding.RouteID != routeA {
		t.Fatalf("duplicate mutated existing route: %+v", got)
	}
}

func TestPIDReuseDoesNotInheritOldOwnership(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	_, session, _ := addSession(t, r, "a", UDPBlock, healthy())
	old, replacement := ProcessIdentity{PID: 19, CreationTime: 100}, ProcessIdentity{PID: 19, CreationTime: 200}
	if err := r.RegisterRoot(old, session); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideProcess(replacement, TCP, false), ActionUnknown)
	requireError(t, r.RegisterRoot(replacement, session), ErrPIDConflict)
	if err := r.RevokeProcess(old); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmUnowned(replacement, r.Generation()); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideProcess(replacement, TCP, false), ActionDirect)
	requireAction(t, r.DecideProcess(old, TCP, false), ActionBlock)
	requireError(t, r.ConfirmUnowned(old, r.Generation()), ErrDuplicate)
	requireError(t, r.RegisterRoot(old, session), ErrDuplicate)
}

func TestParentAndJobInheritanceAndLateRevocation(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	_, session, job := addSession(t, r, "a", UDPBlock, healthy())
	root := ProcessIdentity{PID: 10, CreationTime: 100}
	child := ProcessIdentity{PID: 11, CreationTime: 101}
	grandchild := ProcessIdentity{PID: 12, CreationTime: 102}
	if err := r.RegisterRoot(root, session); err != nil {
		t.Fatal(err)
	}
	requireError(t, r.InheritChild(child, root, "other-job"), ErrJobMismatch)
	requireError(t, r.InheritChild(child, ProcessIdentity{PID: root.PID, CreationTime: root.CreationTime + 1}, job), ErrUnknownProcess)
	if err := r.InheritChild(child, root, job); err != nil {
		t.Fatal(err)
	}
	if err := r.InheritChild(grandchild, child, job); err != nil {
		t.Fatal(err)
	}
	if r.DecideProcess(root, TCP, false).Binding != r.DecideProcess(grandchild, TCP, false).Binding {
		t.Fatal("descendant did not inherit exact environment binding")
	}
	if err := r.RevokeProcess(root); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []ProcessIdentity{root, child, grandchild} {
		requireAction(t, r.DecideProcess(identity, TCP, false), ActionBlock)
	}
	late := ProcessIdentity{PID: 13, CreationTime: 103}
	requireError(t, r.InheritChild(late, root, job), ErrRevoked)
	lateRecord, exists := r.Process(late)
	if !exists || lateRecord.State != StateRevoked || lateRecord.Ownership != OwnershipOwned {
		t.Fatalf("late descendant lost ownership: %+v, exists=%v", lateRecord, exists)
	}
	requireAction(t, r.DecideProcess(late, TCP, false), ActionBlock)
	requireError(t, r.ConfirmUnowned(late, r.Generation()), ErrDuplicate)
}

func TestVerifiedJobMemberDoesNotRequireInventedParent(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	route, session, job := addSession(t, r, "a", UDPBlock, healthy())
	identity := ProcessIdentity{PID: 30, CreationTime: 300}
	requireError(t, r.RegisterJobMember(identity, session, "different-job"), ErrJobMismatch)
	requireError(t, r.RegisterJobMember(identity, "unknown-session", job), ErrNotFound)
	requireAction(t, r.DecideProcess(identity, TCP, false), ActionUnknown)
	if err := r.RegisterJobMember(identity, session, job); err != nil {
		t.Fatal(err)
	}
	decision := r.DecideProcess(identity, TCP, false)
	requireAction(t, decision, ActionProxy)
	if decision.Binding.RouteID != route || decision.Binding.SessionID != session || decision.Binding.JobID != job {
		t.Fatalf("verified Job member lost binding: %+v", decision)
	}
	record, exists := r.Process(identity)
	if !exists || record.Parent != (ProcessIdentity{}) {
		t.Fatalf("Job observation fabricated a parent: %+v", record)
	}
	requireError(t, r.RegisterJobMember(identity, session, job), ErrDuplicate)
	if err := r.RevokeSession(session, "owner"); err != nil {
		t.Fatal(err)
	}
	late := ProcessIdentity{PID: 31, CreationTime: 301}
	requireError(t, r.RegisterJobMember(late, session, job), ErrRevoked)
	requireAction(t, r.DecideProcess(late, TCP, false), ActionBlock)
	requireError(t, r.ConfirmUnowned(late, r.Generation()), ErrDuplicate)
}

func TestVerifiedJobMemberRejectsInvalidIdentityStaleJobAndCapacity(t *testing.T) {
	limits := DefaultLimits()
	limits.Processes = 1
	r := newTestRegistry(t, limits)
	_, session, job := addSession(t, r, "a", UDPBlock, healthy())
	for _, identity := range []ProcessIdentity{{}, {PID: 1}, {CreationTime: 1}} {
		requireError(t, r.RegisterJobMember(identity, session, job), ErrInvalidIdentity)
	}
	if _, err := r.AdvanceGeneration(Generation{Core: testGeneration.Core + 1, Adapter: testGeneration.Adapter}); err != nil {
		t.Fatal(err)
	}
	identity := ProcessIdentity{PID: 30, CreationTime: 300}
	requireError(t, r.RegisterJobMember(identity, session, job), ErrRevoked)
	record, exists := r.Process(identity)
	if !exists || record.Generation != testGeneration || record.State != StateRevoked {
		t.Fatalf("stale Job observation acquired current epoch: %+v", record)
	}
	requireError(t, r.RegisterJobMember(ProcessIdentity{PID: 31, CreationTime: 301}, session, job), ErrCapacity)
	requireAction(t, r.DecideProcess(identity, TCP, false), ActionBlock)
}

func TestInvalidAndConflictingBindingsAreRejected(t *testing.T) {
	for _, limits := range []Limits{{}, {Routes: 1, Sessions: 1, Processes: 1, Flows: -1}} {
		_, err := NewRegistry(limits, testGeneration)
		requireError(t, err, ErrInvalidLimits)
	}
	_, err := NewRegistry(DefaultLimits(), Generation{Core: 1})
	requireError(t, err, ErrInvalidGeneration)
	r := newTestRegistry(t, DefaultLimits())
	route, session, job := addSession(t, r, "a", UDPBlock, healthy())
	for _, identity := range []ProcessIdentity{{}, {PID: 1}, {CreationTime: 1}} {
		requireError(t, r.RegisterRoot(identity, session), ErrInvalidIdentity)
		requireError(t, r.ConfirmUnowned(identity, r.Generation()), ErrInvalidIdentity)
		requireAction(t, r.DecideProcess(identity, TCP, false), ActionUnknown)
	}
	requireError(t, r.RegisterRoute(RouteSpec{ID: " ", Owner: "owner", Generation: r.Generation(), UDPPolicy: UDPBlock}), ErrInvalidID)
	requireError(t, r.RegisterRoute(RouteSpec{ID: "other", Owner: "owner", Generation: r.Generation()}), ErrInvalidPolicy)
	requireError(t, r.RegisterRoute(RouteSpec{ID: route, Owner: "owner", Generation: r.Generation(), UDPPolicy: UDPBlock}), ErrDuplicate)
	requireError(t, r.RegisterSession(SessionSpec{ID: "other", Owner: "another-owner", RouteID: route, JobID: "other-job", Generation: r.Generation()}), ErrOwnerMismatch)
	requireError(t, r.RegisterSession(SessionSpec{ID: "other", Owner: "owner", RouteID: route, JobID: job, Generation: r.Generation()}), ErrDuplicate)
	requireError(t, r.RevokeSession(session, "another-owner"), ErrOwnerMismatch)
	requireError(t, r.RevokeRoute(route, "another-owner"), ErrOwnerMismatch)
	requireError(t, r.SetRouteHealth(route, "another-owner", RouteHealth{}), ErrOwnerMismatch)
	if got, _ := r.Route(route); got.State != StateActive || got.Health != healthy() {
		t.Fatalf("rejected owner mutation changed route: %+v", got)
	}
}

func TestOwnedPolicyNeverFallsBackToDirect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol Protocol
		dns      bool
		udp      UDPPolicy
		health   RouteHealth
		action   Action
		reason   Reason
	}{
		{"tcp", TCP, false, UDPBlock, healthy(), ActionProxy, ReasonOwnedRoute},
		{"proxy-down", TCP, false, UDPBlock, RouteHealth{DNSAdapterReady: true}, ActionBlock, ReasonProxyUnavailable},
		{"udp-block", UDP, false, UDPBlock, healthy(), ActionBlock, ReasonUDPBlocked},
		{"udp-unavailable", UDP, false, UDPProxy, RouteHealth{ProxyReady: true, DNSAdapterReady: true}, ActionBlock, ReasonUDPUnavailable},
		{"udp-proxy", UDP, false, UDPProxy, healthy(), ActionProxy, ReasonOwnedRoute},
		{"udp-dns-missing", UDP, true, UDPBlock, RouteHealth{ProxyReady: true}, ActionBlock, ReasonDNSUnavailable},
		{"tcp-dns-missing", TCP, true, UDPBlock, RouteHealth{ProxyReady: true}, ActionBlock, ReasonDNSUnavailable},
		{"owned-dns-adapter", UDP, true, UDPBlock, healthy(), ActionProxy, ReasonOwnedRoute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRegistry(t, DefaultLimits())
			_, session, _ := addSession(t, r, "a", tc.udp, tc.health)
			identity := ProcessIdentity{PID: 10, CreationTime: 100}
			if err := r.RegisterRoot(identity, session); err != nil {
				t.Fatal(err)
			}
			decision := r.DecideProcess(identity, tc.protocol, tc.dns)
			if decision.Action != tc.action || decision.Reason != tc.reason || decision.DNS != tc.dns {
				t.Fatalf("decision = %+v; want %s/%s", decision, tc.action, tc.reason)
			}
		})
	}
}

func TestUnknownNeedsFreshPlatformConfirmation(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	identity := ProcessIdentity{PID: 15, CreationTime: 100}
	key := flow("192.0.2.1:41000", "198.51.100.1:443", TCP)
	requireAction(t, r.DecideProcess(identity, TCP, false), ActionUnknown)
	requireAction(t, r.DecideFlow(key), ActionUnknown)
	requireError(t, r.BindFlow(key, identity, r.Generation()), ErrUnknownProcess)
	requireError(t, r.ConfirmUnowned(identity, Generation{Core: 10, Adapter: 27}), ErrInvalidGeneration)
	if err := r.ConfirmUnowned(identity, r.Generation()); err != nil {
		t.Fatal(err)
	}
	if err := r.BindFlow(key, identity, r.Generation()); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideFlow(key), ActionDirect)
	oldGeneration := r.Generation()
	next := Generation{Core: oldGeneration.Core + 1, Adapter: oldGeneration.Adapter}
	if _, err := r.AdvanceGeneration(next); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideProcess(identity, TCP, false), ActionUnknown)
	requireAction(t, r.DecideFlow(key), ActionUnknown)
	requireError(t, r.ConfirmUnowned(identity, oldGeneration), ErrInvalidGeneration)
	if err := r.ConfirmUnowned(identity, next); err != nil {
		t.Fatal(err)
	}
	// Reconfirming the process does not implicitly bless stale flow evidence.
	requireAction(t, r.DecideFlow(key), ActionUnknown)
	if err := r.BindFlow(key, identity, next); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideFlow(key), ActionDirect)
}

func TestFlowKeyUsesFullIPv4IPv6EndpointsAndProtocol(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	_, session, _ := addSession(t, r, "a", UDPProxy, healthy())
	identity := ProcessIdentity{PID: 20, CreationTime: 100}
	if err := r.RegisterRoot(identity, session); err != nil {
		t.Fatal(err)
	}
	keys := []FlowKey{
		flow("192.0.2.1:41000", "198.51.100.1:443", TCP),
		flow("192.0.2.2:41000", "198.51.100.1:443", TCP),
		flow("192.0.2.1:41000", "198.51.100.2:443", TCP),
		flow("192.0.2.1:41000", "198.51.100.1:443", UDP),
		flow("[2001:db8::1]:41000", "[2001:db8::2]:443", TCP),
	}
	for i, key := range keys {
		instance := FlowInstance{Key: key, Token: uint64(i + 1)}
		if err := r.BindFlowInstance(instance, identity, r.Generation()); err != nil {
			t.Fatal(err)
		}
		record, exists := r.LookupFlowInstance(instance)
		if !exists || record.Key != key || record.Process != identity {
			t.Fatalf("full tuple lost: %+v", record)
		}
		requireAction(t, r.DecideFlowInstance(instance), ActionProxy)
	}
	mapped := flow("[::ffff:192.0.2.1]:41000", "[::ffff:198.51.100.1]:443", TCP)
	requireError(t, r.BindFlowInstance(FlowInstance{Key: mapped, Token: 100}, identity, r.Generation()), ErrDuplicate)
	requireAction(t, r.DecideFlow(mapped), ActionProxy)
	for _, key := range []FlowKey{
		{}, flow("192.0.2.1:0", "198.51.100.1:443", TCP),
		flow("192.0.2.1:1", "198.51.100.1:0", TCP),
		flow("192.0.2.1:1", "[2001:db8::1]:443", TCP),
		flow("[fe80::1%en0]:1", "[fe80::2%en0]:443", TCP),
		flow("192.0.2.1:1", "198.51.100.1:443", Protocol(1)),
	} {
		requireError(t, r.BindFlowInstance(FlowInstance{Key: key, Token: 100}, identity, r.Generation()), ErrInvalidFlow)
		requireAction(t, r.DecideFlow(key), ActionUnknown)
	}
}

func TestFlowInstanceReuseBlocksLateOldPackets(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	routeA, sessionA, _ := addSession(t, r, "a", UDPBlock, healthy())
	routeB, sessionB, _ := addSession(t, r, "b", UDPBlock, healthy())
	a, b := ProcessIdentity{PID: 21, CreationTime: 100}, ProcessIdentity{PID: 22, CreationTime: 101}
	if err := r.RegisterRoot(a, sessionA); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterRoot(b, sessionB); err != nil {
		t.Fatal(err)
	}
	key := flow("192.0.2.1:41000", "198.51.100.1:443", TCP)
	old, replacement := FlowInstance{Key: key, Token: 10}, FlowInstance{Key: key, Token: 11}
	requireError(t, r.BindFlowInstance(FlowInstance{Key: key}, a, r.Generation()), ErrInvalidFlow)
	if err := r.BindFlowInstance(old, a, r.Generation()); err != nil {
		t.Fatal(err)
	}
	requireError(t, r.BindFlowInstance(replacement, b, r.Generation()), ErrDuplicate)
	if err := r.CloseFlowInstance(old); err != nil {
		t.Fatal(err)
	}
	if err := r.BindFlowInstance(replacement, b, r.Generation()); err != nil {
		t.Fatal(err)
	}
	oldDecision, newDecision := r.DecideFlowInstance(old), r.DecideFlowInstance(replacement)
	requireAction(t, oldDecision, ActionBlock)
	requireAction(t, newDecision, ActionProxy)
	if oldDecision.Binding.RouteID != routeA || newDecision.Binding.RouteID != routeB {
		t.Fatalf("instance ownership mixed: old=%+v, new=%+v", oldDecision, newDecision)
	}
	// A late old close cannot kill the replacement, and token-free packet
	// attribution cannot safely pass either generation of the tuple.
	if err := r.CloseFlowInstance(old); err != nil {
		t.Fatal(err)
	}
	requireAction(t, r.DecideFlowInstance(replacement), ActionProxy)
	requireAction(t, r.DecideFlow(key), ActionUnknown)
	requireError(t, r.BindFlowInstance(old, a, r.Generation()), ErrDuplicate)
	otherKey := flow("192.0.2.1:41001", "198.51.100.1:443", TCP)
	requireError(t, r.BindFlowInstance(FlowInstance{Key: otherKey, Token: old.Token}, b, r.Generation()), ErrDuplicate)
}

func TestRevocationIsOneWayAndOwnerScoped(t *testing.T) {
	for _, scope := range []string{"route", "session"} {
		t.Run(scope, func(t *testing.T) {
			r := newTestRegistry(t, DefaultLimits())
			route, session, job := addSession(t, r, "a", UDPBlock, healthy())
			_, otherSession, _ := addSession(t, r, "other", UDPBlock, healthy())
			identity, unrelated := ProcessIdentity{PID: 1, CreationTime: 1}, ProcessIdentity{PID: 2, CreationTime: 2}
			if err := r.RegisterRoot(identity, session); err != nil {
				t.Fatal(err)
			}
			if err := r.RegisterRoot(unrelated, otherSession); err != nil {
				t.Fatal(err)
			}
			instance := FlowInstance{Key: flow("192.0.2.1:41000", "198.51.100.1:443", TCP), Token: 1}
			if err := r.BindFlowInstance(instance, identity, r.Generation()); err != nil {
				t.Fatal(err)
			}
			if scope == "route" {
				if err := r.RevokeRoute(route, "owner"); err != nil {
					t.Fatal(err)
				}
				requireError(t, r.SetRouteHealth(route, "owner", healthy()), ErrRevoked)
			} else if err := r.RevokeSession(session, "owner"); err != nil {
				t.Fatal(err)
			}
			requireAction(t, r.DecideProcess(identity, TCP, false), ActionBlock)
			requireAction(t, r.DecideFlowInstance(instance), ActionBlock)
			requireAction(t, r.DecideProcess(unrelated, TCP, false), ActionProxy)
			requireError(t, r.RegisterSession(SessionSpec{ID: session, Owner: "owner", RouteID: route, JobID: job, Generation: r.Generation()}), ErrDuplicate)
			requireError(t, r.RegisterRoot(identity, otherSession), ErrDuplicate)
		})
	}
}

func TestEitherGenerationChangeRevokesAllOwnedAuthorization(t *testing.T) {
	for _, next := range []Generation{{Core: 12, Adapter: 27}, {Core: 11, Adapter: 28}} {
		r := newTestRegistry(t, DefaultLimits())
		route, session, _ := addSession(t, r, "a", UDPBlock, healthy())
		identity := ProcessIdentity{PID: 1, CreationTime: 1}
		if err := r.RegisterRoot(identity, session); err != nil {
			t.Fatal(err)
		}
		instance := FlowInstance{Key: flow("192.0.2.1:41000", "198.51.100.1:443", TCP), Token: 1}
		if err := r.BindFlowInstance(instance, identity, r.Generation()); err != nil {
			t.Fatal(err)
		}
		if changed, err := r.AdvanceGeneration(r.Generation()); changed || err != nil {
			t.Fatalf("same generation changed: changed=%v, err=%v", changed, err)
		}
		requireAction(t, r.DecideFlowInstance(instance), ActionProxy)
		if changed, err := r.AdvanceGeneration(next); !changed || err != nil {
			t.Fatalf("new generation ignored: changed=%v, err=%v", changed, err)
		}
		requireAction(t, r.DecideProcess(identity, TCP, false), ActionBlock)
		requireAction(t, r.DecideFlowInstance(instance), ActionBlock)
		requireError(t, r.SetRouteHealth(route, "owner", healthy()), ErrRevoked)
		requireError(t, r.RegisterRoute(RouteSpec{ID: "new", Owner: "owner", Generation: testGeneration, UDPPolicy: UDPBlock}), ErrInvalidGeneration)
		requireError(t, r.RegisterRoute(RouteSpec{ID: route, Owner: "owner", Generation: next, UDPPolicy: UDPBlock}), ErrDuplicate)
		requireError(t, r.ConfirmUnowned(identity, next), ErrDuplicate)
	}
}

func TestGenerationRollbackCannotReviveOldUnownedEvidence(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	identity := ProcessIdentity{PID: 10, CreationTime: 100}
	instance := FlowInstance{Key: flow("192.0.2.1:41000", "198.51.100.1:443", TCP), Token: 1}
	if err := r.ConfirmUnowned(identity, testGeneration); err != nil {
		t.Fatal(err)
	}
	if err := r.BindFlowInstance(instance, identity, testGeneration); err != nil {
		t.Fatal(err)
	}
	next := Generation{Core: testGeneration.Core + 1, Adapter: testGeneration.Adapter + 1}
	if _, err := r.AdvanceGeneration(next); err != nil {
		t.Fatal(err)
	}
	for _, rollback := range []Generation{
		testGeneration,
		{Core: next.Core + 1, Adapter: next.Adapter - 1},
		{Core: next.Core - 1, Adapter: next.Adapter + 1},
	} {
		changed, err := r.AdvanceGeneration(rollback)
		requireError(t, err, ErrInvalidGeneration)
		if changed || r.Generation() != next {
			t.Fatalf("rollback mutated generation: %v, current=%+v", changed, r.Generation())
		}
		requireAction(t, r.DecideProcess(identity, TCP, false), ActionUnknown)
		requireAction(t, r.DecideFlowInstance(instance), ActionUnknown)
	}
}

func TestCapacityCountsTombstonesAndNeverEvicts(t *testing.T) {
	for _, scope := range []string{"route", "session", "process", "flow"} {
		t.Run(scope, func(t *testing.T) {
			limits := DefaultLimits()
			switch scope {
			case "route":
				limits.Routes = 1
			case "session":
				limits.Sessions = 1
			case "process":
				limits.Processes = 1
			case "flow":
				limits.Flows = 1
			}
			r := newTestRegistry(t, limits)
			route, session, _ := addSession(t, r, "a", UDPBlock, healthy())
			identity := ProcessIdentity{PID: 1, CreationTime: 1}
			if err := r.RegisterRoot(identity, session); err != nil {
				t.Fatal(err)
			}
			key := flow("192.0.2.1:41000", "198.51.100.1:443", TCP)
			instance := FlowInstance{Key: key, Token: 1}
			if err := r.BindFlowInstance(instance, identity, r.Generation()); err != nil {
				t.Fatal(err)
			}
			switch scope {
			case "route":
				if err := r.RevokeRoute(route, "owner"); err != nil {
					t.Fatal(err)
				}
				requireError(t, r.RegisterRoute(RouteSpec{ID: "new", Owner: "owner", Generation: r.Generation(), UDPPolicy: UDPBlock}), ErrCapacity)
			case "session":
				if err := r.RevokeSession(session, "owner"); err != nil {
					t.Fatal(err)
				}
				requireError(t, r.RegisterSession(SessionSpec{ID: "new", Owner: "owner", RouteID: route, JobID: "new-job", Generation: r.Generation()}), ErrCapacity)
			case "process":
				if err := r.RevokeProcess(identity); err != nil {
					t.Fatal(err)
				}
				requireError(t, r.RegisterRoot(ProcessIdentity{PID: 2, CreationTime: 2}, session), ErrCapacity)
			case "flow":
				if err := r.CloseFlowInstance(instance); err != nil {
					t.Fatal(err)
				}
				requireError(t, r.BindFlowInstance(FlowInstance{Key: key, Token: 2}, identity, r.Generation()), ErrCapacity)
			}
			requireAction(t, r.DecideFlowInstance(instance), ActionBlock)
			if record, exists := r.LookupFlowInstance(instance); !exists || record.State != StateRevoked {
				t.Fatalf("capacity pressure evicted tombstone: %+v, exists=%v", record, exists)
			}
		})
	}
}

func TestConcurrentRevocationNeverResurrectsOwnedDecisions(t *testing.T) {
	r := newTestRegistry(t, DefaultLimits())
	_, session, job := addSession(t, r, "a", UDPBlock, healthy())
	root := ProcessIdentity{PID: 1, CreationTime: 1}
	if err := r.RegisterRoot(root, session); err != nil {
		t.Fatal(err)
	}
	start, revoked := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	errors := make(chan string, 32)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			child := ProcessIdentity{PID: uint32(worker + 10), CreationTime: uint64(worker + 10)}
			err := r.InheritChild(child, root, job)
			if err != nil && err != ErrRevoked {
				errors <- fmt.Sprintf("inherit failed: %v", err)
				return
			}
			instance := FlowInstance{Key: flow(fmt.Sprintf("192.0.2.1:%d", 42000+worker), "198.51.100.1:443", TCP), Token: uint64(worker + 1)}
			err = r.BindFlowInstance(instance, child, r.Generation())
			if err != nil && err != ErrRevoked {
				errors <- fmt.Sprintf("bind failed: %v", err)
				return
			}
			for i := 0; i < 100; i++ {
				_ = r.DecideProcess(child, TCP, false)
				_ = r.DecideFlowInstance(instance)
			}
			<-revoked
			for i := 0; i < 100; i++ {
				if got := r.DecideProcess(child, TCP, false); got.Action != ActionBlock {
					errors <- fmt.Sprintf("revoked child became usable: %+v", got)
					return
				}
				if got := r.DecideFlowInstance(instance); got.Action == ActionProxy || got.Action == ActionDirect {
					errors <- fmt.Sprintf("revoked flow became usable: %+v", got)
					return
				}
			}
		}(worker)
	}
	close(start)
	if err := r.RevokeSession(session, "owner"); err != nil {
		t.Fatal(err)
	}
	close(revoked)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
