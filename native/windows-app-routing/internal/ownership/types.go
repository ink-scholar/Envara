// Package ownership contains fail-closed routing policy. It does not inspect
// Windows processes, enforce a packet verdict, or attest an adapter's health.
// Only the trusted platform adapter may supply process and Job observations.
package ownership

import (
	"errors"
	"net/netip"
	"strings"
)

type RouteID string
type SessionID string
type OwnerID string
type JobID string

// ProcessIdentity uses the platform process creation timestamp, not an
// executable name or a PID alone. CreationTime is Windows FILETIME when used
// by the Windows adapter.
type ProcessIdentity struct {
	PID          uint32
	CreationTime uint64
}

func (p ProcessIdentity) Valid() bool { return p.PID != 0 && p.CreationTime != 0 }

// Generation identifies the actual managed core and packet adapter instances
// with monotonically increasing counters. Neither value may be zero. Never use
// a reusable PID as a counter. Old observations cannot create authorization.
type Generation struct {
	Core    uint64
	Adapter uint64
}

func (g Generation) Valid() bool { return g.Core != 0 && g.Adapter != 0 }

type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
)

type Ownership string

const (
	OwnershipUnknown Ownership = "unknown"
	OwnershipOwned   Ownership = "owned"
	OwnershipUnowned Ownership = "unowned"
)

type UDPPolicy string

const (
	UDPBlock UDPPolicy = "block"
	UDPProxy UDPPolicy = "proxy"
)

// RouteHealth is supplied by verified platform/core observations. A successful
// config parse or modelled unit test must never set these readiness flags.
type RouteHealth struct {
	ProxyReady      bool
	DNSAdapterReady bool
	UDPReady        bool
}

type RouteSpec struct {
	ID         RouteID
	Owner      OwnerID
	Generation Generation
	UDPPolicy  UDPPolicy
	Health     RouteHealth
}

type RouteRecord struct {
	RouteSpec
	State State
}

type SessionSpec struct {
	ID         SessionID
	Owner      OwnerID
	RouteID    RouteID
	JobID      JobID
	Generation Generation
}

type SessionRecord struct {
	SessionSpec
	State State
}

// Binding is immutable once a process or flow is registered. It contains only
// opaque identity; proxy passwords and listener credentials do not belong here.
type Binding struct {
	RouteID   RouteID
	SessionID SessionID
	Owner     OwnerID
	JobID     JobID
}

type ProcessRecord struct {
	Identity   ProcessIdentity
	Parent     ProcessIdentity
	Ownership  Ownership
	Binding    Binding
	Generation Generation
	State      State
}

type Protocol uint8

const (
	TCP Protocol = 6
	UDP Protocol = 17
)

// FlowKey is an outbound, real five-tuple observed before any relay rewriting.
// The addresses are kept with their ports, including for IPv6. It is not a
// synthetic hash of a destination or a local proxy port.
type FlowKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Protocol    Protocol
}

// canonical rejects zone names (packet headers do not contain them) and
// normalizes IPv4-mapped addresses so one tuple cannot obtain two identities.
func (f FlowKey) canonical() (FlowKey, error) {
	if !f.Source.IsValid() || !f.Destination.IsValid() || f.Source.Port() == 0 || f.Destination.Port() == 0 ||
		(f.Protocol != TCP && f.Protocol != UDP) || f.Source.Addr().Zone() != "" || f.Destination.Addr().Zone() != "" {
		return FlowKey{}, ErrInvalidFlow
	}
	f.Source = netip.AddrPortFrom(f.Source.Addr().Unmap(), f.Source.Port())
	f.Destination = netip.AddrPortFrom(f.Destination.Addr().Unmap(), f.Destination.Port())
	if f.Source.Addr().Is4() != f.Destination.Addr().Is4() {
		return FlowKey{}, ErrInvalidFlow
	}
	return f, nil
}

func (f FlowKey) Valid() bool { _, err := f.canonical(); return err == nil }
func (f FlowKey) IsDNS() bool { return f.Destination.IsValid() && f.Destination.Port() == 53 }

// FlowInstance binds a real tuple to a unique platform endpoint/socket token.
// Tokens must be nonzero and never reused during a Registry's lifetime. Packet
// attribution must distinguish this token; a tuple alone is ambiguous on reuse.
type FlowInstance struct {
	Key   FlowKey
	Token uint64
}

type FlowRecord struct {
	Key        FlowKey
	Token      uint64
	Process    ProcessIdentity
	Ownership  Ownership
	Binding    Binding
	Generation Generation
	State      State
}

type Action string

const (
	ActionUnknown Action = "UNKNOWN"
	ActionDirect  Action = "DIRECT"
	ActionProxy   Action = "PROXY"
	ActionBlock   Action = "BLOCK"
)

type Reason string

const (
	ReasonUnknownOwnership  Reason = "ownership-unknown"
	ReasonConfirmedUnowned  Reason = "platform-confirmed-unowned"
	ReasonOwnedRoute        Reason = "owned-route"
	ReasonInvalidIdentity   Reason = "invalid-process-identity"
	ReasonInvalidFlow       Reason = "invalid-flow"
	ReasonRevoked           Reason = "revoked"
	ReasonGenerationChanged Reason = "generation-changed"
	ReasonProxyUnavailable  Reason = "proxy-unavailable"
	ReasonDNSUnavailable    Reason = "dns-adapter-unavailable"
	ReasonUDPBlocked        Reason = "udp-policy-block"
	ReasonUDPUnavailable    Reason = "udp-proxy-unavailable"
)

// Decision is a snapshot, not permission to send later. The packet adapter must
// serialize/revalidate a verdict with revocation before releasing any packet.
// UNKNOWN must be dropped or held for trustworthy attribution, never passed.
// DIRECT applies only to confirmed unrelated processes and preserves their
// existing platform path; it does not instruct the host to bypass other VPNs.
// DNS with PROXY requires the owned DNS adapter, not an ordinary SOCKS relay.
type Decision struct {
	Action     Action
	Reason     Reason
	Process    ProcessIdentity
	Ownership  Ownership
	Binding    Binding
	Generation Generation
	State      State
	DNS        bool
}

// Limits count active entries and tombstones together. No capacity eviction is
// allowed: dropping a revoked identity could turn its delayed packets into an
// unowned decision. Start a new, quiesced platform instance to clear the table.
type Limits struct {
	Routes    int
	Sessions  int
	Processes int
	Flows     int
}

func DefaultLimits() Limits { return Limits{Routes: 64, Sessions: 256, Processes: 4096, Flows: 16384} }

var (
	ErrInvalidIdentity   = errors.New("invalid process identity")
	ErrInvalidID         = errors.New("invalid opaque identity")
	ErrInvalidGeneration = errors.New("invalid or stale generation")
	ErrInvalidLimits     = errors.New("all capacities must be positive")
	ErrInvalidPolicy     = errors.New("an explicit UDP policy is required")
	ErrInvalidFlow       = errors.New("invalid real flow tuple")
	ErrDuplicate         = errors.New("identity already registered")
	ErrPIDConflict       = errors.New("PID already belongs to another active process identity")
	ErrCapacity          = errors.New("ownership registry capacity exhausted")
	ErrNotFound          = errors.New("identity not registered")
	ErrUnknownProcess    = errors.New("process ownership is unknown")
	ErrOwnerMismatch     = errors.New("owner binding does not match")
	ErrJobMismatch       = errors.New("verified Job binding does not match")
	ErrRevoked           = errors.New("ownership has been revoked")
)

func validID(s string) bool { return len(s) <= 256 && strings.TrimSpace(s) != "" }
