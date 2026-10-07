package ownership

import "sync"

// Registry is safe for concurrent platform event and packet callbacks. It never
// discovers ownership from an executable name, proxy environment, or PID alone.
type Registry struct {
	mu           sync.RWMutex
	limits       Limits
	generation   Generation
	routes       map[RouteID]RouteRecord
	sessions     map[SessionID]SessionRecord
	jobs         map[JobID]SessionID
	processes    map[ProcessIdentity]ProcessRecord
	currentPID   map[uint32]ProcessIdentity
	flows        map[FlowInstance]FlowRecord
	currentFlows map[FlowKey]FlowInstance
	flowTokens   map[uint64]bool
	reusedFlows  map[FlowKey]bool
}

func NewRegistry(limits Limits, generation Generation) (*Registry, error) {
	if limits.Routes <= 0 || limits.Sessions <= 0 || limits.Processes <= 0 || limits.Flows <= 0 {
		return nil, ErrInvalidLimits
	}
	if !generation.Valid() {
		return nil, ErrInvalidGeneration
	}
	return &Registry{limits: limits, generation: generation, routes: make(map[RouteID]RouteRecord),
		sessions: make(map[SessionID]SessionRecord), jobs: make(map[JobID]SessionID),
		processes: make(map[ProcessIdentity]ProcessRecord), currentPID: make(map[uint32]ProcessIdentity),
		flows: make(map[FlowInstance]FlowRecord), currentFlows: make(map[FlowKey]FlowInstance),
		flowTokens: make(map[uint64]bool), reusedFlows: make(map[FlowKey]bool)}, nil
}

func (r *Registry) Generation() Generation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.generation
}

func (r *Registry) RegisterRoute(spec RouteSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !validID(string(spec.ID)) || !validID(string(spec.Owner)) {
		return ErrInvalidID
	}
	if spec.Generation != r.generation {
		return ErrInvalidGeneration
	}
	if spec.UDPPolicy != UDPBlock && spec.UDPPolicy != UDPProxy {
		return ErrInvalidPolicy
	}
	if _, exists := r.routes[spec.ID]; exists {
		return ErrDuplicate
	}
	if len(r.routes) >= r.limits.Routes {
		return ErrCapacity
	}
	r.routes[spec.ID] = RouteRecord{RouteSpec: spec, State: StateActive}
	return nil
}

func (r *Registry) SetRouteHealth(id RouteID, owner OwnerID, health RouteHealth) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.routes[id]
	if !exists {
		return ErrNotFound
	}
	if record.Owner != owner {
		return ErrOwnerMismatch
	}
	if record.State != StateActive || record.Generation != r.generation {
		return ErrRevoked
	}
	record.Health = health
	r.routes[id] = record
	return nil
}

func (r *Registry) RegisterSession(spec SessionSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !validID(string(spec.ID)) || !validID(string(spec.Owner)) || !validID(string(spec.JobID)) {
		return ErrInvalidID
	}
	if spec.Generation != r.generation {
		return ErrInvalidGeneration
	}
	if _, exists := r.sessions[spec.ID]; exists {
		return ErrDuplicate
	}
	if _, exists := r.jobs[spec.JobID]; exists {
		return ErrDuplicate
	}
	route, exists := r.routes[spec.RouteID]
	if !exists {
		return ErrNotFound
	}
	if route.Owner != spec.Owner {
		return ErrOwnerMismatch
	}
	if route.State != StateActive || route.Generation != r.generation {
		return ErrRevoked
	}
	if len(r.sessions) >= r.limits.Sessions {
		return ErrCapacity
	}
	r.sessions[spec.ID] = SessionRecord{SessionSpec: spec, State: StateActive}
	r.jobs[spec.JobID] = spec.ID
	return nil
}

// RegisterRoot must succeed while the platform-owned process is suspended and
// before it can send traffic. The adapter has already assigned its nonbreakaway
// Job and verified the real creation timestamp.
func (r *Registry) RegisterRoot(identity ProcessIdentity, sessionID SessionID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.canRegisterProcess(identity); err != nil {
		return err
	}
	session, exists := r.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}
	if session.State != StateActive || session.Generation != r.generation {
		return ErrRevoked
	}
	route := r.routes[session.RouteID]
	if route.State != StateActive || route.Generation != r.generation {
		return ErrRevoked
	}
	r.storeProcess(ProcessRecord{Identity: identity, Ownership: OwnershipOwned, Binding: sessionBinding(session),
		Generation: r.generation, State: StateActive})
	return nil
}

// RegisterJobMember registers an observed process in an existing owned Job.
// The platform must first use the retained, exact process HANDLE and actual Job
// HANDLE to verify IsProcessInJob; this API cannot attest caller evidence. It
// does not invent a parent identity when a Job notification omitted one. A late
// verified member of a revoked Job is retained as owned+revoked and returns
// ErrRevoked, so it cannot subsequently be confirmed unowned.
func (r *Registry) RegisterJobMember(identity ProcessIdentity, sessionID SessionID, verifiedJob JobID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.canRegisterProcess(identity); err != nil {
		return err
	}
	session, exists := r.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}
	if !validID(string(verifiedJob)) || session.JobID != verifiedJob {
		return ErrJobMismatch
	}
	binding := sessionBinding(session)
	state := StateActive
	if session.State != StateActive || session.Generation != r.generation || !r.bindingActive(binding) {
		state = StateRevoked
	}
	r.storeProcess(ProcessRecord{Identity: identity, Ownership: OwnershipOwned, Binding: binding,
		Generation: session.Generation, State: state})
	if state == StateRevoked {
		return ErrRevoked
	}
	return nil
}

// InheritChild accepts only a platform-observed exact parent identity and a
// verified Job membership. Calling it with user-supplied parent/Job claims is
// unsafe. A late child of a revoked parent remains owned and revoked: the
// tombstone is stored even though this call returns ErrRevoked.
func (r *Registry) InheritChild(child, parent ProcessIdentity, verifiedJob JobID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.canRegisterProcess(child); err != nil {
		return err
	}
	if !parent.Valid() || child == parent {
		return ErrInvalidIdentity
	}
	parentRecord, exists := r.processes[parent]
	if !exists || parentRecord.Ownership != OwnershipOwned {
		return ErrUnknownProcess
	}
	if !validID(string(verifiedJob)) || parentRecord.Binding.JobID != verifiedJob {
		return ErrJobMismatch
	}
	state := StateActive
	if parentRecord.State != StateActive || parentRecord.Generation != r.generation || !r.bindingActive(parentRecord.Binding) {
		state = StateRevoked
	}
	r.storeProcess(ProcessRecord{Identity: child, Parent: parent, Ownership: OwnershipOwned, Binding: parentRecord.Binding,
		Generation: parentRecord.Generation, State: state})
	if state == StateRevoked {
		return ErrRevoked
	}
	return nil
}

// ConfirmUnowned is only for a successful trusted platform observation that the
// exact process is outside every owned Job and tree. Failure to query ownership
// is not evidence. A current generation prevents stale observations from being
// turned into DIRECT after an adapter/core restart.
func (r *Registry) ConfirmUnowned(identity ProcessIdentity, generation Generation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation {
		return ErrInvalidGeneration
	}
	if record, exists := r.processes[identity]; exists && record.Ownership == OwnershipUnowned &&
		record.State == StateActive && record.Generation != r.generation {
		record.Generation = generation
		r.processes[identity] = record
		return nil
	}
	if err := r.canRegisterProcess(identity); err != nil {
		return err
	}
	r.storeProcess(ProcessRecord{Identity: identity, Ownership: OwnershipUnowned, Generation: generation, State: StateActive})
	return nil
}

func (r *Registry) canRegisterProcess(identity ProcessIdentity) error {
	if !identity.Valid() {
		return ErrInvalidIdentity
	}
	if _, exists := r.processes[identity]; exists {
		return ErrDuplicate
	}
	if current, exists := r.currentPID[identity.PID]; exists && current != identity && r.processes[current].State == StateActive {
		return ErrPIDConflict
	}
	if len(r.processes) >= r.limits.Processes {
		return ErrCapacity
	}
	return nil
}

func (r *Registry) storeProcess(record ProcessRecord) {
	r.processes[record.Identity] = record
	r.currentPID[record.Identity.PID] = record.Identity
}

func sessionBinding(session SessionRecord) Binding {
	return Binding{RouteID: session.RouteID, SessionID: session.ID, Owner: session.Owner, JobID: session.JobID}
}

func (r *Registry) bindingActive(binding Binding) bool {
	session, ok := r.sessions[binding.SessionID]
	if !ok || session.State != StateActive || session.Generation != r.generation || sessionBinding(session) != binding {
		return false
	}
	route, ok := r.routes[binding.RouteID]
	return ok && route.State == StateActive && route.Generation == r.generation && route.Owner == binding.Owner
}

func (r *Registry) BindFlow(key FlowKey, identity ProcessIdentity, generation Generation) error {
	return r.bindFlow(FlowInstance{Key: key}, identity, generation, true)
}

func (r *Registry) BindFlowInstance(instance FlowInstance, identity ProcessIdentity, generation Generation) error {
	return r.bindFlow(instance, identity, generation, false)
}

func (r *Registry) bindFlow(instance FlowInstance, identity ProcessIdentity, generation Generation, legacy bool) error {
	key, err := instance.Key.canonical()
	if err != nil {
		return err
	}
	if !legacy && instance.Token == 0 {
		return ErrInvalidFlow
	}
	instance.Key = key
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation {
		return ErrInvalidGeneration
	}
	if !identity.Valid() {
		return ErrInvalidIdentity
	}
	process, exists := r.processes[identity]
	if !exists {
		return ErrUnknownProcess
	}
	if process.State != StateActive {
		return ErrRevoked
	}
	if process.Generation != r.generation {
		return ErrInvalidGeneration
	}
	if process.Ownership == OwnershipOwned && !r.bindingActive(process.Binding) {
		return ErrRevoked
	}
	if previous, exists := r.flows[instance]; exists {
		// Only refresh stale, confirmed-unowned evidence for the very same
		// process; owned/tombstoned tuples cannot be overwritten or revived.
		if previous.Ownership == OwnershipUnowned && previous.State == StateActive && previous.Process == identity && previous.Generation != generation {
			previous.Generation = generation
			r.flows[instance] = previous
			return nil
		}
		return ErrDuplicate
	}
	if instance.Token != 0 && r.flowTokens[instance.Token] {
		return ErrDuplicate
	}
	if current, exists := r.currentFlows[key]; exists {
		// A nonzero, new platform token is required to reuse a closed tuple.
		// Legacy tuple-only records never authorize tuple reuse.
		if legacy || current.Token == 0 || r.flows[current].State == StateActive {
			return ErrDuplicate
		}
	}
	if len(r.flows) >= r.limits.Flows {
		return ErrCapacity
	}
	if _, exists := r.currentFlows[key]; exists {
		r.reusedFlows[key] = true
	}
	r.currentFlows[key] = instance
	if instance.Token != 0 {
		r.flowTokens[instance.Token] = true
	}
	r.flows[instance] = FlowRecord{Key: key, Token: instance.Token, Process: identity, Ownership: process.Ownership, Binding: process.Binding,
		Generation: generation, State: StateActive}
	return nil
}

// CloseFlow closes the current tuple instance. An adapter handling endpoint
// lifecycle events should use CloseFlowInstance so an old close event cannot
// accidentally revoke a newer socket with the same tuple.
func (r *Registry) CloseFlow(key FlowKey) error {
	key, err := key.canonical()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	instance, exists := r.currentFlows[key]
	if !exists {
		return ErrNotFound
	}
	record := r.flows[instance]
	record.State = StateRevoked
	r.flows[instance] = record
	return nil
}

func (r *Registry) CloseFlowInstance(instance FlowInstance) error {
	key, err := instance.Key.canonical()
	if err != nil || instance.Token == 0 {
		return ErrInvalidFlow
	}
	instance.Key = key
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.flows[instance]
	if !exists {
		return ErrNotFound
	}
	record.State = StateRevoked
	r.flows[instance] = record
	return nil
}

func (r *Registry) RevokeRoute(id RouteID, owner OwnerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.routes[id]
	if !exists {
		return ErrNotFound
	}
	if record.Owner != owner {
		return ErrOwnerMismatch
	}
	record.State = StateRevoked
	r.routes[id] = record
	for sessionID, session := range r.sessions {
		if session.RouteID == id {
			r.revokeSession(sessionID)
		}
	}
	return nil
}

func (r *Registry) RevokeSession(id SessionID, owner OwnerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.sessions[id]
	if !exists {
		return ErrNotFound
	}
	if record.Owner != owner {
		return ErrOwnerMismatch
	}
	r.revokeSession(id)
	return nil
}

func (r *Registry) revokeSession(id SessionID) {
	session := r.sessions[id]
	session.State = StateRevoked
	r.sessions[id] = session
	for identity, record := range r.processes {
		if record.Ownership == OwnershipOwned && record.Binding.SessionID == id {
			record.State = StateRevoked
			r.processes[identity] = record
		}
	}
	for key, flow := range r.flows {
		if flow.Ownership == OwnershipOwned && flow.Binding.SessionID == id {
			flow.State = StateRevoked
			r.flows[key] = flow
		}
	}
}

// RevokeProcess also revokes already observed descendants. A platform process
// exit or failed tree verification must not leave a usable inherited binding.
func (r *Registry) RevokeProcess(identity ProcessIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !identity.Valid() {
		return ErrInvalidIdentity
	}
	if _, exists := r.processes[identity]; !exists {
		return ErrNotFound
	}
	queue := []ProcessIdentity{identity}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		record := r.processes[current]
		record.State = StateRevoked
		r.processes[current] = record
		for child, childRecord := range r.processes {
			if childRecord.Parent == current {
				queue = append(queue, child)
			}
		}
		for key, flow := range r.flows {
			if flow.Process == current {
				flow.State = StateRevoked
				r.flows[key] = flow
			}
		}
	}
	return nil
}

// AdvanceGeneration revokes all owned authorization when either managed
// instance changes. A same-generation observation is a no-op. Unrelated
// evidence becomes UNKNOWN until the platform confirms it in the new epoch.
func (r *Registry) AdvanceGeneration(generation Generation) (bool, error) {
	if !generation.Valid() {
		return false, ErrInvalidGeneration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation.Core < r.generation.Core || generation.Adapter < r.generation.Adapter {
		return false, ErrInvalidGeneration
	}
	if generation == r.generation {
		return false, nil
	}
	for id, route := range r.routes {
		route.State = StateRevoked
		r.routes[id] = route
	}
	for id := range r.sessions {
		r.revokeSession(id)
	}
	r.generation = generation
	return true, nil
}

func (r *Registry) Route(id RouteID) (RouteRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.routes[id]
	return record, exists
}

func (r *Registry) Session(id SessionID) (SessionRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.sessions[id]
	return record, exists
}

func (r *Registry) Process(identity ProcessIdentity) (ProcessRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.processes[identity]
	return record, exists
}

func (r *Registry) LookupFlow(key FlowKey) (FlowRecord, bool) {
	key, err := key.canonical()
	if err != nil {
		return FlowRecord{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	instance, exists := r.currentFlows[key]
	if !exists {
		return FlowRecord{}, false
	}
	record := r.flows[instance]
	return record, exists
}

func (r *Registry) LookupFlowInstance(instance FlowInstance) (FlowRecord, bool) {
	key, err := instance.Key.canonical()
	if err != nil || instance.Token == 0 {
		return FlowRecord{}, false
	}
	instance.Key = key
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.flows[instance]
	return record, exists
}

func (r *Registry) DecideProcess(identity ProcessIdentity, protocol Protocol, dns bool) Decision {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.decideProcess(identity, protocol, dns)
}

func (r *Registry) decideProcess(identity ProcessIdentity, protocol Protocol, dns bool) Decision {
	decision := Decision{Action: ActionUnknown, Reason: ReasonUnknownOwnership, Process: identity,
		Ownership: OwnershipUnknown, Generation: r.generation, DNS: dns}
	if !identity.Valid() {
		decision.Reason = ReasonInvalidIdentity
		return decision
	}
	if protocol != TCP && protocol != UDP {
		decision.Reason = ReasonInvalidFlow
		return decision
	}
	process, exists := r.processes[identity]
	if !exists {
		return decision
	}
	decision.Ownership, decision.Binding, decision.State = process.Ownership, process.Binding, process.State
	if process.State != StateActive {
		decision.Action, decision.Reason = ActionBlock, ReasonRevoked
		return decision
	}
	if process.Generation != r.generation {
		if process.Ownership == OwnershipOwned {
			decision.Action = ActionBlock
		}
		decision.Reason = ReasonGenerationChanged
		return decision
	}
	if process.Ownership == OwnershipUnowned {
		decision.Action, decision.Reason = ActionDirect, ReasonConfirmedUnowned
		return decision
	}
	decision.Action = ActionBlock
	if !r.bindingActive(process.Binding) {
		decision.Reason = ReasonRevoked
		return decision
	}
	route := r.routes[process.Binding.RouteID]
	if !route.Health.ProxyReady {
		decision.Reason = ReasonProxyUnavailable
		return decision
	}
	if dns {
		if !route.Health.DNSAdapterReady {
			decision.Reason = ReasonDNSUnavailable
			return decision
		}
	} else if protocol == UDP {
		if route.UDPPolicy == UDPBlock {
			decision.Reason = ReasonUDPBlocked
			return decision
		}
		if !route.Health.UDPReady {
			decision.Reason = ReasonUDPUnavailable
			return decision
		}
	}
	decision.Action, decision.Reason = ActionProxy, ReasonOwnedRoute
	return decision
}

func (r *Registry) DecideFlow(key FlowKey) Decision {
	key, err := key.canonical()
	if err != nil {
		return Decision{Action: ActionUnknown, Reason: ReasonInvalidFlow, Ownership: OwnershipUnknown}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.reusedFlows[key] {
		// Token-free attribution cannot distinguish delayed packets after a
		// socket reuses a five-tuple. Do not guess from the current record.
		return Decision{Action: ActionUnknown, Reason: ReasonUnknownOwnership, Ownership: OwnershipUnknown, Generation: r.generation, DNS: key.IsDNS()}
	}
	instance, exists := r.currentFlows[key]
	if !exists {
		return Decision{Action: ActionUnknown, Reason: ReasonUnknownOwnership, Ownership: OwnershipUnknown, Generation: r.generation, DNS: key.IsDNS()}
	}
	return r.decideFlow(r.flows[instance])
}

func (r *Registry) DecideFlowInstance(instance FlowInstance) Decision {
	key, err := instance.Key.canonical()
	if err != nil || instance.Token == 0 {
		return Decision{Action: ActionUnknown, Reason: ReasonInvalidFlow, Ownership: OwnershipUnknown}
	}
	instance.Key = key
	r.mu.RLock()
	defer r.mu.RUnlock()
	flow, exists := r.flows[instance]
	if !exists {
		return Decision{Action: ActionUnknown, Reason: ReasonUnknownOwnership, Ownership: OwnershipUnknown, Generation: r.generation, DNS: key.IsDNS()}
	}
	return r.decideFlow(flow)
}

func (r *Registry) decideFlow(flow FlowRecord) Decision {
	decision := r.decideProcess(flow.Process, flow.Key.Protocol, flow.Key.IsDNS())
	if flow.State != StateActive {
		decision.Action, decision.Reason, decision.State = ActionBlock, ReasonRevoked, StateRevoked
		return decision
	}
	if flow.Generation != r.generation {
		decision.Action, decision.Reason = ActionUnknown, ReasonGenerationChanged
		if flow.Ownership == OwnershipOwned {
			decision.Action = ActionBlock
		}
		return decision
	}
	// A record mismatch is never authorization to use another process's route.
	if decision.Ownership != flow.Ownership || decision.Binding != flow.Binding {
		decision.Action, decision.Reason = ActionBlock, ReasonRevoked
	}
	return decision
}
