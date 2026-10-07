/* Pure transition rules shared by the driver and local portable C tests. */
#pragma once

typedef struct ENVARA_LIFECYCLE {
    UINT64 generation;
    UINT32 enforcing;
    UINT32 drained;
} ENVARA_LIFECYCLE;

/* Caller holds tableLock. Invalidating an epoch cannot be undone by heartbeat. */
static __inline VOID EnvaraLifecycleInvalidate(ENVARA_LIFECYCLE* state) {
    state->enforcing=0;
    state->drained=0;
    state->generation++;
    if(state->generation==0) state->generation=1;
}

/* Restoring BFE never restores an old route or a surviving process tree. */
static __inline BOOLEAN EnvaraLifecycleRebuilt(ENVARA_LIFECYCLE* state,
    BOOLEAN bfeRunning,BOOLEAN filtersVerified,BOOLEAN processesDrained) {
    state->drained=processesDrained ? 1u : 0u;
    state->enforcing=(bfeRunning && filtersVerified && processesDrained) ? 1u : 0u;
    return state->enforcing!=0;
}

static __inline BOOLEAN EnvaraLifecycleAllows(const ENVARA_LIFECYCLE* state,
    UINT64 routeGeneration,BOOLEAN routeActive) {
    return state->enforcing!=0 && state->drained!=0 && routeActive && routeGeneration==state->generation;
}
