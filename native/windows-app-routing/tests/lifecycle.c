#include <stdint.h>
#include <stddef.h>
#include <assert.h>
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uint16_t UINT16;
typedef unsigned char UCHAR;
typedef unsigned char BOOLEAN;
typedef void VOID;
#include "../driver/envara_wire.h"
#include "../driver/envara_lifecycle.h"

_Static_assert(sizeof(ENVARA_STATUS)==40,"status ABI");
_Static_assert(sizeof(ENVARA_ROUTE_REQUEST)==48,"register ABI");
_Static_assert(sizeof(ENVARA_REDIRECT_CONTEXT)==48,"redirect ABI");
_Static_assert(sizeof(ENVARA_PROCESS_QUERY)==24,"process query ABI");
_Static_assert(sizeof(ENVARA_PROCESS_ROUTE)==24,"process response ABI");
_Static_assert(offsetof(ENVARA_REDIRECT_CONTEXT,address)==28,"redirect IP offset");

int main(void) {
    ENVARA_LIFECYCLE state={0};
    UINT64 oldEpoch;
    assert(!EnvaraLifecycleAllows(&state,0,1));
    EnvaraLifecycleInvalidate(&state);
    assert(!EnvaraLifecycleRebuilt(&state,0,1,1));
    assert(!EnvaraLifecycleRebuilt(&state,1,0,1));
    assert(!EnvaraLifecycleRebuilt(&state,1,1,0));
    assert(EnvaraLifecycleRebuilt(&state,1,1,1));
    oldEpoch=state.generation;
    assert(EnvaraLifecycleAllows(&state,oldEpoch,1));
    EnvaraLifecycleInvalidate(&state);
    assert(!EnvaraLifecycleAllows(&state,oldEpoch,1));
    assert(EnvaraLifecycleRebuilt(&state,1,1,1));
    assert(!EnvaraLifecycleAllows(&state,oldEpoch,1));
    assert(!EnvaraLifecycleAllows(&state,state.generation,0));
    assert(EnvaraLifecycleAllows(&state,state.generation,1));
    return 0;
}
