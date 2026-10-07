#ifndef ENVARA_CAPTURE_CORE_H
#define ENVARA_CAPTURE_CORE_H
#include "envara_capture.h"
#include <stddef.h>
#define ENVARA_MAX_OWNERS 4096u
#define ENVARA_MAX_REVOKED 256u
typedef struct {
    uint32_t used, pid, decision, reserved;
    uint64_t creation_time, process_handle, route_tag, session_tag, generation;
} EnvaraCoreIdentity;
typedef struct {
    uint32_t used, identity_index;
    uint64_t endpoint_id;
    uint64_t event_timestamp;
    EnvaraTuple tuple;
} EnvaraCoreOwner;
typedef struct {
    uint32_t used, claimed, identity_index, reserved;
    uint32_t fin_mask, initial_sequence;
    uint64_t flow_id, last_seen, closed_at;
    EnvaraTuple original, accepted;
} EnvaraCoreFlow;
typedef struct { uint64_t session_tag, generation; } EnvaraCoreRevoked;
typedef struct {
    EnvaraCoreIdentity identities[ENVARA_CAPTURE_MAX_IDENTITIES];
    EnvaraCoreOwner owners[ENVARA_MAX_OWNERS];
    EnvaraCoreFlow flows[ENVARA_CAPTURE_MAX_FLOWS];
    EnvaraCoreRevoked revoked[ENVARA_MAX_REVOKED];
    uint64_t next_flow;
    uint32_t next_alias, relay_port;
} EnvaraCore;
void envara_core_init(EnvaraCore *, uint16_t relay_port);
int envara_endpoint_equal(const EnvaraEndpoint *, const EnvaraEndpoint *);
int envara_tuple_equal(const EnvaraTuple *, const EnvaraTuple *);
int envara_tuple_valid(const EnvaraTuple *);
uint32_t envara_core_identity(EnvaraCore *, const EnvaraIdentityRequest *, const EnvaraIdentityResult *, uint32_t *);
uint32_t envara_core_owner(EnvaraCore *, uint64_t endpoint, const EnvaraTuple *, uint32_t identity_index);
uint32_t envara_core_owner_event(EnvaraCore *, uint64_t endpoint, const EnvaraTuple *, uint32_t identity_index, uint64_t event_timestamp);
void envara_core_close_owner(EnvaraCore *, uint64_t endpoint);
void envara_core_remove_identity(EnvaraCore *, uint32_t index, uint64_t now);
uint32_t envara_core_decision(const EnvaraCore *, const EnvaraTuple *, uint32_t *identity_index);
uint32_t envara_core_decision_at(const EnvaraCore *, const EnvaraTuple *, uint64_t packet_timestamp, uint32_t *identity_index);
uint32_t envara_core_revoke(EnvaraCore *, uint64_t session, uint64_t generation);
uint32_t envara_core_forward(EnvaraCore *, const EnvaraTuple *, uint32_t identity_index, uint64_t now,
    EnvaraTuple *rewritten, uint64_t *flow_id);
uint32_t envara_core_reverse(EnvaraCore *, const EnvaraTuple *, uint64_t now, EnvaraTuple *rewritten);
uint32_t envara_core_lookup(EnvaraCore *, const EnvaraTuple *, EnvaraRelayResult *);
int envara_core_has_original(const EnvaraCore *, const EnvaraTuple *, uint32_t *identity_index);
void envara_core_mark_closed(EnvaraCore *, const EnvaraTuple *, uint64_t now);
void envara_core_note_tcp(EnvaraCore *, const EnvaraTuple *, int reverse, int fin, int rst, uint64_t now);
void envara_core_retire_original(EnvaraCore *, const EnvaraTuple *, uint64_t now);
void envara_core_expire(EnvaraCore *, uint64_t now);
#endif
