/* Envara-owned identity, generation, NAT alias and lease implementation.
 * TCP address/port swapping follows ProxyBridge's MIT packet relay technique.
 * See PROVENANCE.md and LICENSE. No executable-name rule implementation used. */
#include "capture_core.h"
#include <string.h>
#include <limits.h>
_Static_assert(sizeof(EnvaraEndpoint)==20, "endpoint ABI");
_Static_assert(sizeof(EnvaraTuple)==48, "tuple ABI");
_Static_assert(sizeof(EnvaraIdentityRequest)==32, "request ABI");
_Static_assert(sizeof(EnvaraIdentityResult)==40, "result ABI");
_Static_assert(sizeof(EnvaraCaptureConfig)==32, "config ABI");
_Static_assert(sizeof(EnvaraRelayQuery)==56, "relay query ABI");
_Static_assert(sizeof(EnvaraRelayResult)==104, "relay result ABI");
_Static_assert(sizeof(EnvaraRevokeRequest)==24, "revoke ABI");
_Static_assert(sizeof(EnvaraCaptureStatus)==104, "status ABI");

static int address_zero(const EnvaraEndpoint *ep) {
    static const uint8_t zero[16]={0};
    return memcmp(ep->address,zero,ep->family==4?4:16)==0;
}
int envara_endpoint_equal(const EnvaraEndpoint *a,const EnvaraEndpoint *b) {
    return a->family==b->family && a->port==b->port &&
        memcmp(a->address,b->address,a->family==4?4:16)==0;
}
int envara_tuple_equal(const EnvaraTuple *a,const EnvaraTuple *b) {
    return a->protocol==b->protocol && envara_endpoint_equal(&a->source,&b->source) &&
        envara_endpoint_equal(&a->destination,&b->destination);
}
int envara_tuple_valid(const EnvaraTuple *t) {
    static const uint8_t zero[7]={0};
    return (t->source.family==4 || t->source.family==6) &&
        t->source.family==t->destination.family && t->source.port && t->destination.port &&
        (t->protocol==6 || t->protocol==17) && !t->source.reserved && !t->destination.reserved &&
        memcmp(t->reserved,zero,sizeof(zero))==0;
}
void envara_core_init(EnvaraCore *c,uint16_t relay_port) {
    memset(c,0,sizeof(*c)); c->relay_port=relay_port; c->next_alias=20000; c->next_flow=1;
}
static int revoked(const EnvaraCore *c,uint64_t session,uint64_t gen) {
    uint32_t i;
    for(i=0;i<ENVARA_MAX_REVOKED;i++)
        if(c->revoked[i].session_tag==session && c->revoked[i].generation>=gen) return 1;
    return 0;
}
uint32_t envara_core_identity(EnvaraCore *c,const EnvaraIdentityRequest *r,const EnvaraIdentityResult *v,uint32_t *index) {
    uint32_t i,slot=UINT32_MAX;
    if(r->version!=ENVARA_CAPTURE_ABI || r->size!=sizeof(*r) || !r->pid || !r->creation_time ||
       r->reserved || v->reserved || v->version!=ENVARA_CAPTURE_ABI || v->size!=sizeof(*v) || v->decision>ENVARA_ID_BLOCKED)
        return ENVARA_ERR_IDENTITY;
    if(v->decision==ENVARA_ID_UNKNOWN) return ENVARA_ERR_IDENTITY;
    if(v->decision==ENVARA_ID_OWNED && (!v->route_tag || !v->session_tag || !v->generation))
        return ENVARA_ERR_IDENTITY;
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++) {
        EnvaraCoreIdentity *id=&c->identities[i];
        if(!id->used) { if(slot==UINT32_MAX)slot=i; continue; }
        if(id->pid==r->pid && id->creation_time==r->creation_time) { slot=i; break; }
    }
    if(slot==UINT32_MAX) return ENVARA_ERR_CAPACITY;
    {
        EnvaraCoreIdentity *id=&c->identities[slot];
        /* A live identity cannot migrate between environments or revive from a
         * blocked tombstone. The caller must stop that process and launch anew. */
        if(id->used && (id->decision==ENVARA_ID_BLOCKED ||
            (id->decision==ENVARA_ID_OWNED && (id->route_tag!=v->route_tag ||
             id->session_tag!=v->session_tag || id->generation!=v->generation)))) {
            id->decision=ENVARA_ID_BLOCKED; *index=slot; return ENVARA_OK;
        }
        if(!id->used) id->process_handle=r->process_handle;
        id->used=1; id->pid=r->pid; id->creation_time=r->creation_time;
        id->decision=v->decision; id->route_tag=v->route_tag;
        id->session_tag=v->session_tag; id->generation=v->generation;
        if(v->session_tag && revoked(c,v->session_tag,v->generation)) id->decision=ENVARA_ID_BLOCKED;
        *index=slot;
    }
    return ENVARA_OK;
}
uint32_t envara_core_owner(EnvaraCore *c,uint64_t endpoint,const EnvaraTuple *tuple,uint32_t identity) {
    return envara_core_owner_event(c,endpoint,tuple,identity,0);
}
uint32_t envara_core_owner_event(EnvaraCore *c,uint64_t endpoint,const EnvaraTuple *tuple,uint32_t identity,uint64_t event_timestamp) {
    uint32_t i,slot=UINT32_MAX;static const uint8_t zero[7]={0};
    if(!endpoint || identity>=ENVARA_CAPTURE_MAX_IDENTITIES || !c->identities[identity].used ||
       !(tuple->protocol==6 || tuple->protocol==17) || !tuple->source.port ||
       !(tuple->source.family==4 || tuple->source.family==6) || tuple->source.family!=tuple->destination.family ||
       tuple->source.reserved || tuple->destination.reserved || memcmp(tuple->reserved,zero,sizeof(zero)))return ENVARA_ERR_ARGUMENT;
    for(i=0;i<ENVARA_MAX_OWNERS;i++) {
        if(c->owners[i].used && c->owners[i].endpoint_id==endpoint) { slot=i; break; }
        if(!c->owners[i].used && slot==UINT32_MAX) slot=i;
    }
    if(slot==UINT32_MAX) return ENVARA_ERR_CAPACITY;
    c->owners[slot].used=1; c->owners[slot].endpoint_id=endpoint;
    c->owners[slot].tuple=*tuple; c->owners[slot].identity_index=identity;
    c->owners[slot].event_timestamp=event_timestamp;
    return ENVARA_OK;
}
void envara_core_close_owner(EnvaraCore *c,uint64_t endpoint) {
    uint32_t i; for(i=0;i<ENVARA_MAX_OWNERS;i++)
        if(c->owners[i].used && c->owners[i].endpoint_id==endpoint) c->owners[i].used=0;
}
void envara_core_remove_identity(EnvaraCore *c,uint32_t index,uint64_t now) {
    uint32_t i;
    if(index>=ENVARA_CAPTURE_MAX_IDENTITIES)return;
    for(i=0;i<ENVARA_MAX_OWNERS;i++)if(c->owners[i].used && c->owners[i].identity_index==index)c->owners[i].used=0;
    /* Leave closed NAT tombstones for late packets; they will be blocked because
     * their identity was removed, and cleared after the close lease. */
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++)if(c->flows[i].used && c->flows[i].identity_index==index) {
        c->flows[i].identity_index=UINT32_MAX;
        c->flows[i].closed_at=now?now:1;
    }
    memset(&c->identities[index],0,sizeof(c->identities[index]));
}
uint32_t envara_core_decision(const EnvaraCore *c,const EnvaraTuple *tuple,uint32_t *index) {
    return envara_core_decision_at(c,tuple,0,index);
}
uint32_t envara_core_decision_at(const EnvaraCore *c,const EnvaraTuple *tuple,uint64_t packet_timestamp,uint32_t *index) {
    uint32_t i,found=UINT32_MAX; int exact=0;
    for(i=0;i<ENVARA_MAX_OWNERS;i++) {
        const EnvaraCoreOwner *o=&c->owners[i]; int match_exact;
        if(!o->used || (packet_timestamp && (!o->event_timestamp || o->event_timestamp>packet_timestamp)) ||
           o->tuple.protocol!=tuple->protocol || o->tuple.source.family!=tuple->source.family ||
           o->tuple.source.port!=tuple->source.port)continue;
        if(!address_zero(&o->tuple.source) && !envara_endpoint_equal(&o->tuple.source,&tuple->source))continue;
        match_exact=o->tuple.destination.port!=0;
        if(match_exact && !envara_endpoint_equal(&o->tuple.destination,&tuple->destination))continue;
        if(exact && !match_exact)continue;
        if(match_exact && !exact) { found=UINT32_MAX; exact=1; }
        if(found!=UINT32_MAX && found!=o->identity_index)return ENVARA_ID_UNKNOWN;
        found=o->identity_index;
    }
    if(found==UINT32_MAX || found>=ENVARA_CAPTURE_MAX_IDENTITIES || !c->identities[found].used)return ENVARA_ID_UNKNOWN;
    *index=found; return c->identities[found].decision;
}
uint32_t envara_core_revoke(EnvaraCore *c,uint64_t session,uint64_t gen) {
    uint32_t i,slot=UINT32_MAX;
    if(!session || !gen)return ENVARA_ERR_ARGUMENT;
    for(i=0;i<ENVARA_MAX_REVOKED;i++) {
        if(c->revoked[i].session_tag==session) {slot=i;break;}
        if(!c->revoked[i].session_tag && slot==UINT32_MAX)slot=i;
    }
    if(slot==UINT32_MAX)return ENVARA_ERR_CAPACITY;
    c->revoked[slot].session_tag=session;
    if(c->revoked[slot].generation<gen)c->revoked[slot].generation=gen;
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++) {
        EnvaraCoreIdentity *id=&c->identities[i];
        if(id->used && id->session_tag==session && id->generation<=gen)id->decision=ENVARA_ID_BLOCKED;
    }
    return ENVARA_OK;
}
int envara_core_has_original(const EnvaraCore *c,const EnvaraTuple *t,uint32_t *index) {
    uint32_t i;for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++)
        if(c->flows[i].used && !c->flows[i].reserved && envara_tuple_equal(&c->flows[i].original,t)) {*index=c->flows[i].identity_index;return 1;}
    return 0;
}
static int flow_live(const EnvaraCore *c,const EnvaraCoreFlow *f) {
    return f->identity_index<ENVARA_CAPTURE_MAX_IDENTITIES && c->identities[f->identity_index].used &&
        c->identities[f->identity_index].decision==ENVARA_ID_OWNED;
}
uint32_t envara_core_forward(EnvaraCore *c,const EnvaraTuple *t,uint32_t identity,uint64_t now,EnvaraTuple *out,uint64_t *flow_id) {
    uint32_t i,slot=UINT32_MAX;
    if(!envara_tuple_valid(t) || t->protocol!=6 || identity>=ENVARA_CAPTURE_MAX_IDENTITIES ||
       !c->identities[identity].used || c->identities[identity].decision!=ENVARA_ID_OWNED)return ENVARA_ERR_IDENTITY;
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {
        EnvaraCoreFlow *f=&c->flows[i];
        if(!f->used) {if(slot==UINT32_MAX)slot=i;continue;}
        if(!f->reserved && envara_tuple_equal(&f->original,t)) {
            if(f->identity_index!=identity || !flow_live(c,f))return ENVARA_ERR_IDENTITY;
            f->last_seen=now; *out=f->accepted; *flow_id=f->flow_id; return ENVARA_OK;
        }
    }
    if(slot==UINT32_MAX || c->next_alias>65535 || c->next_flow==UINT64_MAX)return ENVARA_ERR_CAPACITY;
    if(c->next_alias==c->relay_port)c->next_alias++;
    if(c->next_alias>65535)return ENVARA_ERR_CAPACITY;
    {
        EnvaraCoreFlow *f=&c->flows[slot]; memset(f,0,sizeof(*f));
        f->used=1; f->original=*t; f->identity_index=identity; f->flow_id=c->next_flow++; f->last_seen=now;
        f->accepted.protocol=6; f->accepted.source=t->destination; f->accepted.destination=t->source;
        f->accepted.source.port=(uint16_t)c->next_alias++; f->accepted.destination.port=(uint16_t)c->relay_port;
        *out=f->accepted; *flow_id=f->flow_id;
    }
    return ENVARA_OK;
}
uint32_t envara_core_reverse(EnvaraCore *c,const EnvaraTuple *t,uint64_t now,EnvaraTuple *out) {
    uint32_t i; EnvaraTuple flipped=*t;
    flipped.source=t->destination; flipped.destination=t->source;
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {
        EnvaraCoreFlow *f=&c->flows[i];
        if(!f->used || !envara_tuple_equal(&flipped,&f->accepted))continue;
        if(!flow_live(c,f))return ENVARA_ERR_IDENTITY;
        *out=f->original; out->source=f->original.destination; out->destination=f->original.source;
        f->last_seen=now;return ENVARA_OK;
    }
    return ENVARA_ERR_NOT_FOUND;
}
uint32_t envara_core_lookup(EnvaraCore *c,const EnvaraTuple *t,EnvaraRelayResult *out) {
    uint32_t i;
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {
        EnvaraCoreFlow *f=&c->flows[i]; EnvaraCoreIdentity *id;
        if(!f->used || !envara_tuple_equal(t,&f->accepted))continue;
        if(!flow_live(c,f) || f->claimed)return ENVARA_ERR_IDENTITY;
        id=&c->identities[f->identity_index];
        memset(out,0,sizeof(*out));out->size=sizeof(*out);out->version=ENVARA_CAPTURE_ABI;
        out->flow_id=f->flow_id;out->route_tag=id->route_tag;out->session_tag=id->session_tag;
        out->generation=id->generation;out->pid=id->pid;out->creation_time=id->creation_time;out->original=f->original;
        f->claimed=1;return ENVARA_OK;
    }
    return ENVARA_ERR_NOT_FOUND;
}
void envara_core_mark_closed(EnvaraCore *c,const EnvaraTuple *tuple,uint64_t now) {
    uint32_t i;for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++)if(c->flows[i].used && envara_tuple_equal(&c->flows[i].original,tuple)) {
        c->flows[i].closed_at=now?now:1;return;
    }
}
void envara_core_note_tcp(EnvaraCore *c,const EnvaraTuple *tuple,int reverse,int fin,int rst,uint64_t now) {
    uint32_t i;EnvaraTuple flipped=*tuple;
    if(reverse){flipped.source=tuple->destination;flipped.destination=tuple->source;}
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {
        EnvaraCoreFlow *f=&c->flows[i];
        if(!f->used || !(reverse?envara_tuple_equal(&f->accepted,&flipped):
            (!f->reserved && envara_tuple_equal(&f->original,tuple))))continue;
        if(fin)f->fin_mask|=reverse?2u:1u;
        if(rst || f->fin_mask==3u)f->closed_at=now?now:1;
        return;
    }
}
void envara_core_retire_original(EnvaraCore *c,const EnvaraTuple *tuple,uint64_t now) {
    uint32_t i;for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++)if(c->flows[i].used &&
        !c->flows[i].reserved && envara_tuple_equal(&c->flows[i].original,tuple)) {
        c->flows[i].reserved=1;c->flows[i].closed_at=now?now:1;
    }
}
void envara_core_expire(EnvaraCore *c,uint64_t now) {
    uint32_t i;for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {
        EnvaraCoreFlow *f=&c->flows[i];
        /* No idle eviction of living streams. Never reuse NAT aliases within a
         * capture run, including after a closed flow's two-minute packet lease. */
        if(f->used && f->closed_at && now>=f->closed_at && now-f->closed_at>=120000)memset(f,0,sizeof(*f));
    }
}
