#include "capture_core.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static EnvaraTuple tuple(uint8_t family,uint16_t sport,uint16_t dport) {
    EnvaraTuple t;memset(&t,0,sizeof(t));t.protocol=6;
    t.source.family=t.destination.family=family;t.source.port=sport;t.destination.port=dport;
    if(family==4) {t.source.address[0]=10;t.source.address[3]=5;t.destination.address[0]=203;t.destination.address[1]=0;t.destination.address[2]=113;t.destination.address[3]=7;}
    else {t.source.address[0]=0x20;t.source.address[1]=1;t.source.address[15]=5;t.destination.address[0]=0x20;t.destination.address[1]=1;t.destination.address[15]=7;}
    return t;
}
static uint32_t identity(EnvaraCore *c,uint32_t pid,uint64_t birth,uint32_t decision,uint64_t session,uint64_t gen) {
    EnvaraIdentityRequest r={0};EnvaraIdentityResult v={0};uint32_t id;
    r.size=sizeof(r);r.version=1;r.pid=pid;r.creation_time=birth;
    v.size=sizeof(v);v.version=1;v.decision=decision;v.route_tag=decision==ENVARA_ID_OWNED?41:0;
    v.session_tag=session;v.generation=gen;
    assert(envara_core_identity(c,&r,&v,&id)==ENVARA_OK);return id;
}
static void nat_roundtrip(EnvaraCore *c,uint8_t family,uint32_t id,uint16_t sport) {
    EnvaraTuple orig=tuple(family,sport,443),nat,reply,restored,wrong;
    EnvaraRelayResult lookup={0};uint64_t flow;
    assert(envara_core_owner(c,1000+sport,&orig,id)==ENVARA_OK);
    assert(envara_core_forward(c,&orig,id,100,&nat,&flow)==ENVARA_OK);
    assert(nat.source.port!=orig.source.port && nat.destination.port==19444);
    assert(memcmp(nat.source.address,orig.destination.address,family==4?4:16)==0);
    wrong=nat;wrong.source.address[family==4?3:15]^=1;
    assert(envara_core_lookup(c,&wrong,&lookup)==ENVARA_ERR_NOT_FOUND);
    wrong=nat;wrong.destination.address[family==4?3:15]^=1;
    assert(envara_core_lookup(c,&wrong,&lookup)==ENVARA_ERR_NOT_FOUND);
    wrong=nat;wrong.protocol=17;assert(envara_core_lookup(c,&wrong,&lookup)==ENVARA_ERR_NOT_FOUND);
    assert(envara_core_lookup(c,&nat,&lookup)==ENVARA_OK);
    assert(lookup.flow_id==flow && lookup.pid==42 && lookup.creation_time==100 && lookup.session_tag==51 && lookup.generation==1);
    assert(envara_tuple_equal(&lookup.original,&orig));
    assert(envara_core_lookup(c,&nat,&lookup)==ENVARA_ERR_IDENTITY); /* one accepted stream */
    reply=nat;reply.source=nat.destination;reply.destination=nat.source;
    assert(envara_core_reverse(c,&reply,200,&restored)==ENVARA_OK);
    assert(envara_endpoint_equal(&restored.source,&orig.destination));
    assert(envara_endpoint_equal(&restored.destination,&orig.source));
    envara_core_mark_closed(c,&orig,200);
    envara_core_expire(c,120199);assert(envara_core_has_original(c,&orig,&id));
    envara_core_expire(c,120200);assert(!envara_core_has_original(c,&orig,&id));
}
int main(void) {
    EnvaraCore *c=(EnvaraCore*)calloc(1,sizeof(*c));uint32_t owned,unowned,id,reused,i;
    EnvaraTuple orig,nat,reply,other;EnvaraRelayResult result;uint64_t flow;
    assert(c);envara_core_init(c,19444);
    owned=identity(c,42,100,ENVARA_ID_OWNED,51,1);
    nat_roundtrip(c,4,owned,35001);nat_roundtrip(c,6,owned,35002);
    unowned=identity(c,99,100,ENVARA_ID_UNOWNED,0,0);
    orig=tuple(4,36000,443);assert(envara_core_owner(c,1,&orig,owned)==0);
    other=orig;other.destination.address[3]++;
    assert(envara_core_owner(c,2,&other,unowned)==0);
    assert(envara_core_decision(c,&orig,&id)==ENVARA_ID_OWNED && id==owned);
    assert(envara_core_decision(c,&other,&id)==ENVARA_ID_UNOWNED && id==unowned);
    assert(envara_core_decision_at(c,&other,50,&id)==ENVARA_ID_UNKNOWN); /* snapshots cannot authorize packets */
    assert(envara_core_owner_event(c,2,&other,unowned,100)==0);
    assert(envara_core_decision_at(c,&other,99,&id)==ENVARA_ID_UNKNOWN); /* later tuple rebinding */
    assert(envara_core_decision_at(c,&other,100,&id)==ENVARA_ID_UNOWNED && id==unowned);
    {EnvaraTuple invalid=orig;invalid.reserved[1]=1;assert(!envara_tuple_valid(&invalid));}
    other.destination.port++;assert(envara_core_decision(c,&other,&id)==ENVARA_ID_UNKNOWN);
    assert(envara_core_forward(c,&orig,owned,300,&nat,&flow)==0);
    assert(envara_core_revoke(c,51,1)==0);
    assert(envara_core_decision(c,&orig,&id)==ENVARA_ID_BLOCKED);
    assert(envara_core_lookup(c,&nat,&result)==ENVARA_ERR_IDENTITY);
    reply=nat;reply.source=nat.destination;reply.destination=nat.source;
    assert(envara_core_reverse(c,&reply,400,&other)==ENVARA_ERR_IDENTITY);
    assert(identity(c,42,100,ENVARA_ID_OWNED,51,2)==owned);
    assert(c->identities[owned].decision==ENVARA_ID_BLOCKED); /* no tombstone revival */
    reused=identity(c,42,101,ENVARA_ID_OWNED,52,1);assert(reused!=owned);
    assert(envara_core_owner(c,1,&orig,reused)==0);
    assert(envara_core_forward(c,&orig,reused,400,&other,&flow)==ENVARA_ERR_IDENTITY);
    envara_core_retire_original(c,&orig,400);
    assert(envara_core_forward(c,&orig,reused,401,&other,&flow)==0);
    assert(other.source.port!=nat.source.port); /* never recycle alias */
    assert(envara_core_revoke(c,53,1)==0);
    id=identity(c,43,101,ENVARA_ID_OWNED,53,1);assert(c->identities[id].decision==ENVARA_ID_BLOCKED); /* callback-revoke race */
    envara_core_remove_identity(c,reused,500);
    assert(envara_core_lookup(c,&other,&result)==ENVARA_ERR_IDENTITY);
    envara_core_expire(c,120500);
    assert(!envara_core_has_original(c,&orig,&id)); /* process exit reclaims closed lease */
    envara_core_init(c,19444);owned=identity(c,42,100,ENVARA_ID_OWNED,51,1);orig=tuple(6,35000,443);
    assert(envara_core_forward(c,&orig,owned,1,&nat,&flow)==0);
    envara_core_note_tcp(c,&orig,0,1,0,100);
    envara_core_expire(c,130000);assert(envara_core_has_original(c,&orig,&id)); /* half-close stays live */
    reply=nat;reply.source=nat.destination;reply.destination=nat.source;
    envara_core_note_tcp(c,&reply,1,1,0,130001);
    envara_core_expire(c,250000);assert(envara_core_has_original(c,&orig,&id));
    envara_core_expire(c,250001);assert(!envara_core_has_original(c,&orig,&id));
    envara_core_init(c,19444);
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++)identity(c,i+1,i+1,ENVARA_ID_UNOWNED,0,0);
    {EnvaraIdentityRequest r={sizeof(r),1,99999,0,99999,0};EnvaraIdentityResult v={sizeof(v),1,1,0,0,0,0};
     assert(envara_core_identity(c,&r,&v,&id)==ENVARA_ERR_CAPACITY);}
    envara_core_init(c,19444);owned=identity(c,42,100,ENVARA_ID_OWNED,51,1);orig=tuple(4,35000,443);
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++) {orig.destination.port=(uint16_t)(i+1);assert(envara_core_forward(c,&orig,owned,1,&nat,&flow)==0);}
    orig.destination.port=60000;assert(envara_core_forward(c,&orig,owned,1,&nat,&flow)==ENVARA_ERR_CAPACITY);
    free(c);puts("capture core: v4/v6 NAT, full tuple lookup, event timestamp, single claim, PID reuse, revoke race, FIN/process leases and capacity passed");return 0;
}
