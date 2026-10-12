/* Test-only: use the exact factory implementation's local preparation
 * functions. No installed root entry, store mutation, PF or child launch. */
#include "app-native-factory.h"
static int envara_factory_fixture_registered_app(struct envara_app_native_factory *);
static int envara_factory_fixture_verify_mode(struct envara_app_native_factory *, EnvaraPFProductionMode, int);
#define ENVARA_APP_FACTORY_TICKET_INERT 1
#include "app-native-factory.m"
#include "pf-run-ledger.h"

int envara_factory_fixture_parse_hook(const char *, size_t);
size_t envara_factory_fixture_hook(char output[ENVARA_PF_RUN_LEASE_LIMIT + 1]);

/* Compile-only seam around the actual ticket_verify function. No authority
 * from these fixture booleans exists in the production executable. */
static unsigned bundle_calls, mode_calls, live_calls;
static int bundle_valid=1, pf_valid=1, lease_valid=1, identity_valid=1;
static int envara_factory_fixture_registered_app(struct envara_app_native_factory *f) {
    (void)f;bundle_calls++;return bundle_valid;
}
static int envara_factory_fixture_verify_mode(struct envara_app_native_factory *f,EnvaraPFProductionMode mode,int live) {
    mode_calls++;if(live)live_calls++;
    return !f->poisoned&&pf_valid&&lease_valid&&identity_valid&&f->mode==mode;
}
static int staged_ticket_fixture(void) {
    struct envara_app_native_factory f={0};
    strcpy(f.plan.run_id,"00000000-0000-4000-8000-000000000003");
    memset(f.plan.lease_sha256,'a',64);f.plan.lease_sha256[64]=0;
    f.app.schema=1;f.request.schema=ENVARA_GUI_SCHEMA;f.mode=ENVARA_PF_PRODUCTION_FRONT;
    /* This seam exercises the Notion front profile explicitly. A zero-initialised factory selects the generic cold profile, whose live mode is ROUTED. */
    f.notion_front=1;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)||bundle_calls!=1||mode_calls!=1||live_calls!=1)return 50;
    bundle_valid=0;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1||bundle_calls!=2||mode_calls!=1)return 51;
    f.staged=1;bundle_calls=mode_calls=live_calls=0;
    for(unsigned i=0;i<1000;i++)if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f))return 52;
    if(bundle_calls||mode_calls!=1000||live_calls)return 53;
    unsigned before=mode_calls;pf_valid=0;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1||mode_calls!=before+2)return 54;
    pf_valid=1;lease_valid=0;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1)return 55;
    lease_valid=1;identity_valid=0;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1)return 56;
    identity_valid=1;f.poisoned=1;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1)return 57;
    f.poisoned=0;f.mode=ENVARA_PF_PRODUCTION_DENY;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f))return 58;
    f.mode=ENVARA_PF_PRODUCTION_EMPTY;
    if(ticket_verify(&f.app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1)return 59;
    f.mode=ENVARA_PF_PRODUCTION_FRONT;before=mode_calls;
    struct envara_app_registration app=f.app;app.schema++;
    struct envara_gui_request request=f.request;request.console_uid++;
    char hash[65];strcpy(hash,f.plan.lease_sha256);hash[0]='b';
    if(ticket_verify(&app,&f.request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1||
       ticket_verify(&f.app,&request,f.plan.run_id,f.plan.lease_sha256,&f)!=-1||
       ticket_verify(&f.app,&f.request,"00000000-0000-4000-8000-000000000004",f.plan.lease_sha256,&f)!=-1||
       ticket_verify(&f.app,&f.request,f.plan.run_id,hash,&f)!=-1||mode_calls!=before||bundle_calls)return 60;
    puts("{\"ok\":true,\"stagedChecks\":1000,\"stagedBundleAudits\":0,\"prestageBundleAuditRetained\":true,\"freshPFLeaseIdentityRefusals\":true,\"bindingMismatchesRefusedBeforeAudit\":true,\"ready\":false,\"protected\":false,\"root\":false,\"pf\":false}");
    return 0;
}

static int diagnostic_recovery_fixture(void) {
    envara_app_native_failure_begin();errno=ENOENT;
    if(operation_refuse("NATIVE_NOTION_DATA_PREPARE_REFUSED",EACCES)!=-1||errno!=EACCES)return 61;
    if(operation_refuse("NATIVE_JOURNAL_REFUSED",EIO)!=-1||errno!=EIO||
        strcmp(envara_app_native_failure_reason(),"NATIVE_NOTION_DATA_PREPARE_REFUSED")||envara_app_native_failure_error(errno)!=EACCES)return 62;
    envara_app_native_failure_begin();if(envara_app_native_failure_error(ESTALE)!=ESTALE||strcmp(envara_app_native_failure_reason(),"NATIVE_OPERATION_REFUSED"))return 63;
    struct envara_app_native_preflight p;errno=ENOSPC;
    if(envara_app_native_preflight("00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000004",&p)!=-1||errno!=EACCES||
        strcmp(envara_app_native_failure_reason(),"NATIVE_CONTEXT_LOAD_REFUSED"))return 64;
    struct envara_app_native_factory f={.owner=getpid(),.pending_intent=1,.poisoned=1};
    if(cleanup_outcome(&f)!=1)return 65;
    f.pending_write_attempted=1;if(cleanup_outcome(&f)!=1)return 66;
    f.pending_result.begun=1;f.pending_result.uncertain=1;
    if(cleanup_outcome(&f))return 67;
    f.pending_result.rollback_acknowledged=1;f.pending_result.verified=1;
    if(cleanup_outcome(&f))return 68;
    f.pending_result.uncertain=0;f.pending_result.committed=1;f.pending_result.ticket_known=1;f.pending_result.writer_pid=getpid();
    if(cleanup_outcome(&f)!=2)return 69;
    f.pending_result.writer_pid++;if(cleanup_outcome(&f))return 70;f.pending_result.writer_pid=getpid();
    f.pending_intent=0;if(cleanup_outcome(&f))return 71;f.pending_intent=1;
    f.owner++;if(cleanup_outcome(&f))return 72;f.owner=getpid();f.cleanup_only=1;
    if(envara_app_native_factory_provider(&f)||!f.poisoned)return 73;
    f.poisoned=0;if(envara_app_native_factory_provider(&f))return 74;
    puts("{\"ok\":true,\"firstFailureSurvivesCleanup\":true,\"preflightErrnoPreserved\":true,\"knownOutcomeOnly\":true,\"unknownAndRollbackAckRemainRefused\":true,\"cleanupCannotRestoreProvider\":true,\"root\":false,\"pf\":false,\"ready\":false,\"protected\":false}");return 0;
}
static int json_fixture(void) {
    char bytes[ENVARA_PF_RUN_LEASE_LIMIT + 1]; size_t size = envara_factory_fixture_hook(bytes);
    if (!size || envara_factory_fixture_parse_hook(bytes, size) != 1) return 10;
    NSDictionary *hook = decode(bytes, size); if (!hook) return 11;
    NSData *legacy = [NSJSONSerialization dataWithJSONObject:hook options:0 error:NULL];
    if (!legacy || !memchr(legacy.bytes, '\\', legacy.length) || envara_factory_fixture_parse_hook(legacy.bytes, legacy.length) != 0) return 12;
    NSData *current = serialize_hook(hook);
    if (!current || envara_factory_fixture_parse_hook(current.bytes, current.length) != 1) return 13;
    NSMutableDictionary *foreign = [hook mutableCopy]; foreign[@"runId"] = @"00000000-0000-4000-8000-000000000003";
    NSData *invalid = serialize_hook(foreign);
    if (!invalid || envara_factory_fixture_parse_hook(invalid.bytes, invalid.length) != 0) return 14;
    foreign = [hook mutableCopy]; foreign[@"ticket"] = @123456;
    invalid = serialize_hook(foreign);
    if (!invalid || envara_factory_fixture_parse_hook(invalid.bytes, invalid.length) != 0) return 15;
    foreign = [hook mutableCopy]; foreign[@"unexpected"] = @"must-refuse";
    invalid = serialize_hook(foreign);
    if (!invalid || envara_factory_fixture_parse_hook(invalid.bytes, invalid.length) != 0) return 16;
    puts("{\"ok\":true,\"legacyEscapesRefused\":true,\"fixedSerializationAccepted\":true,\"foreignAndMalformedRefused\":true,\"ready\":false,\"protected\":false}");
    return 0;
}
static NSDictionary *roundtrip(NSDictionary *value,int manifest) {
    NSData *bytes=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingWithoutEscapingSlashes error:NULL];
    return bytes?(manifest?decode_manifest(bytes.bytes,bytes.length):decode(bytes.bytes,bytes.length)):nil;
}
static NSMutableDictionary *members(unsigned count) {
    NSMutableDictionary *value=[NSMutableDictionary dictionary];
    for(unsigned i=0;i<count;i++)value[[NSString stringWithFormat:@"source%u",i]]=@0;
    return value;
}
static int manifest_fixture(const char *path) {
    NSData *bytes=[NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    if(!bytes||decode(bytes.bytes,bytes.length)!=nil)return 30; /* exact old 64-key bound */
    NSDictionary *manifest=decode_manifest(bytes.bytes,bytes.length);
    if(!manifest||![manifest[@"schema"] isEqual:@"envara.macos-pf-installation/v1"]||
       [manifest[@"nativeSourceFiles"] count]!=65||[manifest[@"files"] count]!=18||
       ![manifest[@"files"][@"envara-pf-native"] isEqual:@"f8631ecf1421c5a5fdb644400a895e4a42f9ee24b23051c10ed607d817aa6399"])return 31;
    NSMutableDictionary *candidate=[manifest mutableCopy];
    candidate[@"nativeSourceFiles"]=members(128);if(!roundtrip(candidate,1))return 32;
    candidate[@"nativeSourceFiles"]=members(129);if(roundtrip(candidate,1))return 33;
    /* Both private record families retain the old limit, including nested objects. */
    for(NSString *family in @[@"lease",@"registry"]){
        if(!roundtrip(@{family:members(64)},0)||roundtrip(@{family:members(65)},0))return 34;
    }
    NSMutableString *duplicate=[NSMutableString stringWithString:@"{\"nativeSourceFiles\":{"];
    for(unsigned i=0;i<65;i++)[duplicate appendFormat:@"%s\"source%u\":0",i?",":"",i];
    [duplicate appendString:@",\"source0\":1}}"];
    NSData *invalid=[duplicate dataUsingEncoding:NSUTF8StringEncoding];
    if(decode_manifest(invalid.bytes,invalid.length))return 35; /* duplicate beyond old bound */
    const char *escaped="{\"a\":1,\"\\u0061\":2}";
    if(decode_manifest(escaped,strlen(escaped)))return 36;
    NSMutableArray *array=[NSMutableArray array];for(unsigned i=0;i<64;i++)[array addObject:@0];
    if(!roundtrip(@{@"entries":array},0)||!roundtrip(@{@"entries":array},1))return 37;
    [array addObject:@0];if(roundtrip(@{@"entries":array},0)||roundtrip(@{@"entries":array},1))return 38;
    /* 1 root + 63 arrays + 63*64 scalar nodes equals the unchanged 4096-node bound. */
    [array removeLastObject];NSMutableDictionary *nodes=[NSMutableDictionary dictionary];
    for(unsigned i=0;i<63;i++)nodes[[NSString stringWithFormat:@"group%u",i]]=array;
    if(!roundtrip(nodes,1))return 39;
    nodes[@"extra"]=@[];if(roundtrip(nodes,1))return 40;
    char *oversized=malloc(RECORD_LIMIT+1);if(!oversized)return 41;
    memset(oversized,' ',RECORD_LIMIT+1);memcpy(oversized,"{}",2);
    int refused=decode_manifest(oversized,RECORD_LIMIT+1)==nil;free(oversized);if(!refused)return 42;
    id nested=@0;for(unsigned i=0;i<21;i++)nested=@{@"nested":nested};
    if(roundtrip(nested,1))return 43;
    puts("{\"ok\":true,\"actualC37SourceCount\":65,\"oldBoundRefused\":true,\"manifestAccepted\":true,\"manifest128Accepted129Refused\":true,\"leaseAndRegistry64Retained\":true,\"duplicatesRefused\":true,\"arraysNodesBytesDepthRetained\":true,\"root\":false,\"pf\":false,\"ready\":false,\"protected\":false}");
    return 0;
}
static int application_fixture(const char *cwd) {
    struct envara_app_native_factory f = {0};
    if (envara_gui_manifest_inspect("/Applications/Notion.app", 0, &f.app.snapshot)) return 20;
    f.request.schema = ENVARA_GUI_SCHEMA; f.request.console_uid = getuid(); f.request.realm_gid = ENVARA_REALM_GID_MIN;
    strcpy(f.request.lease_id, "00000000-0000-4000-8000-000000000003");
    strcpy(f.request.environment_id, "00000000-0000-4000-8000-000000000004");
    if (!realpath(cwd, f.request.cwd)) return 21;
    strcpy(f.request.timezone, "Asia/Manila"); strcpy(f.request.browser_locale, "en-PH");
    if (envara_gui_request_validate(&f.app.snapshot, &f.request, 0) != 0 || envara_notion_supported(&f.app.snapshot) != 0 || application_prepared(&f) != 1) return 22;
    strcpy(f.request.timezone, "../must-refuse"); if (application_prepared(&f) != 0) return 23;
    strcpy(f.request.timezone, "Asia/Manila"); strcpy(f.app.snapshot.identifier, "io.envara.unsupported");
    if (application_prepared(&f) != 0) return 24;
    puts("{\"ok\":true,\"actualNotionZeroSuccessAccepted\":true,\"invalidRequestAndUnsupportedAppRefused\":true,\"readOnly\":true,\"ready\":false,\"protected\":false}");
    return 0;
}
int main(int argc, char **argv) {
    if (!getuid() || getuid() != geteuid() || argc < 2) return 90;
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "staged-ticket")) return staged_ticket_fixture();
        if (argc == 2 && !strcmp(argv[1], "diagnostic-recovery")) return diagnostic_recovery_fixture();
        if (argc == 2 && !strcmp(argv[1], "json")) return json_fixture();
        if (argc == 3 && !strcmp(argv[1], "manifest")) return manifest_fixture(argv[2]);
        if (argc == 3 && !strcmp(argv[1], "application")) return application_fixture(argv[2]);
    }
    return 91;
}
