import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');

test('fixed application recovery validates sealed shape and preserves uncertainty without privilege', async () => {
  assert.notEqual(process.getuid(), 0, 'Inert tests must never run as root.');
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-recovery46-inert-'));
  try {
    const harness = path.join(temp, 'inert.m'), binary = path.join(temp, 'inert');
    await writeFile(harness, `
#define RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-46ae-run904.m')}"
#include <assert.h>
static NSMutableDictionary *clone(NSDictionary*v){return [[NSJSONSerialization JSONObjectWithData:[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL] options:NSJSONReadingMutableContainers error:NULL]mutableCopy];}
static NSDictionary *rootLease(void){NSString*id=@"62d7b9b9-019a-42b0-86e0-3d081367c10a";return @{@"schema":@"envara.macos-pf-owned-root-hook-lease/v2",@"runId":CANARY_RUN,@"leaseId":id,@"anchor":CANARY_ANCHOR,@"owner":CANARY_ANCHOR,@"label":[@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,id])substringToIndex:32]],@"ticket":@"18446744073709551615",@"rootBeforeSHA256":ROOT_RULE,@"rootBeforeTextSHA256":ROOT_TEXT};}
static BOOL shape(NSDictionary*r,NSDictionary*l){NSData*b=[NSJSONSerialization dataWithJSONObject:l options:NSJSONWritingWithoutEscapingSlashes error:NULL];uint64_t g,p;NSString*realm,*group,*token;NSDictionary*hook;return contextShape(r,l,b,&g,&p,&realm,&hook,&group,&token);}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 NSDictionary*hook=rootLease();assert(validLease(hook));
 NSDictionary*l=@{@"schema":@"envara.macos-pf-app-bound-lease/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"realmId":@"c5d6a177-46cf-43a8-b739-97ac3aebbe51",@"leaseId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859",@"generation":@"5145eb2d-79e5-4e0a-a98e-5fe389b6fdf9",@"registrationId":@"f20b0d49-deef-4866-ae58-be7da7aeb8dd",@"versionId":@"2d910ccb-f4ad-4210-9ab8-58fbf85d6f8b",@"consoleUID":@501,@"gid":@7100,@"cwd":@"/Users/fixture/Work",@"timezone":@"Asia/Manila",@"locale":@"en-US",@"issuedMonotonicMs":@100000,@"expiresMonotonicMs":@280000,@"bootTimeSeconds":@1791400000,@"controllerPid":@9000,@"controllerBirth":@"1791400001:123456",@"ipv4Address":@"198.18.1.1",@"rootHookLease":hook};
 NSData*lb=[NSJSONSerialization dataWithJSONObject:l options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 NSDictionary*r=@{@"schema":@"envara.macos-pf-owned-registry/v1",@"runId":CANARY_RUN,@"supervisorPid":@9000,@"anchor":CANARY_ANCHOR,@"phase":@"cleanup-required",@"cleanupUncertain":@YES,@"rootHook":@{@"mutationAttempted":@YES,@"verified":@YES,@"removed":@NO,@"receiptRetired":@NO,@"namespaceState":@"unknown",@"namespaceReclaimed":@NO,@"lease":hook},@"ownedPFReference":@{@"attempted":@YES,@"acquired":@YES,@"released":@NO,@"token":@"123456"},@"filterReplacement":NSNull.null,@"filterReceipt":NSNull.null,@"application":@{@"environmentId":FIXED_ENV,@"routeId":@"pf_0123456789abcdef0123456789abcdef",@"registrationId":l[@"registrationId"],@"versionId":l[@"versionId"],@"ticketId":@"c8c0293a-9b90-4d75-a4bc-d4134b150fc6",@"leaseSHA256":hashText([[NSString alloc]initWithData:lb encoding:NSUTF8StringEncoding]),@"transport":NSNull.null,@"child":NSNull.null,@"resumed":@NO},@"incompleteGroupAllocations":@[],@"realms":@[@{@"environmentId":FIXED_ENV,@"realmId":l[@"realmId"],@"gid":@7100,@"groupPath":@"/Groups/_envara_pf_7100",@"mode":@"blocked",@"tunnel":NSNull.null,@"fixtures":@[]}],@"guardians":@[]};
 assert(shape(r,l));
 for(NSString*k in @[@"runId",@"environmentId",@"realmId",@"gid",@"controllerPid",@"generation",@"leaseId",@"registrationId",@"versionId",@"controllerBirth",@"ipv4Address",@"consoleUID",@"issuedMonotonicMs",@"expiresMonotonicMs",@"bootTimeSeconds",@"locale",@"timezone",@"cwd"]){NSMutableDictionary*x=clone(l);x[k]=NSNull.null;assert(!shape(r,x));}
 for(NSString*k in @[@"filterReplacement",@"filterReceipt",@"guardians",@"incompleteGroupAllocations"]){NSMutableDictionary*x=clone(r);x[k]=@[@{@"foreign":@YES}];assert(!shape(x,l));}
 NSMutableDictionary*x=clone(r);x[@"extra"]=@YES;assert(!shape(x,l));
 x=clone(r);x[@"application"][@"resumed"]=@1;assert(!shape(x,l));
 x=clone(r);x[@"application"][@"transport"]=@{@"pid":@12};assert(!shape(x,l));
 x=clone(r);x[@"application"][@"environmentId"]=@"b9cc9113-1391-4e6e-ae4a-4375eab0e18e";assert(!shape(x,l));
 x=clone(r);x[@"rootHook"][@"removed"]=@YES;assert(!shape(x,l));
 x=clone(r);x[@"ownedPFReference"][@"released"]=@YES;assert(!shape(x,l));
 x=clone(r);x[@"realms"]=[@[]mutableCopy];assert(!shape(x,l));
 x=clone(r);x[@"realms"]=[@[NSNull.null]mutableCopy];assert(!shape(x,l));
 x=clone(r);x[@"realms"][0][@"groupPath"]=@"/Groups/admin";assert(!shape(x,l));
 x=clone(r);x[@"cleanupUncertain"]=@1;assert(!shape(x,l));
 NSMutableDictionary*h=clone(hook);h[@"ticket"]=@"0";assert(!validLease(h));h[@"ticket"]=@"18446744073709551616";assert(!validLease(h));
 h=clone(hook);h[@"label"]=@"foreign";assert(!validLease(h));
 assert(nativeOperation(1)==NULL);assert(!strcmp(nativeOperation(0),"hook-status"));assert(!strcmp(nativeOperation(2),"delete-owned-root-hook"));
 assert(!strictJSON([@"{\\"a\\":1,\\"a\\":2}"dataUsingEncoding:NSUTF8StringEncoding],4096));
 assert(!strictJSON([@"{\\"a\\":\\"\\\\/v2\\"}"dataUsingEncoding:NSUTF8StringEncoding],4096));
 assert(isBool(outcome(false)[@"readOnly"]));assert(![outcome(false)[@"cleanupConfirmed"]boolValue]);assert([outcome(false)[@"cleanupUncertain"]boolValue]);
 assert([outcome(false)[@"preflightGate"]isEqual:@"not-started"]);
 uint64_t diagnosticPid=1;assert(integer(outcome(false)[@"componentPid"],&diagnosticPid)&&diagnosticPid==0);
 assert(requestRecovery(false)==1);assert(requestRecovery(true)==1);
 assert(recover(false)==1); /* Actual nonroot entry stops before any authorization API. */
 puts("inert fixed shape/uncertainty checks passed");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const result = await exec(binary, [], { timeout: 15000 });
    assert.match(result.stdout, /inert fixed shape\/uncertainty checks passed/);
    assert.equal((result.stdout.match(/NONINTERACTIVE_PRIVILEGED_EXECUTION_UNAVAILABLE/g) ?? []).length, 2);
    const reports = result.stdout.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
    assert.deepEqual(reports.map(report => report.preflightGate), ['not-started', 'not-started', 'rights']);
    for (const report of reports) {
      assert.equal(report.ok, false);
      assert.equal(report.cleanupConfirmed, false);
      assert.equal(report.cleanupUncertain, true);
      assert.equal(report.ready, false);
      assert.equal(report.protected, false);
      assert.equal(report.componentPid, 0);
    }
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('fixed recovery has no reachable noninteractive authorization or broad network mutation', async () => {
  const source = await readFile(path.join(native, 'recovery-app-46ae-run904.m'), 'utf8');
  const request = source.slice(source.indexOf('static int requestRecovery'), source.indexOf('#ifndef RECOVERY_INERT'));
  assert.doesNotMatch(request, /AuthorizationCreate|AuthorizationCopyRights|AuthorizationExecuteWithPrivileges|sudo/);
  assert.match(source, /O_RDONLY\|O_CLOEXEC/);
  assert.match(source, /actions\[\]=\{0,2,4,6,8,11\}/);
  assert.match(source, /envara_app_scope_gid_absent/);
  assert.match(source, /proc_listallpids/);
  assert.match(source, /RENAME_EXCL/);
  assert.doesNotMatch(source, /"-F"|"-d"|"-e"|"-f"|insert-owned-root-hook/);
  assert.equal((source.match(/!componentsAbsent\(lease\)/g) ?? []).length, 5);
  assert.equal((source.match(/envara_app_scope_gid_absent\(\(gid_t\)gid\)!=1/g) ?? []).length, 5);
  const recover = source.slice(source.indexOf('static int recover(bool mutate)'), source.indexOf('/* AEXWP'));
  const gates = [...recover.matchAll(/out\[@"preflightGate"\]=@"([a-z-]+)";/g)].map(match => match[1]);
  assert.deepEqual(gates, ['rights', 'root-credentials', 'root-parent', 'installed-inventory', 'private-runtime', 'registry-lock', 'registry-shape',
    'run-directory', 'lease-shape', 'state-directory', 'empty-state-shape', 'filter-journal-absent', 'controller-gone', 'gid-scope-absent',
    'components-absent', 'pf-empty', 'dedicated-group', 'root-hook-readback', 'preflight-complete']);
  // Removing only diagnostics must reproduce the exact pre-diagnostic recovery
  // body: conditions, ordering and system calls remain byte-for-byte unchanged.
  let original = recover.replace('if(!componentsAbsent(lease)){out[@"preflightGate"]=componentFailureReason;out[@"componentPid"]=@(componentFailurePid);break;}', 'if(!componentsAbsent(lease))break;')
    .replace(/out\[@"preflightGate"\]=@"[a-z-]+";/g, '');
  const scopeStart = original.indexOf(' state=openat(run,realm.UTF8String,');
  const scopeEnd = original.indexOf('\n struct group*g=getgrgid(', scopeStart);
  const scope = original.slice(scopeStart, scopeEnd);
  assert.equal((scope.match(/\)break;/g) ?? []).length, 7);
  // Consecutive fail-fast checks are exactly the former || chain: each next
  // predicate runs only when every preceding predicate succeeded.
  original = original.slice(0, scopeStart) + scope.replace(/\)break;\n if\(/g, '||') + original.slice(scopeEnd);
  assert.equal(createHash('sha256').update(original).digest('hex'), '73fb4f84f50ed6c054e477ccbf4aed9dddc4af646890ec86329e3b0ebda0d6a6');
});

test('original Notion exclusion requires complete stable sealed-user credentials while owned families still refuse', async () => {
  assert.notEqual(process.getuid(), 0, 'Credential fixtures must never run as root.');
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-recovery46-credentials-'));
  try {
    const harness = path.join(temp, 'credentials.m'), binary = path.join(temp, 'credentials');
    await writeFile(harness, `
#define RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-46ae-run904.m')}"
#include <assert.h>
enum {SHORT_BSD=1,DEPARTED_BSD,SHORT_GROUPS,FAILED_GROUPS,BAD_GROUP_COUNT,DUPLICATE_GROUPS,ROOT_GROUP_UID,WRONG_GROUP_BIRTH,WRONG_GROUP_GID,
 OWNED_LAST_GROUP,GROUP_VECTOR_CHANGED,PATH_CHANGED,BIRTH_CHANGED,SAVED_UID_CHANGED,SAVED_GID_CHANGED,LIST_CHANGED,CAPACITY_UNKNOWN,CAPACITY_CHANGED,PATH_UNKNOWN,
 LIST_FIRST_FAILED,LIST_SECOND_FAILED,SHORT_BSD_AFTER,STATUS_CHANGED};
typedef struct {int fault;const char*path;unsigned lists,bsd[2],paths[2],groups,capacity;} Fixture;
static struct proc_bsdinfo identity(pid_t pid){return (struct proc_bsdinfo){.pbi_pid=(uint32_t)pid,.pbi_status=SRUN,.pbi_start_tvsec=1791400001,.pbi_start_tvusec=123456,
 .pbi_uid=501,.pbi_ruid=501,.pbi_svuid=501,.pbi_gid=20,.pbi_rgid=20,.pbi_svgid=20};}
static struct kinfo_proc groupRecord(const struct proc_bsdinfo*b,unsigned count){struct kinfo_proc p={0};
 p.kp_proc.p_pid=(pid_t)b->pbi_pid;p.kp_proc.p_stat=(char)b->pbi_status;p.kp_proc.p_starttime=(struct timeval){(time_t)b->pbi_start_tvsec,(suseconds_t)b->pbi_start_tvusec};
 p.kp_eproc.e_ucred.cr_uid=b->pbi_uid;p.kp_eproc.e_pcred.p_ruid=b->pbi_ruid;p.kp_eproc.e_pcred.p_svuid=b->pbi_svuid;
 p.kp_eproc.e_pcred.p_rgid=b->pbi_rgid;p.kp_eproc.e_pcred.p_svgid=b->pbi_svgid;p.kp_eproc.e_ucred.cr_ngroups=(short)count;
 for(unsigned i=0;i<count&&i<NGROUPS;i++)p.kp_eproc.e_ucred.cr_groups[i]=i?(gid_t)(30+i):b->pbi_gid;return p;}
static int fakeList(void*context,pid_t*out){Fixture*f=context;f->lists++;if(f->fault==LIST_FIRST_FAILED||(f->fault==LIST_SECOND_FAILED&&f->lists==2))return -1;out[0]=10;out[1]=(f->fault==LIST_CHANGED&&f->lists==2)?12:11;return 2;}
static int fakeBSD(void*context,pid_t pid,struct proc_bsdinfo*out){Fixture*f=context;unsigned i=pid==10?0:1;unsigned call=++f->bsd[i];*out=identity(pid);
 if(pid==10){if(f->fault==SHORT_BSD)return sizeof(*out)-1;if(f->fault==DEPARTED_BSD){errno=ESRCH;return 0;}
 if(f->fault==BIRTH_CHANGED&&call>=3)out->pbi_start_tvusec++;
 if(f->fault==SHORT_BSD_AFTER&&call==2)return sizeof(*out)-1;
 if(f->fault==STATUS_CHANGED&&call==2)out->pbi_status=SSTOP;
 if(f->fault==SAVED_UID_CHANGED&&call==2)out->pbi_svuid=0;
 if(f->fault==SAVED_GID_CHANGED&&call==2)out->pbi_svgid=7100;}
 return sizeof(*out);}
static int fakePath(void*context,pid_t pid,char*out,uint32_t size){Fixture*f=context;unsigned i=pid==10?0:1;unsigned call=++f->paths[i];
 if(pid==10&&f->fault==PATH_UNKNOWN)return 0;
 const char*p=pid==10?f->path:"/usr/bin/fixture-unrelated";
 if(pid==10&&f->fault==PATH_CHANGED&&call==2)p="/Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper";
 assert(strlen(p)+1<size);strcpy(out,p);return (int)strlen(p)+1;}
static int fakeSupplementary(void*context,pid_t pid,struct kinfo_proc*out,size_t*bytes){Fixture*f=context;f->groups++;struct proc_bsdinfo b=identity(pid);*out=groupRecord(&b,NGROUPS);
 if(f->fault==SHORT_GROUPS)(*bytes)--;
 if(f->fault==FAILED_GROUPS){errno=EPERM;return -1;}
 if(f->fault==BAD_GROUP_COUNT)out->kp_eproc.e_ucred.cr_ngroups=NGROUPS+1;
 if(f->fault==DUPLICATE_GROUPS)out->kp_eproc.e_ucred.cr_groups[NGROUPS-1]=20;
 if(f->fault==ROOT_GROUP_UID)out->kp_eproc.e_pcred.p_svuid=0;
 if(f->fault==WRONG_GROUP_BIRTH)out->kp_proc.p_starttime.tv_usec++;
 if(f->fault==WRONG_GROUP_GID)out->kp_eproc.e_pcred.p_svgid=7100;
 if(f->fault==OWNED_LAST_GROUP)out->kp_eproc.e_ucred.cr_groups[NGROUPS-1]=7100;
 if(f->fault==GROUP_VECTOR_CHANGED&&f->groups==2)out->kp_eproc.e_ucred.cr_groups[NGROUPS-1]=7000;
 return 0;}
static int fakeCapacity(void*context,unsigned*out){Fixture*f=context;f->capacity++;*out=NGROUPS;
 if(f->fault==CAPACITY_UNKNOWN)return -1;if(f->fault==CAPACITY_CHANGED&&f->capacity==2)(*out)--;return 0;}
static bool scan(Fixture*f,NSDictionary*lease){const ComponentReaders r={f,fakeList,fakeBSD,fakePath,fakeSupplementary,fakeCapacity};rootDeadline=seconds()+60;return componentsAbsentWithReaders(lease,&r);}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);assert(NGROUPS>=2);unsigned checks=0;
 NSDictionary*lease=@{@"consoleUID":@501,@"gid":@7100};const char*original="/Applications/Notion.app/Contents/MacOS/Notion";
 Fixture good={.path=original};assert(scan(&good,lease));assert(good.groups==2&&good.capacity==2);assert(componentFailureReason==nil&&componentFailurePid==0);checks++;
 for(int fault=SHORT_BSD;fault<=STATUS_CHANGED;fault++){Fixture f={.fault=fault,.path=original};assert(!scan(&f,lease));
  NSString*expected=@"component-notion-groups";
  if(fault==SHORT_BSD||fault==DEPARTED_BSD)expected=@"component-bsd-before";
  if(fault==GROUP_VECTOR_CHANGED||fault==PATH_CHANGED)expected=@"component-baseline-change";
  if(fault==SAVED_UID_CHANGED||fault==SAVED_GID_CHANGED||fault==STATUS_CHANGED)expected=@"component-identity-change";
  if(fault==LIST_CHANGED)expected=@"component-inventory-change";
  if(fault==CAPACITY_UNKNOWN||fault==CAPACITY_CHANGED)expected=@"component-capacity";
  if(fault==PATH_UNKNOWN)expected=@"component-path-read";
  if(fault==LIST_FIRST_FAILED)expected=@"component-list-first";
  if(fault==LIST_SECOND_FAILED)expected=@"component-list-second";
  if(fault==SHORT_BSD_AFTER)expected=@"component-bsd-after";
  if(![componentFailureReason isEqual:expected])fprintf(stderr,"inert fault %d: expected %s got %s\\n",fault,expected.UTF8String,componentFailureReason.UTF8String);
  assert([componentFailureReason isEqual:expected]);
  assert(componentFailurePid==((fault==LIST_CHANGED||fault==CAPACITY_UNKNOWN||fault==CAPACITY_CHANGED||fault==LIST_FIRST_FAILED||fault==LIST_SECOND_FAILED)?0:10));checks++;}
 for(const char**p=(const char*[]){NATIVE,INSTALL "/node",INSTALL "/mihomo","/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/version/Snapshot.app/Contents/MacOS/Notion",NULL};*p;p++){
  Fixture f={.path=*p};assert(!scan(&f,lease));assert(f.groups==0);assert([componentFailureReason isEqual:@"component-owned-runtime-live"]&&componentFailurePid==10);checks++;}
 Fixture helper={.path="/Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper"};assert(scan(&helper,lease));checks++;
 for(NSDictionary*x in @[@{@"consoleUID":@0,@"gid":@7100},@{@"consoleUID":@502,@"gid":@7100},@{@"consoleUID":@YES,@"gid":@7100},@{@"consoleUID":@501,@"gid":@YES},@{@"consoleUID":@501,@"gid":@20},@{@"gid":@7100}]){Fixture f={.path=original};assert(!scan(&f,x));assert([componentFailureReason isEqual:x[@"consoleUID"]&&[x[@"consoleUID"]isEqual:@502]?@"component-notion-groups":@"component-lease"]);checks++;}
 Fixture deadline={.path=original};const ComponentReaders expired={&deadline,fakeList,fakeBSD,fakePath,fakeSupplementary,fakeCapacity};rootDeadline=seconds();assert(!componentsAbsentWithReaders(lease,&expired));assert([componentFailureReason isEqual:@"component-deadline"]);checks++;
 ComponentCredentials c={0};struct proc_bsdinfo b=identity(10);struct kinfo_proc p=groupRecord(&b,NGROUPS);assert(componentDecodeGroups(&p,0,sizeof(p),&b,&c));assert(originalNotionUnrelated(&c,501,7100));checks++;
 for(unsigned which=0;which<3;which++){ComponentCredentials v=c;if(which==0)v.bsd.pbi_uid=0;if(which==1)v.bsd.pbi_ruid=0;if(which==2)v.bsd.pbi_svuid=0;assert(!originalNotionUnrelated(&v,501,7100));checks++;}
 for(unsigned which=0;which<3;which++){ComponentCredentials v=c;if(which==0)v.bsd.pbi_gid=7100;if(which==1)v.bsd.pbi_rgid=7100;if(which==2)v.bsd.pbi_svgid=7100;assert(!originalNotionUnrelated(&v,501,7100));checks++;}
 c.groups[NGROUPS-1]=7100;assert(!originalNotionUnrelated(&c,501,7100));checks++;
 for(int n=0;n<3;n++){struct kinfo_proc bad=p;bad.kp_eproc.e_ucred.cr_ngroups=n==0?0:n==1?-1:NGROUPS+1;assert(!componentDecodeGroups(&bad,0,sizeof(bad),&b,&c));checks++;}
 assert(!componentDecodeGroups(&p,0,sizeof(p)-1,&b,&c));assert(!componentDecodeGroups(&p,-1,sizeof(p),&b,&c));checks+=2;
 /* Actual nonprivileged self only: exercise the production SDK readers and
  * exact returned struct sizes without enumerating or touching user apps. */
 unsigned capacity=0;assert(!componentNativeCapacity(NULL,&capacity)&&capacity==NGROUPS);
 struct proc_bsdinfo first={0},last={0};int firstBytes=componentNativeBSD(NULL,getpid(),&first);assert(componentBSDValid(&first,getpid(),firstBytes));
 struct kinfo_proc actual={0};size_t actualBytes=sizeof(actual);int status=componentNativeSupplementary(NULL,getpid(),&actual,&actualBytes);
 assert(status==0&&actualBytes==sizeof(actual));ComponentCredentials self={0};assert(componentDecodeGroups(&actual,status,actualBytes,&first,&self));
 int lastBytes=componentNativeBSD(NULL,getpid(),&last);assert(componentBSDValid(&last,getpid(),lastBytes)&&componentSameBSD(&first,&last));
 assert(self.bsd.pbi_uid==getuid()&&self.bsd.pbi_ruid==getuid()&&self.bsd.pbi_svuid==getuid()&&self.groupCount>=1&&self.groupCount<=NGROUPS);
 gid_t unrelatedRealm=7100;while(unrelatedRealm<=7999&&!originalNotionUnrelated(&self,getuid(),unrelatedRealm))unrelatedRealm++;
 assert(unrelatedRealm<=7999);checks++;
 assert(!componentsAbsent(lease)); /* Production entry never accepts nonroot. */ checks++;
 printf("inert complete credential checks passed: %u; native self SDK bytes verified\\n",checks);return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const result = await exec(binary, [], { timeout: 15000 });
    assert.match(result.stdout, /^inert complete credential checks passed: (?:[4-9]\d|[1-9]\d{2,}); native self SDK bytes verified\n$/);
    assert.equal(result.stderr, '');
  } finally { await rm(temp, { recursive: true, force: true }); }
});
