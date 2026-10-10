import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const RUN = '877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21', ENV = '72826f65-99c0-446c-a9c3-b825b36ad1a5';
const MF = '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061';
const sha = value => createHash('sha256').update(value).digest('hex');

test('actual observational formatters emit genuine booleans and preserve uncertain cleanup facts', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-observation-bools-'));
  try {
    const harness = path.join(temp, 'observation-bools.m'), binary = path.join(temp, 'observation-bools');
    await writeFile(harness, `
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);NSMutableDictionary*out=inspectionOutcome();
 formatOwnedNamespaceObservation(out,false,@"\\n ");formatOwnedNamespaceObservation(out,true,@"");formatNativeHookObservation(out,nil);
 for(NSString*k in @[@"ownedTablesEmptyObserved",@"ownedChildrenEmptyObserved",@"nativeHookStatusAvailable"]){assert(isBool(out[k]));}
 assert([out[@"ownedTablesEmptyObserved"]boolValue]&&[out[@"ownedChildrenEmptyObserved"]boolValue]&&![out[@"nativeHookStatusAvailable"]boolValue]);
 assert(!isBool(@(1==1))&&!isBool(@((NSDictionary*)nil!=nil)));
 formatOwnedNamespaceObservation(out,false,@"owned_nonempty\\n");formatOwnedNamespaceObservation(out,true,@"child\\n");
 NSDictionary*proof=@{@"ok":@NO,@"reason":@"OWNED_RUN_LEDGER_UNVERIFIED",@"pfDisabled":@NO,@"hookInstalled":@NO,@"ownedRootHookVerified":@NO,@"namespaceState":@"unknown",@"runLedgerState":@"unknown",@"receiptRetired":@NO,@"originalRootCompatible":@NO,@"originalRootSHA256":@"",@"originalRootTextSHA256":@""};
 formatNativeHookObservation(out,proof);assert(isBool(out[@"nativeHookStatusAvailable"])&&[out[@"nativeHookStatusAvailable"]boolValue]);
 assert(isBool(out[@"ownedTablesEmptyObserved"])&&![out[@"ownedTablesEmptyObserved"]boolValue]&&isBool(out[@"ownedChildrenEmptyObserved"])&&![out[@"ownedChildrenEmptyObserved"]boolValue]);
 assert([out[@"nativeRootStatus"]isEqual:proof]);
 for(NSString*k in @[@"readOnly",@"cleanupUncertain"])assert(isBool(out[k])&&[out[k]boolValue]);
 for(NSString*k in @[@"cleanupConfirmed",@"cleanupPermitted",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged"])assert(isBool(out[k])&&![out[k]boolValue]);
 NSData*bytes=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];NSDictionary*decoded=strictJSON(bytes,OUTPUT_LIMIT);assert(decoded);
 for(NSString*k in @[@"ownedTablesEmptyObserved",@"ownedChildrenEmptyObserved",@"nativeHookStatusAvailable"])assert(isBool(decoded[k]));
 puts("actual observational formatter Boolean contract verified");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    assert.match((await exec(binary, [], { timeout: 10000 })).stdout, /actual observational formatter Boolean contract verified/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('actual journal comparison selects FILTER action zero and refuses a coincidental NAT match', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-filter-match-'));
  try {
    const harness = path.join(temp, 'filter-match.m'), binary = path.join(temp, 'filter-match');
    await writeFile(harness, `
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
#include <assert.h>
static NSDictionary*row(NSNumber*a,NSNumber*r,NSNumber*n){return @{@"action":a,@"revision":r,@"activeRuleCount":n};}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);NSDictionary*j=@{@"pendingIntent":@NO,@"lastReceipt":@{@"revision":@42,@"ruleCount":@4}};
 NSMutableArray*rows=[@ [row(@0,@42,@4),row(@2,@10,@0),row(@4,@777,@0),row(@6,@12,@0),row(@8,@13,@0),row(@11,@14,@0)]mutableCopy];
 assert(journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[0]=row(@0,@41,@4);rows[2]=row(@4,@42,@4);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[0]=row(@0,@42,@5);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[0]=row(@0,@42,@4);[rows exchangeObjectAtIndex:0 withObjectAtIndex:5];assert(journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[5]=row(@0,@YES,@4);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[5]=row(@NO,@42,@4);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[5]=row(@2,@42,@4);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[5]=row(@0,@42,@4);rows[1]=row(@0,@42,@4);assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 rows[1]=row(@2,@10,@0);assert(!journalMatchesActiveFilter(@{@"pendingIntent":@YES,@"lastReceipt":j[@"lastReceipt"]},@{@"classes":rows}));
 assert(!journalMatchesActiveFilter(@{@"pendingIntent":@NO},@{@"classes":rows}));[rows removeLastObject];assert(!journalMatchesActiveFilter(j,@{@"classes":rows}));
 puts("actual FILTER action selection and NAT coincidence negatives passed");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    assert.match((await exec(binary, [], { timeout: 10000 })).stdout, /actual FILTER action selection and NAT coincidence negatives passed/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('real Foundation journal output reaches actual readJournal while sealed JSON and decoded duplicate keys stay strict', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-journal-'));
  try {
    const harness = path.join(temp, 'journal.m'), binary = path.join(temp, 'journal');
    const code = String.raw`
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
/* Inert ownership seam covers only explicitly recorded self-owned fixture
 * inodes. The actual read/openat/nofollow/mode/ACL/byte/inventory logic runs. */
static struct {dev_t dev;ino_t ino;uid_t uid;gid_t gid;} owned[32];static unsigned ownedCount;
static void track(int fd){struct stat s;assert(!fstat(fd,&s)&&s.st_uid==getuid());assert(ownedCount<32);owned[ownedCount].dev=s.st_dev;owned[ownedCount].ino=s.st_ino;owned[ownedCount].uid=s.st_uid;owned[ownedCount++].gid=s.st_gid;}
static void mapOwnership(struct stat*s){for(unsigned i=0;i<ownedCount;i++)if(s->st_dev==owned[i].dev&&s->st_ino==owned[i].ino&&s->st_uid==owned[i].uid&&s->st_gid==owned[i].gid){s->st_uid=0;s->st_gid=0;return;}}
static int journalFstat(int fd,struct stat*s){int rc=fstat(fd,s);if(!rc)mapOwnership(s);return rc;}
static int journalFstatat(int fd,const char*name,struct stat*s,int flags){int rc=fstatat(fd,name,s,flags);if(!rc)mapOwnership(s);return rc;}
#define fstat journalFstat
#define fstatat journalFstatat
#define INSPECTOR_INERT 1
#include "@SOURCE@"
#undef fstat
#undef fstatat
static NSData*foundation(NSDictionary*v){NSData*d=[NSJSONSerialization dataWithJSONObject:v options:0 error:NULL];assert(d);return d;}
static void put(int parent,const char*name,NSData*d){int fd=openat(parent,name,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);assert(fd>=0&&!fchmod(fd,0600));assert(write(fd,d.bytes,d.length)==(ssize_t)d.length);track(fd);assert(!close(fd));}
static bool parse(NSString*s){return strictJournalJSON([s dataUsingEncoding:NSUTF8StringEncoding],4096)!=nil;}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);char path[]="/tmp/envara-05d6-journal-owned-XXXXXX";assert(mkdtemp(path));int run=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);assert(run>=0&&!fchmod(run,0700));track(run);
 assert(!mkdirat(run,"app-filter-events",0700));int journal=openat(run,"app-filter-events",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);assert(journal>=0);track(journal);
 NSDictionary*lease=@{@"leaseId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859",@"generation":@"5145eb2d-79e5-4e0a-a98e-5fe389b6fdf9"};NSNumber*keeper=@9001;
 NSDictionary*intent=@{@"schema":@"envara.macos-pf-app-filter-event/v1",@"runId":CANARY_RUN,@"leaseId":lease[@"leaseId"],@"generation":lease[@"generation"],@"sequence":@0,@"previous":@0,@"next":@1,@"writerPid":keeper};
 NSDictionary*receipt=@{@"schema":@"envara.macos-pf-app-filter-receipt/v1",@"runId":CANARY_RUN,@"leaseId":lease[@"leaseId"],@"generation":lease[@"generation"],@"sequence":@0,@"mode":@1,@"writerPid":keeper,@"revision":@42,@"ruleCount":@4};
 NSData*ib=foundation(intent),*rb=foundation(receipt);NSString*text=[[NSString alloc]initWithData:ib encoding:NSUTF8StringEncoding];assert([text containsString:@"\\/v1"]);assert(!strictJSON(ib,4096)&&!strictJSON(rb,4096));assert(strictJournalJSON(ib,4096)&&strictJournalJSON(rb,4096));
 put(journal,"000.intent",ib);put(journal,"000.receipt",rb);assert(directorySnapshot(journal));assert([privateRead(journal,"000.intent",4096,NULL)isEqual:ib]);assert([privateRead(journal,"000.receipt",4096,NULL)isEqual:rb]);NSDictionary*out=readJournal(run,lease,keeper);assert(out&&[out[@"eventCount"]isEqual:@2]&&![out[@"pendingIntent"]boolValue]&&![out[@"nativeRulesVerified"]boolValue]);assert([out[@"lastReceipt"][@"revision"]isEqual:@42]);
 assert(parse(@"{\"a/b\":1}"));assert(parse(@"{\"a\\/b\":1}"));assert(!parse(@"{\"a/b\":1,\"a\\/b\":2}"));assert(!parse(@"{\"a\\/b\":1,\"a/b\":2}"));
 for(NSString*s in @[@"{\"a\":\"\\u002f\"}",@"{\"a\":\"\\\\\"}",@"{\"a\":\"\\n\"}",@"{\"a\":\"\\\"\"}",@"{\"a\":\"\\x\"}",@"{\"a\":\"\\",@"{\"a\":1,\"a\":2}"])assert(!parse(s));
 NSMutableDictionary*bad=[receipt mutableCopy];bad[@"writerPid"]=@9002;put(journal,"000.receipt",foundation(bad));assert(!readJournal(run,lease,keeper));
 bad=[receipt mutableCopy];bad[@"mode"]=@3;put(journal,"000.receipt",foundation(bad));assert(!readJournal(run,lease,keeper));
 bad=[receipt mutableCopy];bad[@"password"]=@"private";put(journal,"000.receipt",foundation(bad));assert(!readJournal(run,lease,keeper));
 bad=[receipt mutableCopy];bad[@"runId"]=@"95c92c49-063e-4595-b28f-232f558d6f6e";put(journal,"000.receipt",foundation(bad));assert(!readJournal(run,lease,keeper));
 put(journal,"000.receipt",rb);put(journal,"unknown",[@"x" dataUsingEncoding:NSUTF8StringEncoding]);assert(!readJournal(run,lease,keeper));assert(!unlinkat(journal,"unknown",0));
 assert(!unlinkat(journal,"000.receipt",0));out=readJournal(run,lease,keeper);assert(out&&[out[@"pendingIntent"]boolValue]&&[out[@"eventCount"]isEqual:@1]);
 assert(!symlinkat("000.intent",journal,"000.receipt"));assert(!readJournal(run,lease,keeper));assert(!unlinkat(journal,"000.receipt",0));assert(!unlinkat(journal,"000.intent",0));close(journal);assert(!unlinkat(run,"app-filter-events",AT_REMOVEDIR));close(run);assert(!rmdir(path));
 puts("actual Foundation escaped journal/readJournal and strict negative checks passed");return 0;
}}
`;
    await writeFile(harness, code.replace('@SOURCE@', path.join(native, 'inspector-app-05d6-run877.m')), { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    assert.match((await exec(binary, [], { timeout: 10000 })).stdout, /actual Foundation escaped journal\/readJournal and strict negative checks passed/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('fixed 05d6 inventory selects all 19 exact leaves and no recovery entry', async () => {
  const bytes = await readFile(path.join(native, 'inspector-app-05d6-manifest.json'));
  assert.equal(sha(bytes), MF);
  const manifest = JSON.parse(bytes), inventory = await readFile(path.join(native, 'inspector-app-05d6-inventory.h'), 'utf8');
  const executables = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
  assert.equal(Object.keys(manifest.files).length, 18);
  for (const [name, hash] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    assert.ok(inventory.includes(`{"${name}","${hash}",${executables.has(name) ? '0755' : '0644'}}`));
  }
  assert.ok(inventory.includes(RUN));
  const source = await readFile(path.join(native, 'inspector-app-05d6-run877.m'), 'utf8');
  assert.match(source, /return operation == 0 \? "hook-status" : NULL/);
  assert.doesNotMatch(source, /AuthorizationExecuteWithPrivileges|AuthorizationCopyRights|"-X"|"-E"|"-f"|"delete-owned-root-hook"|"insert-owned-root-hook"/);
  assert.doesNotMatch(source, /\brecover\s*\(|\brenameatx_np\s*\(|\bmkdirat\s*\(|\bunlinkat\s*\(/);
});

test('inert actual inspector parser binds live transport while preserving uncertainty and readonly-only dispatch', async () => {
  assert.equal(process.platform, 'darwin');
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-inert-'));
  try {
    const leaseId = '62d7b9b9-019a-42b0-86e0-3d081367c10a';
    const hook = { schema: 'envara.macos-pf-owned-root-hook-lease/v2', runId: RUN, leaseId,
      anchor: `io.envara.pf.run.${RUN}`, owner: `io.envara.pf.run.${RUN}`,
      label: `envara.hook.v2.${sha(`${RUN}|${leaseId}`).slice(0, 32)}`, ticket: '18446744073709551615',
      rootBeforeSHA256: '7f79342e7409a1d3569220b8e143c1f261574ae1ae7de6a07b915a2364316bb5',
      rootBeforeTextSHA256: '5e803c2e459d5417da5d61aba888d1da25ad56cb0bff4f22e69d36078eb7f575' };
    const lease = { schema: 'envara.macos-pf-app-bound-lease/v1', runId: RUN, environmentId: ENV,
      realmId: 'c5d6a177-46cf-43a8-b739-97ac3aebbe51', leaseId: '73e9d9b3-6b9c-435b-8f64-8305e5a60859',
      generation: '5145eb2d-79e5-4e0a-a98e-5fe389b6fdf9', registrationId: 'f20b0d49-deef-4866-ae58-be7da7aeb8dd',
      versionId: '2d910ccb-f4ad-4210-9ab8-58fbf85d6f8b', consoleUID: 501, gid: 7100, cwd: '/Users/fixture/Work',
      timezone: 'Asia/Manila', locale: 'en-US', issuedMonotonicMs: 100000, expiresMonotonicMs: 280000,
      bootTimeSeconds: 1791400000, controllerPid: 9000, controllerBirth: '1791400001:123456', ipv4Address: '198.18.1.1', rootHookLease: hook };
    const transport = { schema: 'envara.macos-pf-app-transport/v1', event: 'transport-started', runId: RUN,
      environmentId: ENV, interfaceName: 'utun100', corePID: 9002, coreBirth: '1791400002:123456',
      frontPID: 9003, frontBirth: '1791400003:123456', frontPort: 40000, keeperPID: 9001,
      keeperBirth: '1791400001:654321', ownsOriginalUTunFD: true, ownsOriginalListenerFD: true,
      ready: false, protected: false, productionReady: false, profile: 'seatbelt-front-only', genericApplicationRouting: false, udpSupported: false };
    const record = { schema: 'envara.macos-pf-owned-registry/v1', runId: RUN, supervisorPid: 9000,
      anchor: hook.anchor, phase: 'cleanup-required', cleanupUncertain: true,
      rootHook: { mutationAttempted: true, verified: true, removed: false, receiptRetired: false, namespaceState: 'unknown', namespaceReclaimed: false, lease: hook },
      ownedPFReference: { attempted: true, acquired: true, released: false, token: '123456' }, filterReplacement: null, filterReceipt: null,
      application: { environmentId: ENV, routeId: 'pf_0123456789abcdef0123456789abcdef', registrationId: lease.registrationId,
        versionId: lease.versionId, ticketId: 'c8c0293a-9b90-4d75-a4bc-d4134b150fc6', leaseSHA256: sha(JSON.stringify(lease)), transport, child: null, resumed: false },
      incompleteGroupAllocations: [], realms: [{ environmentId: ENV, realmId: lease.realmId, gid: 7100,
        groupPath: '/Groups/_envara_pf_7100', mode: 'blocked', tunnel: null, fixtures: [] }], guardians: [] };
    const literal = value => `@${JSON.stringify(JSON.stringify(value))}`;
    const harness = path.join(temp, 'inert.m'), binary = path.join(temp, 'inert');
    await writeFile(harness, `
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
#include <assert.h>
static NSMutableDictionary *clone(NSDictionary*v){return [[NSJSONSerialization JSONObjectWithData:[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL] options:NSJSONReadingMutableContainers error:NULL]mutableCopy];}
static bool shape(NSDictionary*r,NSDictionary*l,NSData*b){NSDictionary*t=nil;uint64_t gid=0;return liveShape(r,l,b,&t,&gid);}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 NSData*bytes=[${literal(lease)} dataUsingEncoding:NSUTF8StringEncoding];NSDictionary*l=strictJSON(bytes,16384);
 NSDictionary*r=strictJSON([${literal(record)} dataUsingEncoding:NSUTF8StringEncoding],65536);assert(l&&r&&shape(r,l,bytes));
 for(NSString*k in @[@"corePID",@"frontPID",@"keeperPID",@"coreBirth",@"frontBirth",@"keeperBirth",@"interfaceName",@"frontPort",@"ownsOriginalUTunFD",@"ownsOriginalListenerFD",@"profile"]){NSMutableDictionary*x=clone(r);x[@"application"][@"transport"][k]=NSNull.null;assert(!shape(x,l,bytes));}
 for(NSString*k in @[@"ready",@"protected",@"productionReady",@"genericApplicationRouting",@"udpSupported"]){NSMutableDictionary*x=clone(r);x[@"application"][@"transport"][k]=@YES;assert(!shape(x,l,bytes));}
 NSMutableDictionary*x=clone(r);x[@"application"][@"transport"][@"ownsOriginalUTunFD"]=@1;assert(!shape(x,l,bytes));
 x=clone(r);x[@"application"][@"transport"][@"environmentId"]=@"b9cc9113-1391-4e6e-ae4a-4375eab0e18e";assert(!shape(x,l,bytes));
 x=clone(r);x[@"application"][@"transport"][@"password"]=@"secret";assert(!shape(x,l,bytes));
 x=clone(r);x[@"application"][@"resumed"]=@YES;assert(shape(x,l,bytes));
 x=clone(r);x[@"application"][@"child"]=@{};assert(!shape(x,l,bytes));
 x=clone(r);x[@"rootHook"][@"removed"]=@YES;assert(!shape(x,l,bytes));
 x=clone(r);x[@"ownedPFReference"][@"released"]=@YES;assert(!shape(x,l,bytes));
 x=clone(r);x[@"application"][@"leaseSHA256"]=@"bad";assert(!shape(x,l,bytes));
 NSMutableDictionary*bad=clone(l);bad[@"gid"]=@YES;assert(!shape(r,bad,bytes));
 bad=clone(l);bad[@"expiresMonotonicMs"]=@280001;assert(!shape(r,bad,bytes));
 assert(!nativeOperation(1)&&!nativeOperation(2)&&!strcmp(nativeOperation(0),"hook-status"));
 NSDictionary*out=inspectionOutcome();assert(isBool(out[@"readOnly"])&&[out[@"readOnly"]boolValue]);
 for(NSString*k in @[@"cleanupConfirmed",@"cleanupPermitted",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged"])assert(isBool(out[k])&&![out[k]boolValue]);
 assert([out[@"cleanupUncertain"]boolValue]);assert(!out[@"rootHookLease"]&&!out[@"token"]&&!out[@"password"]);
 assert(inspectFixedRun()==1);puts("inert readonly transport binding checks passed");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const result = await exec(binary, [], { timeout: 10000 });
    assert.match(result.stdout, /inert readonly transport binding checks passed/);
    const refusal = JSON.parse(result.stdout.split('\n').find(line => line.startsWith('{')));
    assert.equal(refusal.gate, 'root-credentials');
    assert.equal(refusal.cleanupConfirmed, false);
    assert.equal(refusal.cleanupUncertain, true);
    assert.equal(refusal.readOnly, true);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('actual root-entry credential logic normalizes a genuine EUID0 child and never elevates nonroot', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-credentials-'));
  try {
    const harness = path.join(temp, 'credentials.m'), binary = path.join(temp, 'credentials');
    await writeFile(harness, `
#import <Foundation/Foundation.h>
#include <unistd.h>
#include <grp.h>
#include <assert.h>
#include <errno.h>
typedef struct {uid_t ruid,euid;gid_t rgid,egid,group;int count,fault,calls,order;} Credentials;
static Credentials c;
static uid_t own_ruid(void){return c.ruid;}static uid_t own_euid(void){return c.euid;}
static gid_t own_rgid(void){return c.rgid;}static gid_t own_egid(void){return c.egid;}
static int own_setgroups(int count,const gid_t *groups){assert(c.euid==0&&c.order++==0&&count==1&&groups&&groups[0]==0);c.calls++;if(c.fault==1){errno=EPERM;return -1;}c.count=1;c.group=0;return 0;}
static int own_setgid(gid_t gid){assert(c.euid==0&&c.order++==1&&gid==0);c.calls++;if(c.fault==2){errno=EACCES;return -1;}c.rgid=c.egid=0;if(c.fault==7)c.rgid=20;if(c.fault==8)c.egid=20;return 0;}
static int own_setuid(uid_t uid){assert(c.euid==0&&c.order++==2&&uid==0);c.calls++;if(c.fault==3){errno=EINVAL;return -1;}c.ruid=c.euid=0;if(c.fault==5)c.ruid=501;if(c.fault==6)c.euid=501;return 0;}
static int own_getgroups(int size,gid_t *groups){assert(size==2&&c.order++==3);c.calls++;if(c.fault==4){errno=EIO;return -1;}groups[0]=c.fault==10?20:c.group;groups[1]=20;return c.fault==9?2:c.fault==11?0:c.count;}
#define getuid own_ruid
#define geteuid own_euid
#define getgid own_rgid
#define getegid own_egid
#define setgroups own_setgroups
#define setgid own_setgid
#define setuid own_setuid
#define inspectorKernelGroups own_getgroups
#define INSPECTOR_CREDENTIAL_FIXTURE 1
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
static void reset(int fault,uid_t euid){c=(Credentials){.ruid=501,.euid=euid,.rgid=20,.egid=20,.group=20,.count=1,.fault=fault};}
int main(void){@autoreleasepool{
 reset(0,501);assert(!inspectorRootCredentials()&&c.calls==0&&c.order==0&&c.ruid==501&&c.euid==501);
 reset(0,0);assert(inspectorRootCredentials()&&c.calls==4&&c.order==4&&c.ruid==0&&c.euid==0&&c.rgid==0&&c.egid==0&&c.count==1&&c.group==0);
 for(int fault=1;fault<=11;fault++){reset(fault,0);assert(!inspectorRootCredentials());assert(c.calls==(fault<=3?fault:4));NSDictionary*d=credentialDiagnostic();
  NSArray*expected=@[@"setgroups",@"setgid",@"setuid",@"kernel-groups",@"identity-check",@"identity-check",@"identity-check",@"identity-check",@"group-check",@"group-check",@"group-check"];
  assert([d[@"stage"]isEqual:expected[fault-1]]&&d.count==7);int errors[]={EPERM,EACCES,EINVAL,EIO};assert([d[@"errno"]intValue]==(fault<=4?errors[fault-1]:0));
  assert([d[@"groupCount"]intValue]==(fault<=4?-1:fault==9?2:fault==11?0:1));}
 reset(0,501);assert(inspectFixedRun()==1&&c.calls==0);puts("inert genuine-EUID credential normalization checks passed");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const result = await exec(binary, [], { timeout: 10000 });
    assert.match(result.stdout, /inert genuine-EUID credential normalization checks passed/);
    const refusal = JSON.parse(result.stdout.split('\n').find(line => line.startsWith('{')));
    assert.equal(refusal.gate, 'root-credentials');
    assert.equal(refusal.cleanupConfirmed, false);
    assert.equal(refusal.cleanupUncertain, true);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('actual inspector child initialization restores waitable own exits from inherited SIG_IGN and NOCLDWAIT', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-child-boundary-'));
  try {
    const harness = path.join(temp, 'children.m'), binary = path.join(temp, 'children');
    await writeFile(harness, `
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);struct sigaction saved={0},ignored={0},actual={0};assert(!sigaction(SIGCHLD,NULL,&saved));
 ignored.sa_handler=SIG_IGN;ignored.sa_flags=SA_NOCLDWAIT;assert(!sigemptyset(&ignored.sa_mask)&&!sigaction(SIGCHLD,&ignored,NULL));
 assert(inspectorChildWaitBoundary());assert(!sigaction(SIGCHLD,NULL,&actual)&&actual.sa_handler==SIG_DFL&&!(actual.sa_flags&SA_NOCLDWAIT));
 rootDeadline=seconds()+5;char*argv[]={"/usr/bin/true",NULL};int status=-1;NSData*out=fixedProcess("/usr/bin/true",argv,nil,&status,false);
 assert(out&&status==0&&out.length==0);assert(!sigaction(SIGCHLD,&saved,NULL));
 puts("actual inherited-SIGCHLD readonly own-child wait checks passed");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const result = await exec(binary, [], { timeout: 10000 });
    assert.match(result.stdout, /actual inherited-SIGCHLD readonly own-child wait checks passed/);
    assert.equal(result.stderr, '');
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('compiled legacy getter reads actual own kernel credentials and never imports the Darwin directory extension', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-05d6-inspector-kernel-groups-'));
  try {
    const harness = path.join(temp, 'kernel-groups.m'), binary = path.join(temp, 'kernel-groups');
    await writeFile(harness, `
#define INSPECTOR_INERT 1
#include "${path.join(native, 'inspector-app-05d6-run877.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);gid_t groups[NGROUPS]={0};int count=inspectorKernelGroups(NGROUPS,groups);assert(count>=1&&count<=NGROUPS&&groups[0]==getegid());
 struct kinfo_proc actual={0};int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()};size_t bytes=sizeof(actual);
 assert(!sysctl(mib,4,&actual,&bytes,NULL,0)&&bytes==sizeof(actual)&&actual.kp_proc.p_pid==getpid());
 assert(actual.kp_eproc.e_ucred.cr_uid==geteuid()&&actual.kp_eproc.e_pcred.p_ruid==getuid()&&actual.kp_eproc.e_ucred.cr_ngroups==count);
 assert(!memcmp(actual.kp_eproc.e_ucred.cr_groups,groups,(size_t)count*sizeof(gid_t)));puts("actual own kernel credential getter verified");return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const symbols = (await exec('/usr/bin/nm', ['-u', binary], { timeout: 10000 })).stdout;
    assert.match(symbols, /(?:^|\n)_getgroups(?:\n|$)/);
    assert.doesNotMatch(symbols, /_getgroups\$DARWIN_EXTSN/);
    assert.match((await exec(binary, [], { timeout: 10000 })).stdout, /actual own kernel credential getter verified/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});
