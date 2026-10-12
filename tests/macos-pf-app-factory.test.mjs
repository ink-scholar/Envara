import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm, mkdir, copyFile, chmod, readdir, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const native = fileURLToPath(new URL('../native/macos-pf-routing/', import.meta.url));
const fixture = String.raw`
#import <Foundation/Foundation.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
static int pretend_root_owner, descriptor_flags_unknown;
static int fake_stat(int fd,struct stat *out) {int r=fstat(fd,out);if(!r&&pretend_root_owner)out->st_uid=0;return r;}
static int fake_fcntl(int fd,int command,...) {
    if(command==F_GETFD&&descriptor_flags_unknown){errno=EIO;return -1;}
    if(command==F_GETFD||command==F_GETFL)return fcntl(fd,command);
    va_list values;va_start(values,command);int r;
    if(command==F_GETPATH){char *p=va_arg(values,char *);r=fcntl(fd,command,p);}else{int n=va_arg(values,int);r=fcntl(fd,command,n);}va_end(values);return r;
}
static int forbidden_ioctl(int fd,unsigned long command,...) {(void)fd;(void)command;abort();}
static int fake_clock(clockid_t id,struct timespec *out) { assert(id==CLOCK_MONOTONIC);*out=(struct timespec){.tv_sec=10,.tv_nsec=999000000};return 0; }
static int fake_sysctl(const char *name,void *out,size_t *size,void *in,size_t n) {assert(!strcmp(name,"kern.boottime")&&*size==sizeof(struct timeval)&&!in&&!n);*(struct timeval *)out=(struct timeval){.tv_sec=1234567};return 0;}
#define clock_gettime fake_clock
#define sysctlbyname fake_sysctl
#define fstat fake_stat
#define fcntl fake_fcntl
#define ioctl forbidden_ioctl
#include FACTORY_SOURCE
#undef clock_gettime
#undef sysctlbyname
#undef fstat
#undef fcntl
#undef ioctl
static unsigned checks;
#define CHECK(value) do {assert(value);checks++;}while(0)
static unsigned ticket_inspections,ticket_verifications;
static int fixture_ticket_inspect(const char *environment,const char *run,const struct envara_app_registration *app,struct envara_gui_request *request,char hash[65],void *opaque) {
    struct envara_app_native_factory *f=opaque;ticket_inspections++;
    if(strcmp(environment,f->plan.environment_id)||strcmp(run,f->plan.run_id)||memcmp(app,&f->app,sizeof(*app)))return refuse(EACCES);
    *request=f->request;memset(hash,'a',64);hash[64]=0;return 0;
}
static int fixture_ticket_verify(const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run,const char *hash,void *opaque) {
    struct envara_app_native_factory *f=opaque;ticket_verifications++;
    char expected[65];memset(expected,'a',64);expected[64]=0;
    return !memcmp(app,&f->app,sizeof(*app))&&!memcmp(request,&f->request,sizeof(*request))&&!strcmp(run,f->plan.run_id)&&!strcmp(hash,expected)?0:refuse(EACCES);
}
static unsigned directory_entries(int fd) {
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(copy>=0);DIR *entries=fdopendir(copy);CHECK(entries!=NULL);
    unsigned count=0;struct dirent *entry;while((entry=readdir(entries)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))count++;
    CHECK(!closedir(entries));return count;
}
static void ticket_fixture(const char *workspace,const char *bundle) {
    const char *registration="00000000-0000-4000-8000-000000000101",*version="00000000-0000-4000-8000-000000000102";
    const char *environment="00000000-0000-4000-8000-000000000103",*run="00000000-0000-4000-8000-000000000104";
    const char *id="00000000-0000-4000-8000-000000000105";
    char registry_path[PATH_MAX],ticket_path[PATH_MAX];CHECK(snprintf(registry_path,sizeof(registry_path),"%s/registry",workspace)<(int)sizeof(registry_path));
    CHECK(snprintf(ticket_path,sizeof(ticket_path),"%s/tickets",workspace)<(int)sizeof(ticket_path));
    struct envara_app_registry registry={.fd=-1};struct envara_app_ticket_store store={.fd=-1};
    struct envara_app_native_factory f={.owner=getpid()};
    CHECK(!envara_app_registry_open(&registry,registry_path,1,1));
    CHECK(!envara_app_registry_register(&registry,registration,version,bundle,NULL,NULL,&f.app));
    CHECK(!envara_app_ticket_store_open(&store,ticket_path,1,1));CHECK(directory_entries(store.fd)==0);
    strcpy(f.plan.environment_id,environment);strcpy(f.plan.run_id,run);f.request.schema=ENVARA_GUI_SCHEMA;
    f.request.console_uid=getuid();f.request.realm_gid=getgid();strcpy(f.request.environment_id,environment);
    strcpy(f.request.lease_id,"00000000-0000-4000-8000-000000000106");strcpy(f.request.cwd,workspace);
    strcpy(f.request.timezone,"Asia/Manila");strcpy(f.request.browser_locale,"en-PH");
    provider_initialize(&f);const struct envara_app_supervisor_provider *provider=envara_app_native_factory_provider(&f);
    CHECK(provider==&f.provider);CHECK(provider->ticket.inspect==ticket_inspect);CHECK(provider->ticket.verify==ticket_verify);
    CHECK(provider->ticket.adopt==ticket_never_adopt);CHECK(provider->ticket.context==&f);
    /* This inert registration is not the supported Notion target, so it selects
     * the generic cold profile: no fixed adapter and no front execution profile.
     * Both profiles are real owned-process scopes; neither is ready/protected. */
    CHECK(provider->prepare_guard==prepare_guard&&provider->stage==NULL&&provider->context==&f);
    CHECK(provider->execution_profile==ENVARA_APP_EXECUTION_COLD);
    struct envara_gui_lifecycle child;envara_gui_lifecycle_init(&child);struct envara_gui_lifecycle unchanged=child;
    CHECK(provider->ticket.adopt(NULL,&child,provider->ticket.context)==-1&&errno==ENOTSUP);CHECK(!memcmp(&child,&unchanged,sizeof(child)));
    /* Only these two callbacks use inert fixture authority. The custody hook
     * remains the exact production initializer's fail-closed callback. */
    struct envara_app_ticket_authority authority=provider->ticket;authority.inspect=fixture_ticket_inspect;authority.verify=fixture_ticket_verify;
    struct envara_app_ticket_authority missing=authority;missing.adopt=NULL;struct envara_app_ticket ticket;
    CHECK(envara_app_ticket_prepare(&store,&registry,id,registration,version,environment,run,&missing,&ticket)==-1&&errno==ENOTSUP);
    CHECK(ticket_inspections==0&&ticket_verifications==0&&directory_entries(store.fd)==0);
    CHECK(!envara_app_ticket_prepare(&store,&registry,id,registration,version,environment,run,&authority,&ticket));
    CHECK(ticket_inspections>0&&ticket_verifications>0);CHECK(ticket.fixture_only==1&&!ticket.ready&&!ticket.protected_ready);
    CHECK(!strcmp(ticket.ticket_id,id)&&!strcmp(ticket.environment_id,environment)&&!strcmp(ticket.run_id,run));
    CHECK(authority.adopt(&ticket,&child,authority.context)==-1&&errno==ENOTSUP);CHECK(!memcmp(&child,&unchanged,sizeof(child)));
    struct envara_app_ticket issued;CHECK(!envara_app_ticket_inspect(&store,&registry,id,&issued));CHECK(!memcmp(&issued,&ticket,sizeof(ticket)));
    CHECK(!envara_app_ticket_claim(&store,&registry,id,&authority,&issued));
    CHECK(envara_app_ticket_claim(&store,&registry,id,&authority,&issued)==-1);
    envara_app_ticket_store_close(&store);envara_app_registry_close(&registry);
}
static NSDictionary *json(const char *s){return decode(s,strlen(s));}
static NSMutableDictionary *lease(void) {
    const char *run="00112233-4455-4677-8899-aabbccddeeff";
    return [@{@"schema":@ENVARA_APP_BOUND_LEASE_SCHEMA,@"runId":@(run),@"environmentId":@(run),@"realmId":@(run),@"leaseId":@(run),@"generation":@(run),@"registrationId":@(run),@"versionId":@(run),
      @"consoleUID":@501,@"gid":@7111,@"cwd":@"/Users/example/工作 目录",@"timezone":@"Asia/Manila",@"locale":@"en-PH",@"issuedMonotonicMs":@1000,@"expiresMonotonicMs":@(1000+ENVARA_APP_BOUND_MAX_LEASE_MS),@"bootTimeSeconds":@1234567,@"controllerPid":@222,@"controllerBirth":@"1234567:000123",@"ipv4Address":@"198.18.1.1",@"rootHookLease":@{@"runId":@(run)}} mutableCopy];
}
int main(int argc,char **argv) {@autoreleasepool {
    CHECK(getuid()!=0&&geteuid()!=0); // never a root/PF/native fixture
    CHECK(argc==3);
    CHECK(json("{\"a\":1,\"a\":2}")==nil);
    CHECK(json("{\"a\":{\"b\":1,\"b\":2}}")==nil);
    CHECK(json("{\"a\":[{\"b\":1,\"b\":2}]}")==nil);
    CHECK(json("{\"a\":1,\"\\u0061\":2}")==nil);
    CHECK(json("{\"\xe4\xbd\xa0\":1}")==nil);
    CHECK(json("{\"a\":\"\\u4f60\\u597d\"}")!=nil);
    CHECK(json("{\"a\":\"escaped \\\"value\\\"\"}")!=nil);
    CHECK(json("{\"a\":\"work 空间\"}")!=nil);
    CHECK(json("{\"a\":\"\xff\"}")==nil);
    CHECK(json("{\"a\":1}extra")==nil);
    CHECK(json("{\"a\":1,}")==nil);
    CHECK(json("[]")==nil);
    CHECK(json("{\"a\":NaN}")==nil);
    CHECK(decode("{}\0x",5)==nil);
    uint64_t value;
    CHECK(!number(@YES,&value));CHECK(!number(@NO,&value));CHECK(!number(@-1,&value));CHECK(!number(@1.5,&value));
    CHECK(!number(@"123",&value));CHECK(!number([NSNull null],&value));CHECK(number(@0,&value)&&value==0);CHECK(number(@9007199254740991ULL,&value));CHECK(!number(@9007199254740992ULL,&value));
    CHECK(boolean(@YES,1));CHECK(!boolean(@1,1));CHECK(!boolean(@"true",1));
    NSMutableDictionary *valid=lease();CHECK(lease_shape(valid));
    for(NSString *key in [valid allKeys]) {NSMutableDictionary *bad=[valid mutableCopy];[bad removeObjectForKey:key];CHECK(!lease_shape(bad));}
    NSMutableDictionary *bad=[valid mutableCopy];bad[@"trusted"]=@YES;CHECK(!lease_shape(bad));
    for(NSString *key in @[@"runId",@"environmentId",@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId"]) {
      bad=[valid mutableCopy];bad[key]=@"00112233-4455-4677-8899-AABBCCDDEEFF";CHECK(!lease_shape(bad));
      bad=[valid mutableCopy];bad[key]=@"../00112233-4455-4677-8899-aabbccddeeff";CHECK(!lease_shape(bad));
    }
    for(NSString *key in @[@"consoleUID",@"gid",@"issuedMonotonicMs",@"expiresMonotonicMs",@"bootTimeSeconds",@"controllerPid"]) {
      bad=[valid mutableCopy];bad[key]=@YES;CHECK(!lease_shape(bad));bad[key]=@1.1;CHECK(!lease_shape(bad));bad[key]=@"1000";CHECK(!lease_shape(bad));
    }
    for(NSNumber *gid in @[@7099,@8000,@0]){bad=[valid mutableCopy];bad[@"gid"]=gid;CHECK(!lease_shape(bad));}
    bad=[valid mutableCopy];bad[@"expiresMonotonicMs"]=@(1001+ENVARA_APP_BOUND_MAX_LEASE_MS);CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"expiresMonotonicMs"]=@1000;CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"ipv4Address"]=@"192.168.1.1";CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"rootHookLease"]=@{@"runId":@"11112233-4455-4677-8899-aabbccddeeff"};CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"rootHookLease"]=@YES;CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"cwd"]=@"relative";CHECK(!lease_shape(bad));
    bad=[valid mutableCopy];bad[@"cwd"]=[NSString stringWithCharacters:(unichar[]){'/',0,'a'} length:3];CHECK(!lease_shape(bad));
    struct envara_identity idn={0};CHECK(birth_parse(@"1234567:000123",&idn));CHECK(!birth_parse(@"1234567:123",&idn));CHECK(!birth_parse(@"1234567:000123suffix",&idn));
    uint64_t now,boot;CHECK(!clock_values(&now,&boot)&&now==10999&&boot==1234567);
    char enabled[]="Status: Enabled for 0 days 00:00:02 Debug: Urgent\nState Table\n";CHECK(pf_enabled_text(enabled));
    char disabled[]="Status: Disabled\n";CHECK(!pf_enabled_text(disabled));
    char duplicate[]="Status: Enabled\nStatus: Enabled\n";CHECK(!pf_enabled_text(duplicate));
    char unknown[]="Status: EnabledUnknown\n";CHECK(!pf_enabled_text(unknown));
    char absent[]="State Table\n";CHECK(!pf_enabled_text(absent));
    struct envara_app_native_preflight out={0};CHECK(envara_app_native_preflight("00112233-4455-4677-8899-aabbccddeeff","00112233-4455-4677-8899-aabbccddeeff",&out)==-1);
    struct envara_app_native_admission admission;memset(&admission,255,sizeof(admission));CHECK(envara_app_native_factory_admission(NULL,&admission)==-1);
    struct envara_app_native_admission zero={0};CHECK(!memcmp(&zero,&admission,sizeof(zero)));
    CHECK(envara_app_native_factory_provider(NULL)==NULL);CHECK(!envara_app_native_factory_release_safe(NULL));
    int first[2],second[2],replacement[2];CHECK(!pipe(first)&&!pipe(second)&&!pipe(replacement));
    CHECK(!fcntl(first[0],F_SETFD,FD_CLOEXEC)&&!fcntl(second[0],F_SETFD,FD_CLOEXEC));
    pretend_root_owner=1;struct envara_app_native_factory f={0};f.owned.lease_read_fd=first[0];f.owned.recovery_read_fd=second[0];
    CHECK(pipe_reader(first[0],&f.lease_pipe_identity));CHECK(pipe_reader(second[0],&f.recovery_pipe_identity));CHECK(pipes_original(&f));
    descriptor_flags_unknown=1;struct stat observed;CHECK(!pipe_reader(first[0],&observed));
    f.owned.original_utun_fd=first[0];CHECK(!utun_original(&f)); // flags unknown must precede all ioctls
    descriptor_flags_unknown=0;CHECK(dup2(replacement[0],first[0])==first[0]);CHECK(!fcntl(first[0],F_SETFD,FD_CLOEXEC));
    CHECK(pipe_reader(first[0],&observed));CHECK(!pipes_original(&f)); // a valid replacement pipe is not the original
    for(int i=0;i<2;i++){close(first[i]);close(second[i]);close(replacement[i]);}
    // An actual loopback listener and its original inode are insufficient:
    // the kernel socket credential must independently be root + owned realm.
    pretend_root_owner=0;struct envara_app_listener listener={.fd=-1};
    CHECK(!envara_app_listener_open(&listener));CHECK(!fstat(listener.fd,&observed));
    CHECK(observed.st_uid==getuid()&&observed.st_gid==getgid());
    f.owned.original_listener_fd=listener.fd;f.listener_identity=observed;
    f.config.tcp_front_port=listener.port;f.plan.realm_gid=7111;
    CHECK(!listener_original(&f)); // ordinary UID cannot become an admitted server
    pretend_root_owner=1;CHECK(!listener_original(&f)); // model root UID alone, actual unrelated GID
    pretend_root_owner=0;CHECK(!envara_app_listener_close(&listener));
    ticket_fixture(argv[1],argv[2]);
    printf("{\"checks\":%u,\"root\":false,\"pf\":false}\n",checks);return 0;
}}
`;

test('production factory initializer and real private tickets retain mandatory fail-closed custody', { skip: process.platform !== 'darwin' }, async t => {
  assert.notEqual(process.getuid(), 0);
  const temp = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-app-factory-inert-')));
  try {
    const filename = path.join(temp, 'fixture.m'), binary = path.join(temp, 'fixture');
    await writeFile(filename, fixture);
    const make = await readFile(path.join(native, 'Makefile'), 'utf8');
    const linked = make.match(/^NATIVE_SOURCES = (.+)$/m)[1].split(' ').filter(s => !['main.c', 'app-native-factory.m'].includes(s)).map(s => path.join(native, s));
    await run('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
      `-DFACTORY_SOURCE="${path.join(native, 'app-native-factory.m')}"`, filename, ...linked,
      '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', binary], { timeout: 60_000 });
    const bundle = path.join(temp, 'Inert.app');
    await mkdir(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
    await mkdir(path.join(bundle, 'Contents', 'Resources'), { mode: 0o755 });
    await copyFile(binary, path.join(bundle, 'Contents', 'MacOS', 'Fixture')); await chmod(path.join(bundle, 'Contents', 'MacOS', 'Fixture'), 0o755);
    await writeFile(path.join(bundle, 'Contents', 'Info.plist'), '<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>io.envara.factory-inert</string><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>', { mode: 0o644 });
    const { stdout } = await run(binary, [temp, bundle], { timeout: 10_000 });
    const report = JSON.parse(stdout); assert.ok(report.checks >= 130); assert.equal(report.root, false); assert.equal(report.pf, false);
    t.diagnostic(`${report.checks} native assertions; real inert registration, preparation, inspection and single-use claim; no root/PF/app launch`);
  } finally {
    const removable = async target => { const info = await lstat(target); assert.equal(info.uid, process.getuid());
      if (info.isDirectory()) { await chmod(target, 0o700); for (const name of await readdir(target)) await removable(path.join(target, name)); }
      else if (info.isFile()) await chmod(target, 0o600); };
    await removable(temp); await rm(temp, { recursive: true, force: true });
  }
});

test('factory authority uses a private durable journal, immutable original descriptors and fresh live-mode guards', async () => {
  const source = await readFile(path.join(native, 'app-native-factory.m'), 'utf8');
  /* A live mode is the one this factory's registered profile owns; DENY/EMPTY
   * stay available to either profile. FRONT/RUNNING guards are still required. */
  assert.match(source, /f->guard_live=mode_is_live\(mode\)/);
  assert.match(source, /basic\(f,mode_is_live\(mode\)\)/);
  assert.match(source, /journal_write\(f,@"intent",intent\)/);
  assert.match(source, /O_RDWR\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC,0600/);
  assert.match(source, /f->poisoned=1;f->cleanup_reconciled=0;return operation_refuse/);
  assert.match(source, /envara_app_scope_gid_absent\(f->plan.realm_gid\)==1/);
  assert.match(source, /ENVARA_PF_PRODUCTION_EMPTY,0\)\|\|!scope_absent/);
  assert.match(source, /envara_journal_retirement_init\(&f->retirement/);
  assert.match(source, /dependencies\(f\)&&pf_running\(f\)/);
  assert.match(source, /f->lease_pipe_identity\.st_ino/);
  assert.match(source, /copied_one\.st_ino!=f->lease_pipe_identity\.st_ino/);
  assert.match(source, /mode_is_live\(mode\)&&!f->staged&&envara_app_scope_gid_absent/);
  /* The profile selects the live mode from the registered snapshot only. */
  assert.match(source, /static EnvaraPFProductionMode live_mode\(const struct envara_app_native_factory \*f\)/);
  assert.match(source, /f->notion_front\?ENVARA_PF_PRODUCTION_FRONT:ENVARA_PF_PRODUCTION_ROUTED/);
  assert.match(source, /guard->verify_resume=verify_resume/);
  assert.match(source, /SecCodeCopyGuestWithAttributes/);
  assert.match(source, /p\.kp_eproc\.e_ucred\.cr_ngroups!=1/);
  assert.doesNotMatch(source, /\b(?:system|setuid|setgid|setgroups|envara_child_resume)\s*\(/);
});
