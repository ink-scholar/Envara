import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/app-scope-proof.c',import.meta.url));

test('scope proof exposes native read-only GID proof and fixed non-authoritative diagnostics', async () => {
  const [implementation,header] = await Promise.all([readFile(source,'utf8'),readFile(new URL('../native/macos-pf-routing/app-scope-proof.h',import.meta.url),'utf8')]);
  assert.doesNotMatch(implementation,/\b(?:open|fork|execve|system|posix_spawn|setuid|setgid|setgroups|kill|ioctl|unlink|mkdir|rename)\s*\(/);
  assert.doesNotMatch(implementation,/getgrgid|getgrnam|4fe07677|inert.*override|JSON/);
  assert.match(implementation,/proc_pidinfo\(pid, PROC_PIDTBSDINFO, 1,/);
  assert.match(implementation,/CTL_KERN, KERN_PROC, KERN_PROC_PID, pid/);
  assert.match(implementation,/sysctlbyname\("kern.ngroups"/);
  assert.match(header,/int envara_app_scope_gid_absent\(gid_t gid\);/);
  assert.doesNotMatch(header,/ScopeReaders|ForTest|callback|context|fixed.run/i);
  assert.match(header,/const EnvaraScopeDiagnostic \*envara_app_scope_last_diagnostic\(void\);/);
});

const harness = String.raw`
#include <assert.h>
#include <errno.h>
#include <libproc.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>
static uid_t stub_getuid(void);
static uid_t stub_geteuid(void);
static int stub_proc_listallpids(void *,int);
static int stub_proc_pidinfo(int,int,uint64_t,void *,int);
static int stub_sysctl(int *,unsigned,void *,size_t *,void *,size_t);
static int stub_sysctlbyname(const char *,void *,size_t *,void *,size_t);
static int stub_clock_gettime(clockid_t,struct timespec *);
static void *stub_calloc(size_t,size_t);
#define getuid stub_getuid
#define geteuid stub_geteuid
#define proc_listallpids stub_proc_listallpids
#define proc_pidinfo stub_proc_pidinfo
#define sysctl stub_sysctl
#define sysctlbyname stub_sysctlbyname
#define clock_gettime stub_clock_gettime
#define calloc stub_calloc
#include SCOPE_SOURCE
#undef getuid
#undef geteuid
#undef proc_listallpids
#undef proc_pidinfo
#undef sysctl
#undef sysctlbyname
#undef clock_gettime
#undef calloc

typedef struct {
    const char *scenario;
    unsigned root_calls, capacity_calls, list_calls, bsd_calls, supplementary_calls, clock_calls, allocations;
    unsigned native_uid_calls, native_list_calls, native_bsd_calls, native_sysctl_calls, native_capacity_calls, native_clock_calls;
} Fixture;
static Fixture *native_fixture;
static int is(Fixture *f,const char *name) { return !strcmp(f->scenario,name); }
static ScopeCredentials credential(pid_t pid) {
    return (ScopeCredentials){.pid=pid,.status=SRUN,.seconds=1234567+(uint64_t)pid,.microseconds=456,
        .effective_uid=501,.real_uid=501,.saved_uid=501,.effective_gid=20,.real_gid=20,.saved_gid=20};
}
static int root(void *context) {
    Fixture *f=context; f->root_calls++;
    if (is(f,"root-unknown")) return 2;
    return !is(f,"nonroot") && !(is(f,"root-drift") && f->root_calls>4);
}
static int capacity(void *context,unsigned *out) {
    Fixture *f=context; f->capacity_calls++;
    if (is(f,"capacity-error") || (is(f,"capacity-final-error") && f->capacity_calls>1)) return -1;
    *out=is(f,"capacity-mismatch") || (is(f,"capacity-final-mismatch") && f->capacity_calls>1) ? NGROUPS+1 : NGROUPS;
    return 0;
}
static double clock_read(void *context) {
    Fixture *f=context; f->clock_calls++;
    if (is(f,"clock-nan")) return NAN;
    if (is(f,"clock-infinity")) return INFINITY;
    if (is(f,"clock-negative")) return -1;
    if (is(f,"deadline")) return (double)f->clock_calls*5;
    if (is(f,"deadline-final") && f->capacity_calls>1) return 17;
    if (is(f,"retry-deadline") && f->bsd_calls) return 16;
    return 1;
}
static int list(void *context,pid_t *pids,size_t capacity_value) {
    Fixture *f=context; f->list_calls++; assert(capacity_value==SCOPE_PID_LIMIT);
    if (is(f,"list-error")) return -1;
    if (is(f,"list-capacity")) return (int)capacity_value;
    if (is(f,"list-empty")) return 0;
    if (is(f,"list-zero-only")) {pids[0]=0;return 1;}
    pids[0]=1002; pids[1]=0; pids[2]=1001;
    if (is(f,"list-negative")) pids[0]=-1;
    if (is(f,"list-duplicate")) pids[0]=1001;
    if (is(f,"list-changed") && f->list_calls==2) pids[0]=1003;
    if (is(f,"list-count-changed") && f->list_calls==2) return 2;
    return 3;
}
static int bsd(void *context,pid_t pid,ScopeCredentials *out) {
    Fixture *f=context; f->bsd_calls++;
    if ((is(f,"retry-once")||is(f,"retry-owned")||is(f,"retry-deadline")||is(f,"retry-permission")) && f->bsd_calls==1) return 1;
    if (is(f,"retry-permission") && f->list_calls==2) {errno=EPERM;return -1;}
    if (is(f,"bsd-error") || (is(f,"bsd-final-error") && f->bsd_calls%2==0) ||
        (is(f,"bsd-second-error") && f->list_calls==2)) {errno=ESRCH;return -1;}
    *out=credential(pid);
    if (is(f,"owned-effective")) out->effective_gid=7171;
    if (is(f,"owned-real")) out->real_gid=7171;
    if (is(f,"owned-saved")) out->saved_gid=7171;
    if (is(f,"retry-owned") && f->list_calls==2) out->saved_gid=7171;
    if (is(f,"pid-mismatch")) out->pid++;
    if (is(f,"birth-zero")) out->seconds=0;
    if (is(f,"microseconds-invalid")) out->microseconds=1000000;
    if (is(f,"status-invalid")) out->status=0;
    if (is(f,"bsd-group-count")) out->group_count=NGROUPS+1;
    if (is(f,"birth-bracket") && f->bsd_calls%2==0) out->seconds++;
    if (is(f,"saved-uid-bracket") && f->bsd_calls%2==0) out->saved_uid++;
    if (is(f,"zombie")) out->status=SZOMB;
    if (is(f,"zombie-transition") && f->bsd_calls%2==0) out->status=SZOMB;
    if (is(f,"identity-second") && f->list_calls==2) out->seconds++;
    if (is(f,"owned-second") && f->list_calls==2) out->saved_gid=7171;
    return 0;
}
static int supplementary(void *context,pid_t pid,ScopeCredentials *out) {
    Fixture *f=context; f->supplementary_calls++;
    if (is(f,"supplementary-error")) {errno=EPERM;return -1;}
    *out=credential(pid); out->group_count=2; out->groups[0]=20; out->groups[1]=80;
    if (is(f,"full-groups") || is(f,"owned-last") || is(f,"last-group-second")) {
        out->group_count=NGROUPS; for(unsigned i=1;i<NGROUPS;i++) out->groups[i]=80+i;
    }
    if (is(f,"owned-supplementary")) out->groups[1]=7171;
    if (is(f,"owned-last")) out->groups[NGROUPS-1]=7171;
    if (is(f,"last-group-second") && f->list_calls==2) out->groups[NGROUPS-1]++;
    if (is(f,"groups-empty")) out->group_count=0;
    if (is(f,"groups-overflow")) out->group_count=NGROUPS+1;
    if (is(f,"groups-duplicate")) out->groups[1]=20;
    if (is(f,"groups-primary")) out->groups[0]=21;
    if (is(f,"binding-effective-uid")) out->effective_uid++;
    if (is(f,"binding-real-uid")) out->real_uid++;
    if (is(f,"binding-saved-uid")) out->saved_uid++;
    if (is(f,"binding-effective-gid")) {out->effective_gid++;out->groups[0]++;}
    if (is(f,"binding-real-gid")) out->real_gid++;
    if (is(f,"binding-saved-gid")) out->saved_gid++;
    if (is(f,"binding-pid")) out->pid++;
    if (is(f,"binding-birth")) out->microseconds++;
    if (is(f,"groups-second") && f->list_calls==2) out->groups[1]++;
    if (is(f,"zombie")) out->status=SZOMB;
    return 0;
}
static ScopeReaders readers(Fixture *f) {
    return (ScopeReaders){f,root,capacity,list,bsd,supplementary,clock_read};
}
static void *stub_calloc(size_t count,size_t bytes) {
    assert(native_fixture); native_fixture->allocations++;
    if (is(native_fixture,"allocation-error") && native_fixture->allocations==2) return NULL;
    return calloc(count,bytes);
}
static uid_t stub_getuid(void) {
    assert(native_fixture);native_fixture->native_uid_calls++;return is(native_fixture,"native-real-nonroot")?501:0;
}
static uid_t stub_geteuid(void) {assert(native_fixture);return is(native_fixture,"native-effective-nonroot")?501:0;}
static int stub_proc_listallpids(void *buffer,int bytes) {
    Fixture *f=native_fixture;assert(f);f->native_list_calls++;
    if (!buffer) {
        assert(bytes==0);if(is(f,"native-estimate-error"))return -1;
        if(is(f,"native-estimate-capacity"))return SCOPE_PID_LIMIT; return 3;
    }
    assert(bytes==(int)(SCOPE_PID_LIMIT*sizeof(pid_t)));
    if(is(f,"native-list-error"))return 0;
    return list(f,buffer,SCOPE_PID_LIMIT);
}
static int stub_proc_pidinfo(int pid,int flavor,uint64_t argument,void *buffer,int bytes) {
    Fixture *f=native_fixture;assert(f);f->native_bsd_calls++;
    assert(pid==1001||pid==1002); assert(flavor==PROC_PIDTBSDINFO&&argument==1&&bytes==sizeof(struct proc_bsdinfo));
    if(is(f,"native-bsd-esrch") || ((is(f,"native-bsd-esrch-once")||is(f,"native-bsd-esrch-deadline"))&&f->native_bsd_calls==1)){errno=ESRCH;return 0;}
    if(is(f,"native-bsd-permission")){errno=EPERM;return 0;}
    if(is(f,"native-bsd-zero-unknown"))return 0;
    if(is(f,"native-bsd-partial-esrch")){errno=ESRCH;return bytes-1;}
    if(is(f,"native-bsd-short"))return bytes-1;
    ScopeCredentials c=credential(pid);
    struct proc_bsdinfo info={.pbi_pid=(uint32_t)pid,.pbi_status=SZOMB,.pbi_start_tvsec=c.seconds,.pbi_start_tvusec=c.microseconds,
        .pbi_uid=c.effective_uid,.pbi_ruid=c.real_uid,.pbi_svuid=c.saved_uid,.pbi_gid=c.effective_gid,.pbi_rgid=c.real_gid,.pbi_svgid=c.saved_gid};
    if(is(f,"native-owned-saved"))info.pbi_svgid=7171;
    memcpy(buffer,&info,sizeof(info));return sizeof(info);
}
static int stub_sysctl(int *mib,unsigned mib_count,void *buffer,size_t *bytes,void *new_value,size_t new_size) {
    Fixture *f=native_fixture;assert(f);f->native_sysctl_calls++;
    assert(mib_count==4&&mib[0]==CTL_KERN&&mib[1]==KERN_PROC&&mib[2]==KERN_PROC_PID&&(mib[3]==1001||mib[3]==1002));
    assert(buffer&&bytes&&*bytes==sizeof(struct kinfo_proc)&&!new_value&&!new_size);
    if(is(f,"native-sysctl-esrch")){errno=ESRCH;return -1;}
    if(is(f,"native-sysctl-esrch-zero") || (is(f,"native-sysctl-esrch-once")&&f->native_sysctl_calls==1)){*bytes=0;errno=ESRCH;return -1;}
    if(is(f,"native-sysctl-success-esrch")){*bytes=0;errno=ESRCH;return 0;}
    if(is(f,"native-sysctl-partial-esrch")){(*bytes)--;errno=ESRCH;return -1;}
    if(is(f,"native-sysctl-permission")){*bytes=0;errno=EPERM;return -1;}
    if(is(f,"native-sysctl-zero")){*bytes=0;return 0;}
    if(is(f,"native-sysctl-short")){(*bytes)--;return 0;}
    ScopeCredentials c=credential(mib[3]); struct kinfo_proc info={0};
    info.kp_proc.p_pid=c.pid;info.kp_proc.p_stat=SZOMB;info.kp_proc.p_starttime.tv_sec=(long)c.seconds;info.kp_proc.p_starttime.tv_usec=(int)c.microseconds;
    info.kp_eproc.e_ucred.cr_uid=c.effective_uid;info.kp_eproc.e_pcred.p_ruid=c.real_uid;info.kp_eproc.e_pcred.p_svuid=c.saved_uid;
    info.kp_eproc.e_pcred.p_rgid=c.real_gid;info.kp_eproc.e_pcred.p_svgid=c.saved_gid;
    info.kp_eproc.e_ucred.cr_ngroups=NGROUPS;info.kp_eproc.e_ucred.cr_groups[0]=20;
    for(unsigned i=1;i<NGROUPS;i++)info.kp_eproc.e_ucred.cr_groups[i]=80+i;
    if(is(f,"native-owned-last"))info.kp_eproc.e_ucred.cr_groups[NGROUPS-1]=7171;
    if(is(f,"native-groups-overflow"))info.kp_eproc.e_ucred.cr_ngroups=NGROUPS+1;
    if(is(f,"native-groups-negative"))info.kp_eproc.e_ucred.cr_ngroups=-1;
    memcpy(buffer,&info,sizeof(info));return 0;
}
static int stub_sysctlbyname(const char *name,void *buffer,size_t *bytes,void *new_value,size_t new_size) {
    Fixture *f=native_fixture;assert(f);f->native_capacity_calls++;
    assert(!strcmp(name,"kern.ngroups")&&buffer&&bytes&&*bytes==sizeof(int)&&!new_value&&!new_size);
    if(is(f,"native-capacity-error")){errno=EPERM;return -1;}
    if(is(f,"native-capacity-short")){(*bytes)--;return 0;}
    int value=is(f,"native-capacity-mismatch")?NGROUPS+1:NGROUPS;
    if(is(f,"native-capacity-zero"))value=0;
    memcpy(buffer,&value,sizeof(value));return 0;
}
static int stub_clock_gettime(clockid_t which,struct timespec *value) {
    Fixture *f=native_fixture;assert(f&&which==CLOCK_MONOTONIC);f->native_clock_calls++;
    if(is(f,"native-clock-error"))return -1;
    *value=(struct timespec){is(f,"native-bsd-esrch-deadline")&&f->native_bsd_calls?16:1,0};return 0;
}
int main(int argc,char **argv) {
    assert(argc==2); Fixture f={.scenario=argv[1]};native_fixture=&f;ScopeReaders r=readers(&f);
    if (!strncmp(argv[1],"native-",7)) {
        int expected=is(&f,"native-zombies-complete")||is(&f,"native-bsd-esrch-once")||is(&f,"native-sysctl-esrch-once");
        int result=envara_app_scope_gid_absent(7171);assert(result==expected);
        const EnvaraScopeDiagnostic *diagnostic=envara_app_scope_last_diagnostic();
        assert(diagnostic->rounds<=3&&diagnostic->retry_count<=2);
        if(is(&f,"native-zombies-complete")) assert(f.native_list_calls==4&&f.native_bsd_calls==8&&f.native_sysctl_calls==4&&f.native_capacity_calls==2);
        if(is(&f,"native-real-nonroot")||is(&f,"native-effective-nonroot")) assert(!f.native_list_calls&&!f.native_capacity_calls&&!f.native_bsd_calls);
        if(is(&f,"native-bsd-esrch")) assert(f.native_bsd_calls==3&&f.native_list_calls==6&&!f.native_sysctl_calls&&diagnostic->rounds==3&&diagnostic->retry_count==2&&diagnostic->retry_exhausted==1&&diagnostic->first_reason==ENVARA_SCOPE_BSD_READER_REFUSED&&diagnostic->first_native_errno==ESRCH&&diagnostic->first_native_bytes==0&&diagnostic->first_native_query==ENVARA_SCOPE_QUERY_BSD);
        if(is(&f,"native-bsd-esrch-once")) assert(f.native_bsd_calls==9&&f.native_list_calls==6&&f.native_sysctl_calls==4&&diagnostic->rounds==2&&diagnostic->retry_count==1&&diagnostic->reason==ENVARA_SCOPE_ABSENCE_VERIFIED&&diagnostic->first_reason==ENVARA_SCOPE_BSD_READER_REFUSED);
        if(is(&f,"native-sysctl-esrch-once")) assert(f.native_bsd_calls==9&&f.native_list_calls==6&&f.native_sysctl_calls==5&&diagnostic->rounds==2&&diagnostic->retry_count==1&&diagnostic->reason==ENVARA_SCOPE_ABSENCE_VERIFIED&&diagnostic->first_reason==ENVARA_SCOPE_SUPPLEMENTARY_READER_REFUSED);
        if(is(&f,"native-sysctl-esrch-zero")) assert(f.native_sysctl_calls==3&&f.native_bsd_calls==3&&f.native_list_calls==6&&diagnostic->retry_exhausted==1&&diagnostic->first_native_errno==ESRCH&&diagnostic->first_native_bytes==0&&diagnostic->first_native_query==ENVARA_SCOPE_QUERY_SUPPLEMENTARY);
        if(is(&f,"native-bsd-esrch-deadline")) assert(f.native_bsd_calls==1&&f.native_list_calls==2&&diagnostic->rounds==2&&diagnostic->retry_count==1&&diagnostic->reason==ENVARA_SCOPE_DEADLINE_REFUSED&&!diagnostic->retry_exhausted);
        if(is(&f,"native-bsd-permission")||is(&f,"native-bsd-partial-esrch")||is(&f,"native-bsd-zero-unknown")) assert(f.native_bsd_calls==1&&f.native_list_calls==2&&diagnostic->rounds==1&&!diagnostic->retry_count);
        if(is(&f,"native-sysctl-esrch")||is(&f,"native-sysctl-permission")||is(&f,"native-sysctl-partial-esrch")||is(&f,"native-sysctl-success-esrch")) assert(f.native_sysctl_calls==1&&f.native_bsd_calls==1&&f.native_list_calls==2&&diagnostic->rounds==1&&!diagnostic->retry_count);
        if(is(&f,"native-sysctl-zero")) assert(f.native_sysctl_calls==1&&f.native_bsd_calls==1&&f.native_list_calls==2);
        return 0;
    }
    if(is(&f,"missing-root"))r.root=NULL;
    if(is(&f,"missing-capacity"))r.capacity=NULL;
    if(is(&f,"missing-list"))r.list=NULL;
    if(is(&f,"missing-bsd"))r.bsd=NULL;
    if(is(&f,"missing-supplementary"))r.supplementary=NULL;
    if(is(&f,"missing-clock"))r.clock=NULL;
    gid_t gid=is(&f,"gid-lower")?7099:is(&f,"gid-upper")?8000:7171;
    int result=scope_gid_absent(gid,&r);int expected=is(&f,"stable")||is(&f,"full-groups")||is(&f,"zombie")||is(&f,"list-changed")||is(&f,"list-count-changed")||is(&f,"identity-second")||is(&f,"groups-second")||is(&f,"last-group-second")||is(&f,"retry-once");
    assert(result==expected);
    const EnvaraScopeDiagnostic *diagnostic=envara_app_scope_last_diagnostic();
    if(is(&f,"stable")||is(&f,"full-groups")||is(&f,"zombie"))assert(f.list_calls==2&&f.bsd_calls==8&&f.supplementary_calls==4&&f.capacity_calls==2&&diagnostic->rounds==1&&!diagnostic->retry_count&&diagnostic->reason==ENVARA_SCOPE_ABSENCE_VERIFIED);
    if(expected&&diagnostic->retry_count) assert(diagnostic->rounds==2&&diagnostic->retry_count==1&&!diagnostic->retry_exhausted&&diagnostic->reason==ENVARA_SCOPE_ABSENCE_VERIFIED&&diagnostic->first_count==2&&diagnostic->second_count==2);
    if(is(&f,"nonroot")||is(&f,"root-unknown")||is(&f,"gid-lower")||is(&f,"gid-upper")||!strncmp(argv[1],"missing-",8))
        assert(!f.list_calls&&!f.bsd_calls&&!f.supplementary_calls&&!f.capacity_calls);
    if(is(&f,"list-changed")||is(&f,"list-count-changed"))assert(f.list_calls==4&&f.bsd_calls==12&&f.supplementary_calls==6&&diagnostic->first_reason==ENVARA_SCOPE_PID_INVENTORY_CHANGED);
    if(is(&f,"retry-once"))assert(f.list_calls==3&&f.bsd_calls==9&&f.supplementary_calls==4);
    if(is(&f,"retry-owned"))assert(f.list_calls==2&&f.bsd_calls==2&&!f.supplementary_calls&&diagnostic->reason==ENVARA_SCOPE_GID_PRESENT&&diagnostic->rounds==2&&diagnostic->retry_count==1);
    if(is(&f,"retry-permission"))assert(f.list_calls==2&&f.bsd_calls==2&&!f.supplementary_calls&&diagnostic->reason==ENVARA_SCOPE_BSD_READER_REFUSED&&diagnostic->rounds==2&&diagnostic->retry_count==1);
    if(is(&f,"retry-deadline"))assert(f.list_calls==1&&f.bsd_calls==1&&!f.supplementary_calls&&diagnostic->reason==ENVARA_SCOPE_DEADLINE_REFUSED&&diagnostic->rounds==2&&diagnostic->retry_count==1);
    if(is(&f,"birth-bracket")||is(&f,"saved-uid-bracket")||is(&f,"zombie-transition")||is(&f,"binding-real-uid"))assert(f.list_calls==3&&diagnostic->rounds==3&&diagnostic->retry_count==2&&diagnostic->retry_exhausted==1&&diagnostic->reason==ENVARA_SCOPE_IDENTITY_MISMATCH);
    if(is(&f,"bsd-error"))assert(f.list_calls==1&&f.bsd_calls==1&&!f.supplementary_calls);
    if(is(&f,"supplementary-error"))assert(f.list_calls==1&&f.bsd_calls==1&&f.supplementary_calls==1);
    return 0;
}
`;

test('two complete inventories and native credential decoders with inert callbacks only',{skip:process.platform!=='darwin'},async t=>{
  const directory=await realpath(await mkdtemp(path.join(tmpdir(),'envara-app-scope-proof-test-')));
  try {
    const input=path.join(directory,'fixture.c'),binary=path.join(directory,'fixture');
    await writeFile(input,harness.replace('SCOPE_SOURCE',JSON.stringify(source)));
    await execute('/usr/bin/clang',['-std=c11','-O2','-Wall','-Wextra','-Werror',input,'-o',binary],{timeout:30000,maxBuffer:1024*1024});
    const cases=['stable','full-groups','zombie','nonroot','root-unknown','root-drift','gid-lower','gid-upper',
      'missing-root','missing-capacity','missing-list','missing-bsd','missing-supplementary','missing-clock',
      'capacity-error','capacity-mismatch','capacity-final-error','capacity-final-mismatch',
      'clock-nan','clock-infinity','clock-negative','deadline','deadline-final','allocation-error',
      'retry-once','retry-owned','retry-permission','retry-deadline',
      'list-error','list-capacity','list-empty','list-zero-only','list-negative','list-duplicate','list-changed','list-count-changed',
      'owned-effective','owned-real','owned-saved','owned-supplementary','owned-last','owned-second',
      'bsd-error','bsd-final-error','bsd-second-error','supplementary-error','pid-mismatch','birth-zero','microseconds-invalid','status-invalid','bsd-group-count',
      'birth-bracket','saved-uid-bracket','zombie-transition','identity-second','groups-second','last-group-second',
      'groups-empty','groups-overflow','groups-duplicate','groups-primary','binding-effective-uid','binding-real-uid','binding-saved-uid',
      'binding-effective-gid','binding-real-gid','binding-saved-gid','binding-pid','binding-birth',
      'native-zombies-complete','native-real-nonroot','native-effective-nonroot','native-estimate-error','native-estimate-capacity','native-list-error',
      'native-bsd-esrch','native-bsd-short','native-owned-saved','native-owned-last','native-sysctl-esrch','native-sysctl-zero','native-sysctl-short',
      'native-bsd-esrch-once','native-bsd-esrch-deadline','native-bsd-permission','native-bsd-partial-esrch','native-bsd-zero-unknown',
      'native-sysctl-esrch-once','native-sysctl-esrch-zero','native-sysctl-success-esrch','native-sysctl-partial-esrch','native-sysctl-permission',
      'native-groups-overflow','native-groups-negative','native-capacity-error','native-capacity-short','native-capacity-mismatch','native-capacity-zero','native-clock-error'];
    for(const scenario of cases) await t.test(scenario,()=>execute(binary,[scenario],{timeout:10000}));
  } finally {await rm(directory,{recursive:true,force:true});}
});
