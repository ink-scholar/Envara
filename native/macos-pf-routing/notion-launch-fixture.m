#import <Foundation/Foundation.h>
#include "notion-launch.m"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Standalone nonroot fixture. It never executes/copies/modifies Notion,
 * contacts a DNS broker, activates PF, or authorizes a protected launch. */
static int deny(const struct envara_gui_request *request, void *context) {
    (void)request; (void)context; errno = ENOTSUP; return -1;
}
static int inet_probe(const char *host, const char *port, int udp, int inherited) {
    int parsed = atoi(port); if (parsed < 1024 || parsed > 65535 || (strcmp(host, "127.0.0.1") && strcmp(host, "::1"))) return 101;
    int pair[2]; pid_t child;
    if (inherited) {
        if (pipe(pair) || (child = fork()) < 0) return 102;
        if (child) {
            close(pair[1]); int values[2], status; ssize_t n = read(pair[0], values, sizeof(values)); close(pair[0]);
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) || n != sizeof(values)) return 103;
            printf("{\"connected\":%s,\"error\":%d,\"childObserved\":true,\"ready\":false,\"protected\":false}\n", values[0] ? "true" : "false", values[1]); return 0;
        }
        close(pair[0]);
    }
    int v6 = !strcmp(host, "::1"), fd = socket(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0) return 104;
    struct sockaddr_storage storage = {0}; socklen_t size;
    if (v6) {
        struct sockaddr_in6 *address = (void *)&storage; address->sin6_len = sizeof(*address); address->sin6_family = AF_INET6;
        address->sin6_port = htons((uint16_t)parsed); inet_pton(AF_INET6, host, &address->sin6_addr); size = sizeof(*address);
    } else {
        struct sockaddr_in *address = (void *)&storage; address->sin_len = sizeof(*address); address->sin_family = AF_INET;
        address->sin_port = htons((uint16_t)parsed); inet_pton(AF_INET, host, &address->sin_addr); size = sizeof(*address);
    }
    int success = udp ? sendto(fd, "owned", 5, 0, (struct sockaddr *)&storage, size) == 5 : connect(fd, (struct sockaddr *)&storage, size) == 0;
    int error = success ? 0 : errno; close(fd);
    if (inherited) { int values[] = {success,error}; _exit(write(pair[1], values, sizeof(values)) == sizeof(values) ? 0 : 105); }
    printf("{\"connected\":%s,\"error\":%d,\"childObserved\":false,\"ready\":false,\"protected\":false}\n", success ? "true" : "false", error); return 0;
}
static int socket_probe(const char *path, int inherited) {
    if (!path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 90;
    struct stat s;
    if (lstat(path, &s) || !S_ISSOCK(s.st_mode) || s.st_uid != getuid()) return 91;
    int result_pipe[2] = {-1, -1}; pid_t child = -1;
    if (inherited) {
        if (pipe(result_pipe)) return 92;
        child = fork(); if (child < 0) return 93;
        if (child > 0) {
            close(result_pipe[1]); int result[2], status;
            ssize_t count = read(result_pipe[0], result, sizeof(result)); close(result_pipe[0]);
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) || count != (ssize_t)sizeof(result)) return 94;
            printf("{\"connected\":%s,\"error\":%d,\"childObserved\":true,\"ready\":false,\"protected\":false}\n",
                result[0] ? "true" : "false", result[1]); return 0;
        }
        close(result_pipe[0]);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) return 95;
    struct sockaddr_un address = {0}; address.sun_family = AF_UNIX; address.sun_len = sizeof(address); strcpy(address.sun_path, path);
    int connected = connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0, error = connected ? 0 : errno;
    close(fd);
    if (inherited) { int result[] = {connected, error}; _exit(write(result_pipe[1], result, sizeof(result)) == (ssize_t)sizeof(result) ? 0 : 96); }
    printf("{\"connected\":%s,\"error\":%d,\"childObserved\":false,\"ready\":false,\"protected\":false}\n", connected ? "true" : "false", error);
    return 0;
}
static int refusal(const char *bundle, const char *workspace) {
    struct envara_gui_manifest manifest;
    if (envara_gui_manifest_inspect(bundle, 1, &manifest) || strcmp(manifest.identifier, "notion.id")) return 97;
    int supported_refused = envara_notion_supported(&manifest) == -1 && errno == EACCES;
    struct envara_app_registration app = {0}; app.schema = ENVARA_APP_REGISTRY_SCHEMA;
    strcpy(app.registration_id, "00000000-0000-4000-8000-000000000201");
    strcpy(app.version_id, "00000000-0000-4000-8000-000000000202"); app.original = app.snapshot = manifest;
    app.original.fixture_only = app.snapshot.fixture_only = 0;
    struct envara_gui_request request = {0}; request.schema = ENVARA_GUI_SCHEMA;
    request.console_uid = getuid(); request.realm_gid = ENVARA_REALM_GID_MIN;
    strcpy(request.lease_id, "00000000-0000-4000-8000-000000000203");
    strcpy(request.environment_id, "00000000-0000-4000-8000-000000000204");
    if (strlen(workspace) >= sizeof(request.cwd)) return 98;
    strcpy(request.cwd, workspace); strcpy(request.timezone, "Asia/Shanghai"); strcpy(request.browser_locale, "zh-CN");
    struct envara_notion_context context = {0}; strcpy(context.registration_id, app.registration_id); context.front_port = 23456;
    struct envara_notion_plan plan; memset(&plan, 0xa5, sizeof(plan));
    int plan_refused = envara_notion_plan(&app, &request, &context, &plan) == -1 &&
        !plan.ready && !plan.protected_ready && !plan.resumed;
    int unsealed_refused = envara_gui_sealed_snapshot_validate(&app.snapshot) == -1;
    struct envara_gui_lifecycle lifecycle; envara_gui_lifecycle_init(&lifecycle);
    struct envara_gui_stage_authority authority = {deny, NULL};
    int stage_refused = envara_notion_stage(&app, &request, &context, &authority, &lifecycle) == -1 && errno == EACCES &&
        lifecycle.phase == ENVARA_GUI_EMPTY && lifecycle.child.identity.pid == 0 && !lifecycle.protected_ready;
    int okay = supported_refused && plan_refused && unsealed_refused && stage_refused;
    printf("{\"ok\":%s,\"fixtureManifestRefused\":%s,\"unsealedRefused\":%s,\"planRefused\":%s,\"stageRefused\":%s,"
        "\"childPID\":%d,\"ready\":false,\"protected\":false,\"activatesSystem\":false}\n",
        okay ? "true" : "false", supported_refused ? "true" : "false", unsealed_refused ? "true" : "false",
        plan_refused ? "true" : "false", stage_refused ? "true" : "false", lifecycle.child.identity.pid);
    return okay ? 0 : 1;
}
static int supported(const char *bundle) {
    struct envara_gui_manifest manifest; int result = envara_gui_manifest_inspect(bundle, 0, &manifest), error = errno;
    enum envara_notion_engine engine=ENVARA_NOTION_ENGINE_NONE;
    if (!result) { result = envara_notion_engine(&manifest,&engine); error = result ? errno : 0; }
    char team[11]={0}; if(!result) (void)envara_gui_requirement_team(manifest.requirement,team);
    NSString *version = plist_string(bundle, @"Contents/Info.plist", @"CFBundleShortVersionString");
    NSString *electron = plist_string(bundle, @"Contents/Frameworks/Electron Framework.framework/Resources/Info.plist", @"CFBundleVersion");
    NSDictionary *report = @{@"ok":@YES,@"supported":result == 0 ? @YES : @NO,@"error":@(error),@"ready":@NO,@"protected":@NO,@"activatesSystem":@NO,
        @"supportedVersion":version ?: @"",@"electronVersion":electron ?: @"",@"requiredTeam":@(team),@"engine":@(engine)};
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
    if (!bytes || fwrite(bytes.bytes, 1, bytes.length, stdout) != bytes.length || putchar('\n') == EOF) return 107;
    return 0;
}
static int metadata(const char *bundle) {
    struct envara_gui_manifest manifest;
    if(envara_gui_manifest_inspect(bundle,1,&manifest)) return 108;
    enum envara_notion_engine engine=engine_metadata(&manifest,NULL);
    int refused=envara_notion_supported(&manifest)==-1 && errno==EACCES;
    NSDictionary *value=@{@"ok":@YES,@"engine":@(engine),@"metadataOnly":@YES,@"signedCapabilityVerified":@NO,
        @"fixtureManifestRefused":refused?@YES:@NO,@"ready":@NO,@"protected":@NO,@"activatesSystem":@NO};
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
    return !data || fwrite(data.bytes,1,data.length,stdout)!=data.length || putchar('\n')==EOF ? 109:0;
}
static int context_plan(const char *environment, const char *registration, const char *language) {
    struct envara_notion_plan plan={0}; struct envara_gui_request request={0};
    if(strlen(language)>=sizeof(request.browser_locale)) return 110;
    strcpy(request.browser_locale,language);strcpy(request.timezone,"Asia/Manila");
    if(plan_paths(environment,registration,&plan) || plan_locale(language,&plan)) return 111;
    struct envara_app_registration app={0};strcpy(app.snapshot.executable,"/owned/fixture");
    struct envara_notion_context context={.front_port=23456};
    if(plan_arguments(&app,&request,&context,ENVARA_NOTION_ENGINE_VSCODE,&plan)) return 112;
    struct notion_child_environment env;
    if(child_environment(&plan,&request,"fixture",&env)) return 113;
    NSMutableArray *arguments=[NSMutableArray array],*values=[NSMutableArray array];
    for(int i=0;i<plan.argument_count;i++) [arguments addObject:@(plan.arguments[i])];
    for(unsigned i=0;env.values[i];i++) [values addObject:@(env.values[i])];
    NSDictionary *report=@{@"ok":@YES,@"allocationVerified":@NO,@"UserData":@(plan.user_data),@"Home":@(plan.home),
        @"Cache":@(plan.cache),@"Temp":@(plan.temp),@"Extensions":@(plan.extensions),@"SharedData":@(plan.shared_data),
        @"UserDataAlias":@(plan.user_data_alias),@"TempAlias":@(plan.temp_alias),
        @"posixLocale":@(plan.posix_locale),@"localeFallback":plan.locale_fallback?@YES:@NO,@"arguments":arguments,@"environment":values,
        @"ready":@NO,@"protected":@NO,@"activatesSystem":@NO};
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
    return !data || fwrite(data.bytes,1,data.length,stdout)!=data.length || putchar('\n')==EOF ? 114:0;
}
struct scope_thread_context {const struct envara_gui_manifest *manifest;int valid;};
static void *scope_thread(void *opaque) {
    struct scope_thread_context *context=opaque;
    context->valid=!envara_gui_validation_scope_current() && envara_gui_validation_scope_begin() && !envara_gui_manifest_unchanged(context->manifest);
    envara_gui_validation_scope_end();context->valid=context->valid && !envara_gui_validation_scope_current();return NULL;
}
static int validation_scope_test(const char *bundle) {
    struct envara_gui_manifest manifest;
    if(envara_gui_manifest_inspect(bundle,1,&manifest)) return 115;
    uint64_t generation=envara_gui_validation_scope_begin();
    if(!generation || envara_gui_manifest_unchanged(&manifest) || envara_gui_manifest_unchanged(&manifest)) return 116;
    if(envara_gui_validation_scope_begin()!=generation) return 117;
    struct envara_gui_manifest forged=manifest;strcpy(forged.identifier,"org.envara.forged");
    if(!envara_gui_manifest_unchanged(&forged)) return 118;
    envara_gui_validation_scope_end();if(envara_gui_validation_scope_current()!=generation) return 119;
    struct scope_thread_context thread_context={.manifest=&manifest};pthread_t thread;
    if(pthread_create(&thread,NULL,scope_thread,&thread_context) || pthread_join(thread,NULL) || !thread_context.valid) return 120;
    pid_t child=fork();if(child<0) return 121;
    if(!child) {int okay=!envara_gui_validation_scope_current() && envara_gui_validation_scope_begin() && !envara_gui_manifest_unchanged(&manifest);envara_gui_validation_scope_end();_exit(okay?0:1);}
    int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)) return 122;
    char marker[PATH_MAX];if(snprintf(marker,sizeof(marker),"%s/Contents/Resources/scope-marker",bundle)>=(int)sizeof(marker)) return 123;
    int fd=open(marker,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);struct stat info;
    if(fd<0 || fstat(fd,&info) || !S_ISREG(info.st_mode) || info.st_uid!=getuid() || info.st_nlink!=1) {if(fd>=0)close(fd);return 124;}
    int wrote=ftruncate(fd,0)==0 && write(fd,"owned-change",12)==12;close(fd);
    if(!wrote || !envara_gui_manifest_unchanged(&manifest)) return 125;
    envara_gui_validation_scope_end();if(envara_gui_validation_scope_current() || !envara_gui_manifest_unchanged(&manifest)) return 126;
    if(envara_gui_manifest_inspect(bundle,1,&manifest)) return 127;
    uint64_t next=envara_gui_validation_scope_begin();
    int okay=next && next!=generation && !envara_gui_manifest_unchanged(&manifest);envara_gui_validation_scope_end();
    if(!okay) return 128;
    /* A later boundary re-proves identity without bytes. A same-size rewrite
     * whose modification and access times are put back still moves the
     * status-change time, so the witness must refuse it. */
    if(envara_gui_manifest_inspect(bundle,1,&manifest) || envara_gui_validation_witnessed(&manifest)) return 129;
    struct envara_gui_validation_counts before,after;envara_gui_validation_counts(&before);
    if(!envara_gui_validation_scope_begin() || envara_gui_manifest_unchanged(&manifest) || !envara_gui_validation_witnessed(&manifest) ||
        envara_gui_manifest_unchanged(&manifest)) return 130;
    envara_gui_validation_counts(&after);
    int counted=after.full_inspections==before.full_inspections+1 && after.identity_checks==before.identity_checks+1;
    struct stat original;fd=open(marker,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0 || fstat(fd,&original) || original.st_size!=12) {if(fd>=0)close(fd);return 131;}
    struct timespec times[2]={original.st_atimespec,original.st_mtimespec};
    struct timespec pause={0,20000000};nanosleep(&pause,NULL);
    wrote=pwrite(fd,"OWNED-CHANGE",12,0)==12 && !futimens(fd,times);struct stat restored;
    wrote=wrote && !fstat(fd,&restored) && restored.st_size==original.st_size &&
        restored.st_mtimespec.tv_sec==original.st_mtimespec.tv_sec && restored.st_mtimespec.tv_nsec==original.st_mtimespec.tv_nsec;close(fd);
    if(!wrote) return 132;
    int ctime_refused=envara_gui_manifest_unchanged(&manifest)==-1 && errno==ESTALE;
    envara_gui_validation_scope_end();
    if(!ctime_refused || envara_gui_validation_witnessed(&manifest) || !envara_gui_manifest_unchanged(&manifest)) return 133;
    if(!counted) return 134;
    puts("{\"ok\":true,\"nestedScopesVerified\":true,\"forgedManifestRefused\":true,\"threadIsolationVerified\":true,\"forkIsolationVerified\":true,\"mutationRefused\":true,\"scopeCleared\":true,"
        "\"identityReproofCounted\":true,\"restoredTimesMutationRefused\":true,\"witnessEndsWithScope\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false}");return 0;
}
/* Diagnostic step frames: bounded, whole lines, PID-bound, never blocking. */
static int step_frames_test(void) {
    const char *run="11111111-2222-4333-8444-555555555555",*environment="66666666-7777-4888-9999-aaaaaaaaaaaa";
    const char *schema="envara.macos-pf-app-transport/v1";int pair[2];if(pipe(pair)) return 140;
    envara_gui_step(ENVARA_GUI_STEP_FRONT_COMMIT);
    if(!envara_gui_steps_begin(pair[1],"Bad Schema",run,environment) || !envara_gui_steps_begin(pair[1],schema,"not-a-uuid",environment) ||
        !envara_gui_steps_begin(-1,schema,run,environment)) return 141;
    if(envara_gui_steps_begin(pair[1],schema,run,environment)) return 142;
    envara_gui_step(ENVARA_GUI_STEP_FRONT_COMMIT);envara_gui_step((enum envara_gui_step)99);
    pid_t child=fork();if(child<0) return 143;
    if(!child){envara_gui_step(ENVARA_GUI_STEP_RELAY_FORK);_exit(0);}
    int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)) return 144;
    for(int i=0;i<20;i++) envara_gui_step(ENVARA_GUI_STEP_TICKET_PREPARE);
    envara_gui_steps_end();envara_gui_step(ENVARA_GUI_STEP_STAGE_ADOPT);
    /* A full output drops the frame at once instead of writing part of it. */
    int full[2];if(pipe(full)) return 145;int flags=fcntl(full[1],F_GETFL);if(flags<0 || fcntl(full[1],F_SETFL,flags|O_NONBLOCK)) return 146;
    char filler[4096];memset(filler,'x',sizeof(filler));size_t filled=0;
    for(;;){ssize_t n=write(full[1],filler,sizeof(filler));if(n>0){filled+=(size_t)n;continue;}if(n<0&&errno==EAGAIN){n=write(full[1],filler,1);if(n==1){filled++;continue;}}break;}
    if(envara_gui_steps_begin(full[1],schema,run,environment)) return 147;
    struct timespec started,ended;clock_gettime(CLOCK_MONOTONIC,&started);envara_gui_step(ENVARA_GUI_STEP_STAGE_SPAWN);clock_gettime(CLOCK_MONOTONIC,&ended);
    envara_gui_steps_end();close(full[1]);
    double elapsed=(ended.tv_sec-started.tv_sec)*1000.0+(ended.tv_nsec-started.tv_nsec)/1e6;size_t drained=0;int partial=0;
    for(;;){ssize_t n=read(full[0],filler,sizeof(filler));if(n<=0)break;drained+=(size_t)n;if(memchr(filler,'{',(size_t)n)) partial=1;}
    close(full[0]);
    if(drained!=filled || partial || elapsed>200) return 148;
    close(pair[1]);char output[16384];size_t used=0;
    for(;;){ssize_t n=read(pair[0],output+used,sizeof(output)-1-used);if(n<=0)break;used+=(size_t)n;if(used>=sizeof(output)-1) return 149;}
    close(pair[0]);output[used]=0;fputs(output,stdout);return 0;
}
int main(int argc, char **argv) {
    if (!getuid() || geteuid() != getuid() || getgid() != getegid() || argc < 2) return 99;
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "profile")) { puts(envara_notion_dns_profile()); return 0; }
        if (argc == 3 && !strcmp(argv[1], "metadata")) return metadata(argv[2]);
        if (argc == 3 && !strcmp(argv[1], "validation-scope")) return validation_scope_test(argv[2]);
        if (argc == 2 && !strcmp(argv[1], "step-frames")) return step_frames_test();
        if (argc == 5 && !strcmp(argv[1], "context")) return context_plan(argv[2],argv[3],argv[4]);
        if ((argc == 3 || argc == 4) && !strcmp(argv[1], "scoped-profile")) {
            char profile[PATH_MAX]; int p = atoi(argv[2]);
            if (p < 1024 || p > 65535 || envara_notion_scoped_profile((uint16_t)p, argc == 4 ? argv[3] : NULL, profile, sizeof(profile))) return 106;
            puts(profile); return 0;
        }
        if (argc == 6 && !strcmp(argv[1], "inet-probe") && (!strcmp(argv[4], "tcp") || !strcmp(argv[4], "udp")) &&
            (!strcmp(argv[5], "direct") || !strcmp(argv[5], "inherit"))) return inet_probe(argv[2], argv[3], !strcmp(argv[4], "udp"), !strcmp(argv[5], "inherit"));
        if (argc == 4 && !strcmp(argv[1], "refusal")) return refusal(argv[2], argv[3]);
        if (argc == 3 && !strcmp(argv[1], "supported")) return supported(argv[2]);
        if (argc == 4 && !strcmp(argv[1], "socket-probe") && (!strcmp(argv[3], "direct") || !strcmp(argv[3], "inherit")))
            return socket_probe(argv[2], !strcmp(argv[3], "inherit"));
    }
    return 100;
}
