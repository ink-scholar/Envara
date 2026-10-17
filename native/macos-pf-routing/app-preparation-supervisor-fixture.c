/* Private source-including, nonroot protocol fixture. The opaque module is
 * replaced only at compile time; its own native fixture proves actual waits.
 * These synthetic callbacks are not PF, application, or release evidence. */
#include "app-supervisor.h"
#include <assert.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct fixture_state { volatile int revoke_allowed, revoked, clear_allowed, invalid, changed, cleanups, revokes; };
static struct fixture_state *state;
static int child_state;
static const char *id = "01234567-89ab-4cde-8fab-0123456789ab";
static int fixture_pending(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run) {
    (void)slot;(void)app;(void)request;(void)run;return 1;
}
static int fixture_snapshot(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run,struct envara_app_keychain_snapshot *out) {
    (void)slot;(void)app;(void)request;(void)run;
    if(state->invalid)return -1;
    memset(out,0,sizeof(*out));strcpy(out->slot_id,id);out->generation=state->changed?2:1;
    out->child_state=child_state;out->pending=1;return 0;
}
static int fixture_cleanup(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run) {
    (void)slot;(void)app;(void)request;(void)run;
    assert(state->revoked);state->cleanups++;
    if(state->invalid)return -1;
    return child_state==ENVARA_APP_KEYCHAIN_UNKNOWN?0:state->clear_allowed;
}
#define envara_app_keychain_custody_pending fixture_pending
#define envara_app_keychain_custody_snapshot fixture_snapshot
#define envara_app_keychain_custody_cleanup fixture_cleanup
#include "app-supervisor.c"
#undef envara_app_keychain_custody_pending
#undef envara_app_keychain_custody_snapshot
#undef envara_app_keychain_custody_cleanup

static int fixture_revoke(void *unused) {
    (void)unused;state->revokes++;state->revoked=state->revoke_allowed;return state->revoked;
}
static int fixture_deny(void *unused) {(void)unused;return state->revoked;}
static int fixture_scope(void *unused) {(void)unused;return state->clear_allowed;}
static void send_byte(int fd,char c) {assert(write(fd,&c,1)==1);}
static void receive(int fd,char out[2048]) {
    size_t count=0;
    while(count<2047){struct pollfd p={fd,POLLIN,0};assert(poll(&p,1,3000)==1);char c;assert(read(fd,&c,1)==1);
        out[count++]=c;if(c=='\n'){out[count]=0;fputs(out,stdout);return;}}
    assert(!"oversized frame");
}
static void pending_frame(int fd,const char *command,unsigned attempt) {
    char frame[2048],expected[80];receive(fd,frame);
    assert(strstr(frame,"\"schema\":\"envara.pf-app-preparation/v1\""));
    snprintf(expected,sizeof(expected),"\"command\":\"%s\",\"cleanupAttempt\":%u",command,attempt);assert(strstr(frame,expected));
    assert(!strstr(frame,"stoppedIdentity")&&!strstr(frame,"\"pid\"")&&!strstr(frame,"armed")&&!strstr(frame,"childReaped"));
}
int main(int argc,char **argv) {
    assert(argc==2&&getuid()!=0&&getuid()==geteuid());
    state=mmap(NULL,sizeof(*state),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);assert(state!=MAP_FAILED);
    memset(state,0,sizeof(*state));state->revoke_allowed=strcmp(argv[1],"revoke-refused")!=0;
    child_state=!strcmp(argv[1],"launcher-clear")?ENVARA_APP_KEYCHAIN_LAUNCHER_CLEAR:
        !strcmp(argv[1],"unknown")?ENVARA_APP_KEYCHAIN_UNKNOWN:ENVARA_APP_KEYCHAIN_REAPED;
    int lease[2],recovery[2],output[2],held[2];assert(!pipe(lease)&&!pipe(recovery)&&!pipe(output)&&!socketpair(AF_UNIX,SOCK_STREAM,0,held));
    pid_t worker=fork();assert(worker>=0);
    if(!worker){
        close(lease[1]);close(recovery[1]);close(output[0]);close(held[1]);
        assert(!fcntl(output[1],F_SETFL,O_NONBLOCK));signal(SIGTERM,quarantined);signal(SIGINT,quarantined);signal(SIGHUP,quarantined);signal(SIGPIPE,SIG_IGN);
        struct envara_app_supervisor_provider provider={.preparation=(envara_app_keychain_custody *)state};
        struct envara_app_supervisor_report report={0};envara_gui_lifecycle_init(&report.child);
        struct keeper k={.provider=&provider,.report=&report,.output=output[1],.prepared=1};
        k.guard.lease_fd=lease[0];k.guard.recovery_fd=recovery[0];k.guard.retained_fd=held[0];
        k.authority.revoke_owned_network=fixture_revoke;k.authority.verify_persistent_deny=fixture_deny;k.authority.verify_scope_quiescent=fixture_scope;
        strcpy(k.ticket.ticket_id,id);strcpy(k.ticket.app.registration_id,id);strcpy(k.ticket.app.version_id,id);
        strcpy(k.ticket.environment_id,id);strcpy(k.ticket.run_id,id);assert(!envara_identity_read(getpid(),&k.own));
        int result=preparation_quarantine(&k,EPERM),saved=errno;
        assert(result==-1&&saved==EPERM&&report.preparation.original_error==EPERM&&report.preparation_refusal_emitted);
        assert(report.preparation_cleanup_confirmed&&!report.armed&&!report.released&&!report.guardian.child_reaped&&report.child.phase==ENVARA_GUI_EMPTY);
        assert(report.preparation.cleanup_attempt==2&&fcntl(held[0],F_GETFD)>=0);
        assert(write(output[1],"{\"fixtureReturned\":true}\n",25)==25);_exit(0);
    }
    close(lease[0]);close(recovery[0]);close(output[1]);close(held[0]);
    char frame[2048];receive(output[0],frame);assert(strstr(frame,"transport-refused")&&strstr(frame,"NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED")&&strstr(frame,"\"error\":1"));
    int immediate=!strcmp(argv[1],"immediate-stop");
    if(immediate)send_byte(lease[1],'S');
    pending_frame(output[0],"automatic",0);
    int status;assert(waitpid(worker,&status,WNOHANG)==0);
    if(immediate){pending_frame(output[0],"S",1);assert(state->cleanups==1);}
    else{
        assert(state->cleanups==0); /* Automatic diagnostics never run scope cleanup. */
        send_byte(lease[1],'K');send_byte(lease[1],'B');send_byte(recovery[1],'R');pending_frame(output[0],"R",0);
        send_byte(lease[1],'S');pending_frame(output[0],"S",1);
    }
    if(!strcmp(argv[1],"revoke-refused")){assert(state->cleanups==0);state->revoke_allowed=1;}
    int hold=!strcmp(argv[1],"unknown")||!strcmp(argv[1],"binding-invalid")||!strcmp(argv[1],"snapshot-changed");
    if(!strcmp(argv[1],"binding-invalid"))state->invalid=1;
    if(!strcmp(argv[1],"snapshot-changed"))state->changed=1;
    state->clear_allowed=1;
    send_byte(lease[1],'S');
    if(hold){
        pending_frame(output[0],"S",2);assert(waitpid(worker,&status,WNOHANG)==0);
        assert(!kill(worker,SIGTERM));close(lease[1]);lease[1]=-1;
        send_byte(recovery[1],'R');pending_frame(output[0],"R",2);assert(waitpid(worker,&status,WNOHANG)==0);
        struct envara_identity own;assert(!envara_identity_read(worker,&own)&&own.parent_pid==getpid()&&own.uid==getuid());
        assert(!kill(worker,SIGKILL));assert(waitpid(worker,&status,0)==worker&&WIFSIGNALED(status));
    }else{
        receive(output[0],frame);assert(strstr(frame,"fixtureReturned"));assert(waitpid(worker,&status,0)==worker&&WIFEXITED(status)&&!WEXITSTATUS(status));
    }
    if(lease[1]>=0)close(lease[1]);close(recovery[1]);close(output[0]);close(held[1]);
    printf("{\"ok\":true,\"mode\":\"%s\",\"held\":%s,\"ready\":false,\"protected\":false}\n",argv[1],hold?"true":"false");
    return 0;
}
