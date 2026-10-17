/* Nonroot, owned-process fixture for the actual relay retirement/pipe handoff.
 * Only fixed factory/kernel predicates are private compile-time seams. */
#include "app-native-factory.h"
#include "app-scope-proof.h"
#include <assert.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int scope_allowed, wait_behavior;
static pid_t owned_relay;
static int fixture_scope(gid_t gid) {(void)gid;return scope_allowed;}
static int fixture_deny(envara_app_native_factory *factory) {(void)factory;return 1;}
static int fixture_binding(envara_app_native_factory *factory) {(void)factory;return 1;}
static int fixture_matches(const struct envara_identity *identity,uid_t uid,gid_t gid) {
    if(!uid&&!gid&&identity->pid==getpid())return identity->uid==getuid()&&identity->gid==getgid();
    return envara_identity_matches(identity,uid,gid);
}
static pid_t fixture_waitpid(pid_t pid,int *status,int options) {
    assert(pid>1);
    if(pid==owned_relay&&wait_behavior==1){assert(waitpid(pid,status,options)==0);return 0;}
    if(pid==owned_relay&&wait_behavior==2){errno=ECHILD;return -1;}
    if(pid==owned_relay&&wait_behavior==3)return pid+1;
    if(pid==owned_relay&&wait_behavior==4){errno=EIO;return -1;}
    return waitpid(pid,status,options);
}
#define envara_app_scope_gid_absent fixture_scope
#define envara_app_native_factory_cleanup_deny fixture_deny
#define envara_app_native_factory_cleanup_binding fixture_binding
#define envara_identity_matches fixture_matches
#define waitpid fixture_waitpid
#include "app-transport.c"
#undef envara_app_scope_gid_absent
#undef envara_app_native_factory_cleanup_deny
#undef envara_app_native_factory_cleanup_binding
#undef envara_identity_matches
#undef waitpid

static const char *test_id="01234567-89ab-4cde-8fab-0123456789ab";
static void receive_frame(int fd,int log,const char *event,unsigned attempt) {
    char frame[2048];size_t length=0;
    while(length<sizeof(frame)-1){struct pollfd p={fd,POLLIN,0};assert(poll(&p,1,3000)==1);assert(read(fd,frame+length,1)==1);
        if(frame[length++]=='\n')break;}
    frame[length]=0;assert(strstr(frame,event));
    if(attempt){char expected[64];snprintf(expected,sizeof(expected),"\"cleanupAttempt\":%u",attempt);assert(strstr(frame,expected));}
    assert(write(log,frame,length)==(ssize_t)length);
}
static void next_command(pid_t relay,int lease,int recovery,unsigned *drained,char out[40]) {
    uint64_t end=milliseconds()+3000;
    for(;;){int got=preparation_command(relay,lease,recovery,drained,out);assert(got>=0);if(got==1)return;assert(milliseconds()<end);}
}
int main(int argc,char **argv) {
    assert(argc==2&&getuid()!=0&&getuid()==geteuid());
    int log=dup(1),saved_input=dup(0),frames[2],front_pipe[2],control[2],lease[2],recovery[2],main_input[2];
    assert(log>=3&&saved_input>=3&&!pipe(frames)&&!pipe(front_pipe)&&!pipe(control)&&!pipe(lease)&&!pipe(recovery)&&!pipe(main_input));
    assert(dup2(frames[1],1)==1);close(frames[1]);assert(dup2(main_input[0],0)==0);close(main_input[0]);
    pid_t front=fork();assert(front>=0);
    if(!front){
        int held[]={front_pipe[0]};assert(!envara_launch_guard_isolate_descriptors(held,1));
        char c;while(read(front_pipe[0],&c,1)>0){} _exit(0);
    }
    close(front_pipe[0]);struct envara_identity front_identity;assert(!envara_identity_read(front,&front_identity));
    int front_reaped=0;
    struct frontend_stop_context frontend={.owner=getpid(),.input=&front_pipe[1],.reaped=&front_reaped,.frontend=&front_identity};
    assert(!fstat(front_pipe[1],&frontend.writer));
    pid_t relay=fork();assert(relay>=0);
    if(!relay){
        assert(dup2(control[0],0)==0);int held[]={lease[1],recovery[1]};assert(!envara_launch_guard_isolate_descriptors(held,2));
        struct sigaction action={0};action.sa_handler=stop_signal;sigemptyset(&action.sa_mask);assert(!sigaction(SIGTERM,&action,NULL));stopped=0;
        (void)envara_app_transport_relay(0,lease[1],recovery[1],getppid());_exit(0);
    }
    owned_relay=relay;close(control[0]);close(lease[1]);close(recovery[1]);
    assert(write(control[1],"S\n",2)==2);struct pollfd readable={lease[0],POLLIN,0};assert(poll(&readable,1,3000)==1);
    char c;assert(read(lease[0],&c,1)==1&&c=='S'); /* Supervisor consumed S1. */
    struct envara_app_native_preflight plan={0};strcpy(plan.run_id,test_id);strcpy(plan.environment_id,test_id);plan.realm_gid=7100;
    struct envara_app_preparation_report preparation={0};
    strcpy(preparation.ticket_id,test_id);strcpy(preparation.registration_id,test_id);strcpy(preparation.version_id,test_id);
    strcpy(preparation.environment_id,test_id);strcpy(preparation.run_id,test_id);strcpy(preparation.snapshot.slot_id,test_id);
    preparation.snapshot.generation=1;preparation.snapshot.child_state=ENVARA_APP_KEYCHAIN_REAPED;preparation.cleanup_attempt=1;
    assert(!envara_identity_read(getpid(),&preparation.keeper));
    int held_unknown=!strncmp(argv[1],"relay-",6),wait_unknown=0;
    wait_behavior=!strcmp(argv[1],"relay-echild")?2:!strcmp(argv[1],"relay-other-pid")?3:!strcmp(argv[1],"relay-wait-error")?4:1;
    assert(!preparation_relay_retire(&relay,0,&wait_unknown)&&relay==owned_relay);
    assert(wait_unknown==held_unknown);wait_behavior=0;
    assert(!preparation_handoff_stop(&plan,(envara_app_native_factory *)1,&frontend,relay,&preparation));
    receive_frame(frames[0],log,"cleanup-pending",1);assert(front_reaped);
    /* The retry is already inside the relay pipe when exact reap succeeds. */
    assert(write(control[1],"S\n",2)==2);close(control[1]);assert(poll(&readable,1,3000)==1);
    if(held_unknown){
        siginfo_t info={0};assert(!waitid(P_PID,(id_t)owned_relay,&info,WEXITED|WNOWAIT));assert(info.si_pid==owned_relay);
        assert(!preparation_relay_retire(&relay,0,&wait_unknown)&&relay==owned_relay&&wait_unknown);
        unsigned drained=0;char command[40];next_command(relay,lease[0],recovery[0],&drained,command);assert(!strcmp(command,"S"));
        preparation.cleanup_attempt++;scope_allowed=1;
        assert(!preparation_handoff_stop(&plan,(envara_app_native_factory *)1,&frontend,relay,&preparation));
        receive_frame(frames[0],log,"cleanup-pending",2);
        int status;assert(waitpid(owned_relay,&status,0)==owned_relay&&WIFEXITED(status)); /* Fixture teardown only. */
        assert(dup2(log,1)==1&&dup2(saved_input,0)==0);close(log);close(saved_input);
        close(frames[0]);close(lease[0]);close(recovery[0]);close(main_input[1]);
        printf("{\"ok\":true,\"mode\":\"%s\",\"waitUnknownHeld\":true,\"ready\":false,\"protected\":false}\n",argv[1]);return 0;
    }
    uint64_t deadline=milliseconds()+3000;
    while(!preparation_relay_retire(&relay,0,&wait_unknown)){assert(milliseconds()<deadline);usleep(1000);}
    assert(relay==-1);int status;errno=0;assert(waitpid(owned_relay,&status,WNOHANG)==-1&&errno==ECHILD);
    unsigned drained=0;char command[40];next_command(relay,lease[0],recovery[0],&drained,command);assert(!strcmp(command,"S"));
    preparation.cleanup_attempt++;scope_allowed=strcmp(argv[1],"scope-retry")!=0;
    int confirmed=preparation_handoff_stop(&plan,(envara_app_native_factory *)1,&frontend,relay,&preparation);
    if(!scope_allowed){
        assert(!confirmed);receive_frame(frames[0],log,"cleanup-pending",2);
        assert(write(main_input[1],"S\n",2)==2);next_command(relay,lease[0],recovery[0],&drained,command);assert(!strcmp(command,"S")&&drained==3);
        preparation.cleanup_attempt++;scope_allowed=1;confirmed=preparation_handoff_stop(&plan,(envara_app_native_factory *)1,&frontend,relay,&preparation);
    }
    assert(confirmed);receive_frame(frames[0],log,"transport-cleanup-stopping",0);
    assert(write(main_input[1],"R\n",2)==2);next_command(relay,lease[0],recovery[0],&drained,command);assert(!strcmp(command,"R")&&drained==3);
    /* A consumed R still needs the original production release gates. */
    assert(envara_app_native_factory_release_safe(NULL)==0);
    assert(dup2(log,1)==1&&dup2(saved_input,0)==0);close(log);close(saved_input);
    close(frames[0]);close(lease[0]);close(recovery[0]);close(main_input[1]);
    printf("{\"ok\":true,\"mode\":\"%s\",\"bufferedRetryDelivered\":true,\"relayExactlyReaped\":true,\"immediateRDelivered\":true,\"ready\":false,\"protected\":false}\n",argv[1]);
    return 0;
}
