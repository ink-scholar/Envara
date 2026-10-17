/* Compile the production transport in this test translation unit, so the
 * inert fixture exercises its private proof builder without a public bypass. */
#include "app-transport.c"
#include "transport-session.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Self-owned nonroot only. No production factory is invoked, utun created,
 * registry written, app executed or PF inspected. */
static int listener(void) {
    struct envara_app_listener held;
    if (envara_app_listener_open(&held) || envara_app_listener_verify(&held)) { fprintf(stderr,"listener errno=%d fd=%d port=%u owner=%d self=%d\n",errno,held.fd,held.port,held.owner,getpid()); return 10; }
    int copy = dup(held.fd); if (copy < 0) return 11;
    pid_t child = fork(); if (child < 0) return 12;
    if (!child) { close(held.fd); close(copy); _exit(0); }
    close(copy); int status; if (waitpid(child, &status, 0) != child || status || envara_app_listener_verify(&held)) return 13;
    int other = socket(AF_INET, SOCK_STREAM, 0); if (other < 0) return 14;
    struct sockaddr_in a = {.sin_len=sizeof(a),.sin_family=AF_INET,.sin_port=htons(held.port),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    int pinned = bind(other, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EADDRINUSE; close(other);
    int flags = fcntl(held.fd, F_GETFD); if (fcntl(held.fd, F_SETFD, flags & ~FD_CLOEXEC)) return 15;
    int unsealed_refused = envara_app_listener_verify(&held) == -1;
    if (fcntl(held.fd, F_SETFD, flags)) return 16;
    int reuse = 1;
    if (setsockopt(held.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) return 17;
    int reuse_refused = envara_app_listener_verify(&held) == -1; reuse = 0;
    if (setsockopt(held.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) || envara_app_listener_close(&held)) return 18;
    int okay = pinned && unsealed_refused && reuse_refused;
    printf("{\"ok\":%s,\"heldAfterFrontExit\":%s,\"unsealedRefused\":%s,\"reuseRefused\":%s,\"ready\":false,\"protected\":false}\n",
        okay?"true":"false",pinned?"true":"false",unsealed_refused?"true":"false",reuse_refused?"true":"false"); return okay?0:19;
}
static int frontend_stop_fixture(void) {
    int channel[2], stream[2]; if (pipe_private(channel) || socketpair(AF_UNIX, SOCK_STREAM, 0, stream)) return 101;
    pid_t child = fork(); if (child < 0) return 102;
    if (!child) { close(channel[1]); close(stream[1]); char byte; while (read(channel[0], &byte, 1) > 0) {} close(stream[0]); _exit(0); }
    close(channel[0]); close(stream[0]); struct envara_identity front;
    if (envara_identity_read(child, &front)) return 103;
    int writer = channel[1], original = writer, reaped = 0;
    struct frontend_stop_context context = {.owner = getpid(), .input = &writer, .reaped = &reaped, .frontend = &front};
    if (fstat(writer, &context.writer) || stop_owned_frontend(&context) != 1 || writer != -1 || !reaped) return 104;
    errno = 0; int closed = fcntl(original, F_GETFD) == -1 && errno == EBADF;
    struct pollfd item = {stream[1], POLLIN | POLLHUP, 0}; char byte;
    int stream_closed = poll(&item, 1, 1000) > 0 && read(stream[1], &byte, 1) == 0; close(stream[1]);
    int replacement = open("/dev/null", O_RDONLY); if (replacement < 0) return 105;
    if (replacement != original) { if (dup2(replacement, original) < 0) return 106; close(replacement); replacement = original; }
    int repeat = stop_owned_frontend(&context) == 1 && fcntl(replacement, F_GETFD) >= 0; close(replacement);
    int ok = closed && stream_closed && repeat;
    printf("{\"ok\":%s,\"originalWriterClosed\":%s,\"actualFrontendReaped\":%s,\"actualStreamClosed\":%s,\"repeatPreservesReusedFD\":%s,\"root\":false,\"pf\":false,\"ready\":false,\"protected\":false}\n",
        ok?"true":"false",closed?"true":"false",reaped?"true":"false",stream_closed?"true":"false",repeat?"true":"false"); return ok?0:107;
}
static int relay(int malformed) {
    int input[2], lease[2], recovery[2]; if (pipe(input) || pipe(lease) || pipe(recovery)) return 20;
    pid_t parent = getpid(), child = fork(); if (child < 0) return 21;
    if (!child) {
        close(input[1]); close(lease[0]); close(recovery[0]);
        int result = envara_app_transport_relay(input[0], lease[1], recovery[1], parent);
        close(input[0]); _exit(result == -1 ? 0 : 22);
    }
    close(input[0]); close(lease[1]); close(recovery[1]);
    const char *command = malformed ? "X\nR\n" : "K\nB\nS\nR\n";
    if (write(input[1], command, strlen(command)) != (ssize_t)strlen(command)) return 23; close(input[1]);
    char l[8]={0},r[8]={0}; size_t ln=0,rn=0; ssize_t n;
    while ((n=read(lease[0],l+ln,sizeof(l)-ln))>0) ln+=(size_t)n;
    while ((n=read(recovery[0],r+rn,sizeof(r)-rn))>0) rn+=(size_t)n;
    close(lease[0]); close(recovery[0]); int status;
    if (waitpid(child,&status,0)!=child || status) return 24;
    int okay = malformed ? !ln&&!rn : ln==3&&!memcmp(l,"KBS",3)&&rn==1&&r[0]=='R';
    printf("{\"ok\":%s,\"malformedBurnsBothPipes\":%s,\"protocolTranslation\":%s,\"ready\":false,\"protected\":false}\n",
        okay?"true":"false",malformed&&okay?"true":"false",!malformed&&okay?"true":"false"); return okay?0:25;
}
static int refused(void) {
    struct envara_transport_session session; envara_transport_session_init(&session);
    int start = envara_transport_session_start("/bin/false", "/private/tmp", "198.18.1.1", "{}", &session);
    int root_refused = start == -1 && errno == EACCES && session.original_utun_fd == -1 && session.state_fd == -1 && session.core.pid == 0;
    char *argv[] = {"fixture","app-tunnel-bootstrap","00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002",NULL};
    int command = envara_app_transport_command(4,argv), error=errno;
    int okay = root_refused && command == -1 && error == EACCES;
    printf("{\"ok\":%s,\"nonrootRefusedBeforeNetworking\":%s,\"ready\":false,\"protected\":false}\n",okay?"true":"false",root_refused?"true":"false"); return okay?0:26;
}
static int cold_fds(const char *self) {
    struct rlimit original, raised, lowered; int sockets[2], high = -1, okay = 0;
    if (getrlimit(RLIMIT_NOFILE,&original) || original.rlim_max < 1024 || socketpair(AF_UNIX,SOCK_STREAM,0,sockets)) return 40;
    raised=original; if (raised.rlim_cur<1024) raised.rlim_cur=1024;
    if (setrlimit(RLIMIT_NOFILE,&raised)) return 41;
    high=fcntl(sockets[0],F_DUPFD_CLOEXEC,512); if (high<512) return 42;
    lowered=raised;lowered.rlim_cur=64;if (setrlimit(RLIMIT_NOFILE,&lowered)) return 43;
    char executable[PATH_MAX],cwd[PATH_MAX]; if (!realpath(self,executable)) return 44;
    strcpy(cwd,executable);char *slash=strrchr(cwd,'/');if(!slash)return 45;*slash=0;
    struct envara_child child; char *args[]={executable,NULL}; char *env[]={"PATH=/usr/bin:/bin",NULL};
    if (!envara_spawn_suspended(getuid(),getgid(),cwd,executable,args,env,1,&child)) {
        struct proc_fdinfo entries[128]; int bytes=proc_pidinfo(child.identity.pid,PROC_PIDLISTFDS,0,entries,sizeof(entries));
        int extras=0,pipes=0;
        if (bytes>0&&bytes<(int)sizeof(entries)&&bytes%(int)sizeof(*entries)==0) {
            for(int i=0;i<bytes/(int)sizeof(*entries);i++)if(entries[i].proc_fd>=3){
                extras++;if(entries[i].proc_fdtype==PROX_FDTYPE_PIPE)pipes++;
            }
            okay=extras==1&&pipes==1&&envara_same_process(&child.identity);
        }
        int status; if(envara_child_cancel(&child)||waitpid(child.identity.pid,&status,0)!=child.identity.pid)okay=0;
        close(child.error_fd);
    }
    close(high);close(sockets[0]);close(sockets[1]);if(setrlimit(RLIMIT_NOFILE,&original))return 46;
    printf("{\"ok\":%s,\"stoppedChildHasOnlyErrorPipe\":%s,\"highFDAboveLoweredLimitClosed\":%s,\"ready\":false,\"protected\":false}\n",okay?"true":"false",okay?"true":"false",okay?"true":"false"); return okay?0:47;
}
static int fixture_lease(int run_fd, const char *name) {
    int fd=openat(run_fd,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    const char bytes[]="{\"fixture\":\"owned-inert-lease\"}\n";
    if(fd<0)return -1;
    if(fchmod(fd,0600)||write(fd,bytes,sizeof(bytes)-1)!=(ssize_t)(sizeof(bytes)-1)){close(fd);return -1;}
    return fd;
}
static int fixture_child(struct envara_identity *identity) {
    int ack[2]; if(pipe(ack))return -1;
    pid_t pid=fork(); if(pid<0){close(ack[0]);close(ack[1]);return -1;}
    if(!pid){close(ack[0]);char byte='X';if(write(ack[1],&byte,1)!=1)_exit(70);close(ack[1]);for(;;)pause();}
    close(ack[1]);char byte=0;int okay=read(ack[0],&byte,1)==1&&byte=='X';close(ack[0]);
    if(!okay||envara_identity_read(pid,identity)||identity->parent_pid!=getpid()){
        kill(pid,SIGKILL);while(waitpid(pid,NULL,0)<0&&errno==EINTR){}return -1;
    }
    return 0;
}
static int abort_proofs(const char *self) {
    char directory[PATH_MAX],path[PATH_MAX],digest[65],frame[4096];
    if(!realpath(self,directory))return 50;char *slash=strrchr(directory,'/');if(!slash)return 51;*slash=0;
    if(snprintf(path,sizeof(path),"%s/abort-owned",directory)>=(int)sizeof(path)||mkdir(path,0700)||chmod(path,0700))return 52;
    int run_fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(run_fd<0)return 53;
    int lease_fd=fixture_lease(run_fd,"app-bound-lease.json");if(lease_fd<0||abort_digest(lease_fd,digest))return 54;
    struct abort_pin pin={.run_fd=-1,.lease_fd=-1};
    if(abort_pin_at(run_fd,path,digest,getuid(),&pin)||abort_pin_fresh(&pin)||!abort_journal_absent(&pin))return 55;
    struct stat initial_lease=pin.lease,initial_run=pin.run;
    int replacement=fixture_lease(run_fd,"replacement.json");if(replacement<0)return 56;close(replacement);
    if(renameat(run_fd,"replacement.json",run_fd,"app-bound-lease.json"))return 57;
    int replaced_lease_refused=abort_pin_fresh(&pin)==-1;abort_pin_close(&pin);close(lease_fd);
    if(abort_pin_at(run_fd,path,digest,getuid(),&pin)||abort_pin_fresh(&pin))return 58;
    lease_fd=openat(run_fd,"app-bound-lease.json",O_RDWR|O_NOFOLLOW|O_CLOEXEC);if(lease_fd<0||pwrite(lease_fd,"!",1,0)!=1)return 59;
    int content_refused=abort_pin_fresh(&pin)==-1;abort_pin_close(&pin);close(lease_fd);
    if(unlinkat(run_fd,"app-bound-lease.json",0)||(lease_fd=fixture_lease(run_fd,"app-bound-lease.json"))<0||
        abort_digest(lease_fd,digest)||abort_pin_at(run_fd,path,digest,getuid(),&pin))return 60;
    int journal=openat(run_fd,"app-filter-events",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(journal<0)return 61;close(journal);
    int journal_file_refused=!abort_journal_absent(&pin);
    if(unlinkat(run_fd,"app-filter-events",0)||mkdirat(run_fd,"app-filter-events",0700))return 62;
    int journal_directory_refused=!abort_journal_absent(&pin);
    if(unlinkat(run_fd,"app-filter-events",AT_REMOVEDIR)||symlinkat("missing-target",run_fd,"app-filter-events"))return 63;
    int journal_link_refused=!abort_journal_absent(&pin);
    if(unlinkat(run_fd,"app-filter-events",0))return 64;
    struct abort_pin bad_pin=pin;bad_pin.run_fd=-1;
    int journal_unknown_refused=!abort_journal_absent(&bad_pin);
    abort_pin_close(&pin);close(lease_fd);close(run_fd);
    struct envara_app_listener first={.fd=-1},second={.fd=-1};
    struct stat first_stat;struct socket_fdinfo first_socket;
    if(envara_app_listener_open(&first)||envara_app_listener_open(&second)||abort_socket_capture(first.fd,&first_stat,&first_socket)||
        !abort_socket_same(first.fd,&first_stat,&first_socket))return 65;
    if(dup2(second.fd,first.fd)!=first.fd||fcntl(first.fd,F_SETFD,FD_CLOEXEC))return 66;
    int changed_fd_refused=!abort_socket_same(first.fd,&first_stat,&first_socket);
    int close_verified=abort_close_original(first.fd)==0;
    int repeated_close_refused=abort_close_original(first.fd)==-1;
    first.fd=-1;if(envara_app_listener_close(&second))return 67;
    struct envara_identity core={0},front={0},keeper={0},parent={0};int core_reaped=0,front_reaped=0;
    if(fixture_child(&core)||fixture_child(&front)||envara_identity_read(getpid(),&keeper)||envara_identity_read(getppid(),&parent))return 68;
    struct envara_identity changed=core;changed.birth_microseconds=(changed.birth_microseconds+1)%1000000;
    int changed_birth_refused=exact_stop(&changed,&core_reaped)==-1&&!core_reaped&&envara_same_process(&core);
    changed=front;changed.parent_pid=1;
    int foreign_parent_refused=exact_stop(&changed,&front_reaped)==-1&&!front_reaped&&envara_same_process(&front);
    if(exact_stop(&core,&core_reaped)||exact_stop(&front,&front_reaped))return 69;
    int no_adopted_reap=0;int status=0;
    no_adopted_reap=waitpid(core.pid,&status,WNOHANG)==-1&&errno==ECHILD;
    /* Only serialization facts below are supplied by the fixture. It cannot
     * verify root GID absence or create an utun; both remain real root gates. */
    struct abort_proof proof={0};
    strcpy(proof.plan.run_id,"00000000-0000-4000-8000-000000000001");
    strcpy(proof.plan.environment_id,"00000000-0000-4000-8000-000000000002");
    strcpy(proof.plan.realm_id,"00000000-0000-4000-8000-000000000003");strcpy(proof.plan.lease_sha256,digest);
    proof.plan.realm_gid=7100;proof.plan.controller=parent;proof.keeper=keeper;proof.parent=parent;proof.core=core;proof.front=front;
    proof.lease=initial_lease;proof.run=initial_run;proof.utun=proof.listener=first_stat;strcpy(proof.utun_name,"utun0");
    proof.control_id=1;proof.control_unit=1;proof.port=first.port;proof.factory_failed=proof.captured=1;
    proof.core_reaped=core_reaped;proof.front_reaped=front_reaped;
    proof.scope_before=proof.scope_after=proof.journal_before=proof.journal_after=proof.utun_closed=proof.listener_closed=1;
    int baseline=abort_frame(&proof,frame,sizeof(frame));if(baseline<1)return 71;
    int *burns[]={&proof.deny_attempted,&proof.filter_attempted,&proof.launch_accepted,&proof.cold_attempted};
    int attempted_refused=1;for(size_t i=0;i<sizeof(burns)/sizeof(*burns);i++){*burns[i]=1;attempted_refused&=abort_frame(&proof,frame,sizeof(frame))==-1;*burns[i]=0;}
    int *facts[]={&proof.core_reaped,&proof.front_reaped,&proof.scope_before,&proof.scope_after,&proof.journal_before,&proof.journal_after,&proof.utun_closed,&proof.listener_closed};
    int incomplete_refused=1;for(size_t i=0;i<sizeof(facts)/sizeof(*facts);i++){
        *facts[i]=0;incomplete_refused&=abort_frame(&proof,frame,sizeof(frame))==-1;
        *facts[i]=2;incomplete_refused&=abort_frame(&proof,frame,sizeof(frame))==-1;*facts[i]=1;
    }
    uint64_t birth=proof.parent.birth_seconds;proof.parent.birth_seconds=0;
    int missing_parent_refused=abort_frame(&proof,frame,sizeof(frame))==-1;proof.parent.birth_seconds=birth;
    int nonroot_scope_refused=envara_app_scope_gid_absent(7100)!=1;
    if(abort_frame(&proof,frame,sizeof(frame))<1)return 72;
    int okay=replaced_lease_refused&&content_refused&&journal_file_refused&&journal_directory_refused&&journal_link_refused&&
        journal_unknown_refused&&changed_fd_refused&&close_verified&&repeated_close_refused&&changed_birth_refused&&foreign_parent_refused&&
        core_reaped&&front_reaped&&no_adopted_reap&&attempted_refused&&incomplete_refused&&missing_parent_refused&&nonroot_scope_refused;
    printf("{\"ok\":%s,\"builderOnly\":true,\"realRootAcceptance\":false,\"leaseReplacementRefused\":%s,\"leaseContentRefused\":%s,"
        "\"journalFileRefused\":%s,\"journalDirectoryRefused\":%s,\"journalSymlinkRefused\":%s,\"journalUnknownRefused\":%s,\"changedFDRefused\":%s,"
        "\"closeVerified\":%s,\"repeatedCloseRefused\":%s,\"changedBirthRefused\":%s,\"foreignParentRefused\":%s,\"directChildrenReaped\":%s,"
        "\"noAdoptedReap\":%s,\"writeOrLaunchAttemptRefused\":%s,\"incompleteFactsRefused\":%s,\"missingParentRefused\":%s,\"nonrootScopeRefused\":%s,"
        "\"ready\":false,\"protected\":false,\"frame\":%s}\n",okay?"true":"false",replaced_lease_refused?"true":"false",content_refused?"true":"false",
        journal_file_refused?"true":"false",journal_directory_refused?"true":"false",journal_link_refused?"true":"false",journal_unknown_refused?"true":"false",
        changed_fd_refused?"true":"false",close_verified?"true":"false",repeated_close_refused?"true":"false",changed_birth_refused?"true":"false",
        foreign_parent_refused?"true":"false",core_reaped&&front_reaped?"true":"false",no_adopted_reap?"true":"false",attempted_refused?"true":"false",
        incomplete_refused?"true":"false",missing_parent_refused?"true":"false",nonroot_scope_refused?"true":"false",frame);
    return okay?0:73;
}
static void fixture_listener_plan(struct envara_app_native_preflight *plan) {
    memset(plan,0,sizeof(*plan));strcpy(plan->run_id,"00000000-0000-4000-8000-000000000011");
    strcpy(plan->environment_id,"00000000-0000-4000-8000-000000000012");
    memset(plan->lease_sha256,'a',64);plan->lease_sha256[64]=0;
}
static int listener_protocol_child(const char *mode) {
    struct envara_app_native_preflight plan;fixture_listener_plan(&plan);
    struct listener_request request={0};struct envara_identity parent;
    if(listener_private_channel(3)||envara_identity_read(getppid(),&parent)||listener_receive(3,&request,sizeof(request),0,NULL,1000)||
        !listener_binding(&request,&plan,&parent))return 80;
    if(!strcmp(mode,"timeout")){poll(NULL,0,500);return 0;}
    struct envara_app_listener listener={.fd=-1};struct listener_response response={0};
    if(envara_app_listener_open(&listener)||envara_identity_read(getpid(),&response.creator))return 81;
    response.binding=request;response.port=listener.port;
    if(!strcmp(mode,"nonce"))response.binding.nonce[0]^=1;
    if(!strcmp(mode,"hash"))response.binding.lease_sha256[0]='b';
    if(!strcmp(mode,"birth"))response.creator.birth_microseconds=(response.creator.birth_microseconds+1)%1000000;
    int result;
    if(!strcmp(mode,"extra-fds")||!strcmp(mode,"many-fds")||!strcmp(mode,"truncated-data")){
        int rights[64];size_t count=!strcmp(mode,"extra-fds")?2:!strcmp(mode,"many-fds")?64:20;
        for(size_t i=0;i<count;i++)rights[i]=listener.fd;
        unsigned char control[CMSG_SPACE(sizeof(rights))]={0};char extra='X';struct iovec vectors[]={{&response,sizeof(response)},{&extra,1}};struct msghdr message={0};
        size_t length=sizeof(response)+(!strcmp(mode,"truncated-data")?1:0);
        message.msg_iov=vectors;message.msg_iovlen=!strcmp(mode,"truncated-data")?2:1;message.msg_control=control;message.msg_controllen=CMSG_SPACE(count*sizeof(int));
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(count*sizeof(int));
        memcpy(CMSG_DATA(c),rights,count*sizeof(int));result=sendmsg(3,&message,0)==(ssize_t)length?0:-1;
    }else if(!strcmp(mode,"short"))result=listener_send(3,&response,sizeof(response)-1,listener.fd);
    else result=listener_send(3,&response,sizeof(response),listener.fd);
    if(!result&&!strcmp(mode,"duplicate"))result=listener_send(3,&response,sizeof(response),listener.fd);
    close(listener.fd);close(3);if(result)return 82;return !strcmp(mode,"exit-error")?7:0;
}
static int fixture_fd_count(void) {
    struct proc_fdinfo entries[256];int bytes=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,entries,sizeof(entries));
    return bytes>0&&bytes<(int)sizeof(entries)&&bytes%(int)sizeof(*entries)==0?bytes/(int)sizeof(*entries):-1;
}
static int listener_protocol_case(const char *self,const char *mode,int *stopped_verified,int *before_out,int *after_out) {
    int pair[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)||fcntl(pair[0],F_SETFD,FD_CLOEXEC)||fcntl(pair[1],F_SETFD,FD_CLOEXEC))return 0;
    int copy=fcntl(pair[1],F_DUPFD_CLOEXEC,10);if(copy<0)return 0;
    posix_spawnattr_t attributes;posix_spawn_file_actions_t actions;pid_t pid;
    if(posix_spawnattr_init(&attributes)||posix_spawn_file_actions_init(&actions)||
        posix_spawnattr_setflags(&attributes,POSIX_SPAWN_START_SUSPENDED|POSIX_SPAWN_CLOEXEC_DEFAULT))return 0;
    for(int fd=0;fd<3;fd++)if(posix_spawn_file_actions_addopen(&actions,fd,"/dev/null",O_RDWR,0))return 0;
    if(posix_spawn_file_actions_adddup2(&actions,copy,3)||posix_spawn_file_actions_addinherit_np(&actions,3))return 0;
    char *args[]={(char *)self,"listener-protocol-child",(char *)mode,NULL};char *env[]={"PATH=/usr/bin:/bin",NULL};
    int result=posix_spawn(&pid,self,&actions,&attributes,args,env);
    posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attributes);close(copy);close(pair[1]);if(result){close(pair[0]);return 0;}
    struct envara_identity creator,parent;struct listener_request request={0};struct listener_response response={0};
    struct envara_app_native_preflight plan;fixture_listener_plan(&plan);
    if(envara_identity_read(pid,&creator)||creator.parent_pid!=getpid()||!listener_stopped(&creator)||envara_identity_read(getpid(),&parent)){
        listener_cancel(pid);close(pair[0]);return 0;
    }
    *stopped_verified=1;request.parent=parent;strcpy(request.run,plan.run_id);strcpy(request.environment,plan.environment_id);strcpy(request.lease_sha256,plan.lease_sha256);
    arc4random_buf(request.nonce,sizeof(request.nonce));
    int before=fixture_fd_count(),received=-1,okay=before>=0&&listener_private_channel(pair[0])==0&&listener_send(pair[0],&request,sizeof(request),-1)==0&&kill(pid,SIGCONT)==0;
    *before_out=before;
    int valid=okay&&listener_receive(pair[0],&response,sizeof(response),1,&received,!strcmp(mode,"timeout")?100:2000)==0;
    struct envara_app_listener held={.fd=received};
    if(valid)valid=listener_response_valid(&request,&response,&creator,getuid(),getgid(),&held)==0;
    int status=0;if(listener_reap(pid,milliseconds()+2000,&status)){listener_cancel(pid);okay=0;}else if(!WIFEXITED(status)||WEXITSTATUS(status)||!listener_queue_empty(pair[0]))valid=0;
    if(!strcmp(mode,"good")){
        okay=okay&&valid&&received>=3&&envara_same_process(&parent);
        held.credential_uid++;okay=okay&&envara_app_listener_verify(&held)==-1;held.credential_uid--;
        held.credential_gid++;okay=okay&&envara_app_listener_verify(&held)==-1;held.credential_gid--;
        okay=okay&&envara_app_listener_verify(&held)==0;
    }else okay=okay&&!valid;
    if(received>=0)close(received);
    int after=fixture_fd_count();*after_out=after;if(after!=before)fprintf(stderr,"listener protocol %s FDs before=%d after=%d\n",mode,before,after);
    okay=okay&&after>=0&&after==before;close(pair[0]);return okay;
}
static int listener_protocol(const char *self) {
    char executable[PATH_MAX];if(!realpath(self,executable))return 83;
    const char *modes[]={"good","nonce","hash","birth","extra-fds","many-fds","truncated-data","short","timeout","exit-error","duplicate"};
    int before[sizeof(modes)/sizeof(*modes)],after[sizeof(modes)/sizeof(*modes)];
    int okay=1,stopped_verified=0;
    for(size_t i=0;i<sizeof(modes)/sizeof(*modes);i++){
        before[i]=after[i]=-1;int success=listener_protocol_case(executable,modes[i],&stopped_verified,&before[i],&after[i]);
        if(!success)fprintf(stderr,"listener protocol case %s refused fixture errno=%d\n",modes[i],errno);okay&=success;
    }
    struct envara_app_native_preflight plan;fixture_listener_plan(&plan);plan.realm_gid=7100;
    struct envara_app_listener held={.fd=99};int nonroot_refused=envara_app_listener_open_for_plan(&plan,&held)==-1&&errno==EACCES&&held.fd==-1;
    char *args[]={executable,"app-listener-create",plan.run_id,plan.environment_id,NULL};
    int role_refused=envara_app_transport_command(4,args)==-1&&errno==EACCES;
    okay=okay&&stopped_verified&&nonroot_refused&&role_refused;
    printf("{\"ok\":%s,\"stoppedCreatorBirthCaptured\":%s,\"singleFDTransferAndDirectReap\":%s,\"nonceHashBirthExtraFDTimeoutBadExitRefused\":%s,"
        "\"visibleAndTruncatedRightsClosed\":%s,\"wrongCredentialRefused\":%s,\"nonrootProductionRefused\":%s,\"ready\":false,\"protected\":false,\"rightsCapacity\":%d,\"fdCensus\":[",
        okay?"true":"false",stopped_verified?"true":"false",okay?"true":"false",okay?"true":"false",okay?"true":"false",okay?"true":"false",
        nonroot_refused&&role_refused?"true":"false",LISTENER_RIGHTS_MAX);
    for(size_t i=0;i<sizeof(modes)/sizeof(*modes);i++)printf("%s{\"case\":\"%s\",\"before\":%d,\"after\":%d}",i?",":"",modes[i],before[i],after[i]);
    puts("]}");return okay?0:84;
}
struct preflight_child_fixture { int fault, lists, reads; };
static int preflight_fixture_list(void *context, pid_t *pids, size_t capacity) {
    struct preflight_child_fixture *f = context; f->lists++;
    if (capacity != PREFLIGHT_PID_LIMIT || f->fault == 1) return -1;
    if (f->fault == 2) return (int)capacity;
    pids[0]=10;pids[1]=20;pids[2]=30;
    if (f->fault == 3) pids[2]=20;
    if (f->fault == 4) pids[0]=-1;
    if (f->fault == 5 && f->lists == 2) pids[2]=40;
    return 3;
}
static int preflight_fixture_bsd(void *context, pid_t pid, struct proc_bsdinfo *out) {
    struct preflight_child_fixture *f = context; f->reads++;
    if (f->fault == 6) return -1;
    *out=(struct proc_bsdinfo){.pbi_pid=(uint32_t)pid,.pbi_ppid=1,.pbi_start_tvsec=100,.pbi_start_tvusec=1,.pbi_status=SRUN};
    if (f->fault == 7) out->pbi_ppid=1000;
    if (f->fault == 8) out->pbi_start_tvsec=0;
    if (f->fault == 9) out->pbi_start_tvusec=1000000;
    if (f->fault == 10) out->pbi_pid=99;
    if (f->fault == 11) out->pbi_status=255;
    if (f->fault == 12 && f->reads > 3) out->pbi_start_tvsec++;
    if (f->fault == 13 && f->reads > 3) out->pbi_gid=10;
    if (f->fault == 14 && f->reads > 3) out->pbi_svuid=501;
    if (f->fault == 15 && f->reads > 3) out->pbi_ppid=2;
    if (f->fault == 16 && f->reads > 3) out->pbi_status=SZOMB;
    return 0;
}
struct preflight_rule_fixture { int count, fault, target; };
static int preflight_fixture_rules(void *context, EnvaraPFHookRequest *r) {
    struct preflight_rule_fixture *f=context;const unsigned char actions[]={0,2,4,6,8,11};int index=f->count++;
    if (index >= 12 || r->action || r->nr || strcmp(r->anchor,"io.envara.pf.run.00000000-0000-4000-8000-000000000011") ||
        r->rule.action != actions[index/2]) return -1;
    r->ticket=(uint32_t)(100+index/2);
    if (index == f->target) {if(f->fault==1)return -1;if(f->fault==2)r->nr=1;if(f->fault==3)r->ticket++;
        if(f->fault==4)r->rule.action=255;if(f->fault==5)strcpy(r->anchor,"foreign");if(f->fault==6)r->action=1;
        if(f->fault==7)memset(r->anchor,'X',sizeof(r->anchor));}
    return 0;
}
static int preflight_proofs(void) {
    int checks=0,okay=1;struct preflight_child_fixture base={0};const PreflightChildReaders readers={&base,preflight_fixture_list,preflight_fixture_bsd};
    okay &= preflight_children_absent_with(1000,&readers)==1 && base.lists==2 && base.reads==6;checks++;
    for(int fault=1;fault<=16;fault++){struct preflight_child_fixture f={.fault=fault};const PreflightChildReaders r={&f,preflight_fixture_list,preflight_fixture_bsd};
        okay &= preflight_children_absent_with(1000,&r)==0;checks++;}
    okay &= preflight_children_absent(getpid())==0;checks++;
    struct preflight_rule_fixture empty={0};const char *run="00000000-0000-4000-8000-000000000011";
    okay &= preflight_classes_empty_with(run,preflight_fixture_rules,&empty)==1 && empty.count==12;checks++;
    for(int target=0;target<12;target++)for(int fault=1;fault<=7;fault++){
        if(fault==3&&!(target%2))continue;
        struct preflight_rule_fixture f={.fault=fault,.target=target};okay &= preflight_classes_empty_with(run,preflight_fixture_rules,&f)==0;checks++;
    }
    struct preflight_abort_proof p={0};fixture_listener_plan(&p.plan);
    strcpy(p.plan.realm_id,"00000000-0000-4000-8000-000000000013");p.plan.realm_gid=7100;
    p.parent=(struct envara_identity){.pid=2000,.parent_pid=1,.birth_seconds=100,.birth_microseconds=1};p.plan.controller=p.parent;
    p.bootstrap=(struct envara_identity){.pid=2001,.parent_pid=2000,.birth_seconds=101,.birth_microseconds=2};
    p.lease=(struct stat){.st_mode=S_IFREG|0600,.st_nlink=1,.st_size=200,.st_dev=1,.st_ino=2};
    p.run=(struct stat){.st_mode=S_IFDIR|0700,.st_nlink=2,.st_dev=1,.st_ino=3};
    p.executable=p.parent_executable=(struct stat){.st_mode=S_IFREG|0755,.st_nlink=1,.st_size=500,.st_dev=1,.st_ino=4};
    memset(p.nonce,'a',32);p.nonce[32]=0;p.captured=p.scope_before=p.scope_after=p.children_before=p.children_after=p.journal_before=p.journal_after=p.empty_before=p.empty_after=1;
    char frame[4096];okay &= preflight_abort_frame(&p,frame,sizeof(frame))>0;checks++;
    int *facts[]={&p.captured,&p.scope_before,&p.scope_after,&p.children_before,&p.children_after,&p.journal_before,&p.journal_after,&p.empty_before,&p.empty_after};
    for(size_t i=0;i<sizeof(facts)/sizeof(*facts);i++){*facts[i]=0;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;*facts[i]=2;
        okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;*facts[i]=1;checks+=2;}
    int *attempts[]={&p.bootstrap_attempted,&p.transport_attempted,&p.filter_attempted,&p.cold_attempted};
    for(size_t i=0;i<sizeof(attempts)/sizeof(*attempts);i++){*attempts[i]=1;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;*attempts[i]=0;checks++;}
    p.bootstrap.parent_pid=1999;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;p.bootstrap.parent_pid=2000;checks++;
    p.parent.birth_seconds++;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;p.parent.birth_seconds--;checks++;
    p.nonce[0]='X';okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;p.nonce[0]='a';checks++;
    p.lease.st_uid=501;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;p.lease.st_uid=0;checks++;
    p.parent_executable.st_mode=S_IFREG|0777;okay &= preflight_abort_frame(&p,frame,sizeof(frame))==-1;p.parent_executable.st_mode=S_IFREG|0755;checks++;
    struct envara_app_native_preflight out;memset(&out,0xff,sizeof(out));char hook[16384];memset(hook,0xff,sizeof(hook));size_t n=99;
    okay &= envara_app_native_abort_plan(p.plan.run_id,p.plan.environment_id,&out,hook,sizeof(hook),&n)==-1 && errno==EACCES && n==0;
    for(size_t i=0;i<sizeof(out);i++)okay &= ((unsigned char *)&out)[i]==0;
    for(size_t i=0;i<sizeof(hook);i++)okay &= hook[i]==0;checks++;
    if(preflight_abort_frame(&p,frame,sizeof(frame))<1)return 86;
    printf("{\"ok\":%s,\"builderOnly\":true,\"realRootAcceptance\":false,\"checks\":%d,\"nonrootAbortPlanRefused\":true,\"ready\":false,\"protected\":false,\"frame\":%s}\n",okay?"true":"false",checks,frame);
    return okay?0:87;
}
static int bounded_diagnostic(void) {
    int pipefd[2];if(pipe(pipefd))return 90;int saved=dup(1);if(saved<0||dup2(pipefd[1],1)<0)return 91;close(pipefd[1]);
    int flags=fcntl(1,F_GETFL);if(flags<0||fcntl(1,F_SETFL,flags|O_NONBLOCK))return 92;
    char filler[4096];memset(filler,'X',sizeof(filler));size_t filled=0;
    for(;;){ssize_t n=write(1,filler,sizeof(filler));if(n>0){filled+=(size_t)n;continue;}if(n<0&&errno==EAGAIN)break;return 93;}
    if(!filled)return 94;pid_t child=fork();if(child<0)return 95;
    if(!child){close(1);close(saved);poll(NULL,0,100);char tail[1536]={0},buffer[4096];size_t used=0;ssize_t n;
        while((n=read(pipefd[0],buffer,sizeof(buffer)))>0){for(ssize_t i=0;i<n;i++){if(used==sizeof(tail)-1){memmove(tail,tail+1,--used);}tail[used++]=buffer[i];tail[used]=0;}}
        close(pipefd[0]);_exit(n==0&&strstr(tail,"\"event\":\"transport-refused\"")&&strstr(tail,"\"stage\":\"guardian\"")&&
            strstr(tail,"\"reason\":\"NATIVE_NOTION_DATA_PREPARE_REFUSED\"")&&strstr(tail,"\"error\":13")&&used&&tail[used-1]=='\n'?0:96);
    }
    close(pipefd[0]);errno=ENOSPC;stopped=SIGTERM;
    refused_event_reason("00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000004","guardian","NATIVE_NOTION_DATA_PREPARE_REFUSED",EACCES);
    int preserved=errno==ENOSPC;stopped=0;if(dup2(saved,1)<0)return 97;close(saved);int status;
    if(waitpid(child,&status,0)!=child||status||!preserved)return 98;
    puts("{\"ok\":true,\"backpressureDrainedBeforeCompleteDiagnostic\":true,\"firstCapturedErrnoNotOverwritten\":true,\"diagnosticSurvivesStopFlag\":true,\"root\":false,\"pf\":false,\"ready\":false,\"protected\":false}");return 0;
}
int main(int argc,char **argv) {
    if (!getuid() || getuid()!=geteuid() || getgid()!=getegid()) return 30;
    if(argc==3&&!strcmp(argv[1],"listener-protocol-child"))return listener_protocol_child(argv[2]);
    if(argc!=2)return 30;
    if (!strcmp(argv[1],"bounded-diagnostic")) return bounded_diagnostic();
    if (!strcmp(argv[1],"listener")) return listener();
    if (!strcmp(argv[1],"frontend-stop")) return frontend_stop_fixture();
    if (!strcmp(argv[1],"relay")) return relay(0);
    if (!strcmp(argv[1],"malformed")) return relay(1);
    if (!strcmp(argv[1],"refused")) return refused();
    if (!strcmp(argv[1],"abort-proofs")) return abort_proofs(argv[0]);
    if (!strcmp(argv[1],"preflight-proofs")) return preflight_proofs();
    if (!strcmp(argv[1],"listener-protocol")) return listener_protocol(argv[0]);
    if (!strcmp(argv[1],"cold-fds")) return cold_fds(argv[0]); return 31;
}
