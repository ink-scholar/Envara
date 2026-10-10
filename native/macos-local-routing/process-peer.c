/* Envara local verifier. No entitlements or Apple account required.
 * Inspect a real process identity, or a passed UNIX socket's signed NE peer.
 * This program never changes system preferences or signals another process. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int fail_reason(const char *reason) { printf("{\"verified\":false,\"reason\":\"%s\"}\n",reason);return 1; }
static int fail(void) { return fail_reason("NATIVE_IDENTITY_UNAVAILABLE"); }
static int peer_socket_failure(void) {
    switch(errno) {
        case ENOTCONN:return fail_reason("PEER_SOCKET_DISCONNECTED");
        case EBADF:return fail_reason("PEER_FD_UNAVAILABLE");
        case ENOTSOCK:return fail_reason("PEER_FD_NOT_SOCKET");
        case EPERM:case EACCES:return fail_reason("PEER_CREDENTIALS_DENIED");
        default:return fail_reason("PEER_SOCKET_CREDENTIAL_QUERY_FAILED");
    }
}
static int missing(pid_t pid) {
    /* ESRCH from proc_pidinfo is distinct from a permission/read failure. */
    printf("{\"verified\":true,\"pid\":%d,\"alive\":false,\"reason\":\"not-found\"}\n",pid);return 0;
}
static void json_string(const char *text) {
    putchar('"');
    for (const unsigned char *p=(const unsigned char *)text;*p;p++) {
        if (*p=='"' || *p=='\\') {putchar('\\');putchar(*p);}
        else if (*p<32) printf("\\u%04x",*p);
        else putchar(*p);
    }
    putchar('"');
}
static int identity(pid_t pid) {
    struct proc_bsdinfo info,after;char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(&info,0,sizeof(info));memset(&after,0,sizeof(after));memset(path,0,sizeof(path));
    if(pid<2)return fail();
    errno=0;
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof(info))!=(int)sizeof(info))return errno==ESRCH?missing(pid):fail();
    if(info.pbi_pid!=(uint32_t)pid || !info.pbi_start_tvsec || proc_pidpath(pid,path,sizeof(path))<=0)return fail();
    errno=0;
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&after,sizeof(after))!=(int)sizeof(after))return errno==ESRCH?missing(pid):fail();
    if(
       after.pbi_pid!=info.pbi_pid || after.pbi_uid!=info.pbi_uid ||
       after.pbi_start_tvsec!=info.pbi_start_tvsec || after.pbi_start_tvusec!=info.pbi_start_tvusec)return fail();
    printf("{\"verified\":true,\"alive\":true,\"pid\":%d,\"uid\":%u,\"parentPid\":%u,\"birth\":\"%llu:%06llu\",\"path\":",pid,info.pbi_uid,info.pbi_ppid,
           (unsigned long long)info.pbi_start_tvsec,(unsigned long long)info.pbi_start_tvusec);
    json_string(path);puts("}");return 0;
}
static int peer(void) {
    pid_t pid=0;uid_t uid;gid_t gid;socklen_t size=sizeof(pid);
    SecCodeRef code=NULL;SecRequirementRef requirement=NULL;CFDictionaryRef attrs=NULL,signing=NULL;
    CFNumberRef number=NULL;int ok=0;char hash[41]={0};const char *reason="PEER_SIGNATURE_UNAVAILABLE";
    /* Node passes the accepted socket as stdio fd 3, not a numeric pid claim. */
    if(getsockopt(3,SOL_LOCAL,LOCAL_PEERPID,&pid,&size)!=0)return peer_socket_failure();
    if(size!=sizeof(pid) || pid<2)return fail_reason("PEER_PID_INVALID");
    if(getpeereid(3,&uid,&gid)!=0)return peer_socket_failure();
    number=CFNumberCreate(NULL,kCFNumberIntType,&pid);
    if(!number)return fail_reason("PEER_NATIVE_ALLOCATION_FAILED");
    const void *keys[]={kSecGuestAttributePid};const void *values[]={number};
    attrs=CFDictionaryCreate(NULL,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    if(!attrs){reason="PEER_NATIVE_ALLOCATION_FAILED";goto done;}
    if(SecCodeCopyGuestWithAttributes(NULL,attrs,kSecCSDefaultFlags,&code)!=errSecSuccess){reason="PEER_DYNAMIC_CODE_UNAVAILABLE";goto done;}
    if(SecRequirementCreateWithString(CFSTR("anchor apple generic and identifier \"org.mitmproxy.macos-redirector.network-extension\" and certificate leaf[subject.OU] = \"S8XHQB96PW\""),kSecCSDefaultFlags,&requirement)!=errSecSuccess){reason="PEER_REQUIREMENT_INVALID";goto done;}
    if(SecCodeCheckValidity(code,kSecCSStrictValidate,requirement)!=errSecSuccess){reason="PEER_SIGNATURE_REQUIREMENT_REJECTED";goto done;}
    if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&signing)!=errSecSuccess){reason="PEER_SIGNING_INFO_UNAVAILABLE";goto done;}
    CFDataRef unique=(CFDataRef)CFDictionaryGetValue(signing,kSecCodeInfoUnique);
    if(!unique || CFGetTypeID(unique)!=CFDataGetTypeID() || CFDataGetLength(unique)!=20){reason="PEER_CDHASH_UNAVAILABLE";goto done;}
    const UInt8 *bytes=CFDataGetBytePtr(unique);
    for(int i=0;i<20;i++)snprintf(hash+i*2,3,"%02x",bytes[i]);
    if(strcmp(hash,"5e5a926e18280c133fa34a172b57d6f788d90ea5") && strcmp(hash,"faaf3df7efb96c11c32900558890b86b33b6481e")){reason="PEER_CDHASH_MISMATCH";goto done;}
    ok=1;
done:
    if(signing)CFRelease(signing);if(requirement)CFRelease(requirement);if(code)CFRelease(code);if(attrs)CFRelease(attrs);if(number)CFRelease(number);
    if(!ok)return fail_reason(reason);
    printf("{\"verified\":true,\"pid\":%d,\"uid\":%u,\"teamIdentifier\":\"S8XHQB96PW\",\"identifier\":\"org.mitmproxy.macos-redirector.network-extension\",\"cdhash\":\"%s\"}\n",pid,uid,hash);
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"peer"))return peer();
    if(argc==3 && !strcmp(argv[1],"identity")) {
        char *end=NULL;errno=0;long value=strtol(argv[2],&end,10);
        if(errno || !end || *end || value<2 || value>INT32_MAX)return fail();
        return identity((pid_t)value);
    }
    return fail();
}
