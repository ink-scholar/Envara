#define _DARWIN_C_SOURCE
#include "pf-run-ledger.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LEDGER_NAME "io.envara.pf-run-ledger"
#define ARCHIVE_LEAF "io.envara.pf-run-ledger-archive"
#define EVENT_LIMIT ENVARA_PF_RUN_LEASE_LIMIT
#define LEASE_SCHEMA "envara.macos-pf-owned-root-hook-lease/v2"
#define ALLOCATION_SCHEMA "envara.macos-pf-run-allocation/v2"
#define INTENT_SCHEMA "envara.macos-pf-run-delete-intent/v2"
#define RETIRE_SCHEMA "envara.macos-pf-run-retired/v2"

typedef struct {
    int parent, root;
    struct stat parent_identity, root_identity;
    char leaf[NAME_MAX + 1];
    char parent_path[PATH_MAX];
} LedgerRoot;
typedef struct {
    EnvaraPFRunLedgerState state;
    EnvaraPFRunLedgerRetirement retirement;
    char issued[EVENT_LIMIT + 1];
    size_t issued_length;
    int intent_rollback;
} RunRecord;
struct EnvaraPFRunLedger {
    LedgerRoot base;
    int run;
    struct stat run_identity;
    char run_id[37], anchor[64];
    RunRecord record;
    int allocation_handle;
    int mutation_uncertain;
};
#ifdef ENVARA_PF_RUN_LEDGER_INERT
static char test_root[PATH_MAX];
static int test_issue_failure;
#endif
static int refused(int value) { errno = value; return 0; }
static uid_t owner_uid(void) {
#ifdef ENVARA_PF_RUN_LEDGER_INERT
    return getuid();
#else
    return 0;
#endif
}
static int authorized(void) {
#ifdef ENVARA_PF_RUN_LEDGER_INERT
    return getuid() != 0 && geteuid() == getuid() && test_root[0];
#else
    return !getuid() && !geteuid();
#endif
}
int envara_pf_run_uuid_valid(const char *text) {
    if (!text || strnlen(text,37) != 36 || text[14] != '4' || !strchr("89ab",text[19])) return 0;
    for (size_t i=0;i<36;i++) {
        if (i==8 || i==13 || i==18 || i==23) { if (text[i]!='-') return 0; }
        else if (!((text[i]>='0' && text[i]<='9') || (text[i]>='a' && text[i]<='f'))) return 0;
    }
    return 1;
}
int envara_pf_run_anchor(const char *run_id,char anchor[64]) {
    if (!anchor || !envara_pf_run_uuid_valid(run_id)) return refused(EINVAL);
    int size=snprintf(anchor,64,"io.envara.pf.run.%s",run_id);
    return size==53 ? 1 : refused(EOVERFLOW);
}
const char *envara_pf_run_ledger_state_name(EnvaraPFRunLedgerState state) {
    switch(state) {
    case ENVARA_PF_RUN_UNUSED: return "unused";
    case ENVARA_PF_RUN_ALLOCATION_ONLY: return "allocation-only";
    case ENVARA_PF_RUN_ISSUED: return "issued";
    case ENVARA_PF_RUN_DELETE_INTENT: return "delete-intent";
    case ENVARA_PF_RUN_RETIRED: return "retired";
    case ENVARA_PF_RUN_CAPACITY_EXHAUSTED: return "capacity-exhausted";
    default: return "unknown";
    }
}
static const char *retirement_name(EnvaraPFRunLedgerRetirement value) {
    switch(value) {
    case ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT: return "root-restored-namespace-absent";
    case ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_PRESENT: return "root-restored-namespace-present";
    case ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN: return "root-restored-namespace-unknown";
    default: return NULL;
    }
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void hash_bytes(const char *bytes,size_t length,char out[65]) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(bytes,(CC_LONG)length,hash);
    for(size_t i=0;i<sizeof(hash);i++) snprintf(out+i*2,3,"%02x",hash[i]);
}
#pragma clang diagnostic pop
static int no_acl(int fd) {
    acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
    if(!acl) return errno==ENOENT ? 1 : 0;
    acl_entry_t entry; int count=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry), saved=errno;
    acl_free(acl); errno=saved; return count==0;
}
static int identity(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_uid==b->st_uid &&
        a->st_gid==b->st_gid && a->st_mode==b->st_mode && a->st_flags==b->st_flags;
}
static int stable_file(const struct stat *a,const struct stat *b) {
    return identity(a,b) && a->st_nlink==b->st_nlink && a->st_size==b->st_size &&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static int safe_directory(int fd,int private_directory,int fixture_ancestor,struct stat *out) {
    struct stat st;
    if(fstat(fd,&st) || !S_ISDIR(st.st_mode) || !st.st_nlink) return refused(EPERM);
    if(!fixture_ancestor && (st.st_uid!=owner_uid() ||
        (private_directory ? (st.st_mode&07777)!=0700 : (st.st_mode&0022)!=0) || !no_acl(fd))) return refused(EPERM);
    if(out) *out=st; return 1;
}
static int safe_file(int fd,struct stat *out) {
    struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=owner_uid() ||
        (st.st_mode&07777)!=0600 || st.st_nlink!=1 || st.st_size<1 || st.st_size>EVENT_LIMIT || !no_acl(fd)) return refused(EPERM);
    if(out) *out=st; return 1;
}
static int open_absolute_directory(const char *path,int fixture_ancestors) {
    if(!path || path[0]!='/' || strlen(path)>=PATH_MAX) { refused(EINVAL); return -1; }
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return -1;
    if(!safe_directory(fd,0,fixture_ancestors,NULL)) { close(fd); return -1; }
    char copy[PATH_MAX]; strcpy(copy,path); char *save=NULL;
    for(char *part=strtok_r(copy+1,"/",&save);part;part=strtok_r(NULL,"/",&save)) {
        if(!*part || !strcmp(part,".") || !strcmp(part,"..")) { close(fd); refused(EINVAL); return -1; }
        int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd); if(next<0) return -1;
        if(!safe_directory(next,0,fixture_ancestors,NULL)) { close(next); return -1; }
        fd=next;
    }
    return fd;
}
#ifdef ENVARA_PF_RUN_LEDGER_INERT
int envara_pf_run_ledger_test_root(const char *path) {
    struct stat st; char resolved[PATH_MAX];
    if(getuid()==0 || geteuid()!=getuid() || !path || path[0]!='/' || lstat(path,&st) ||
        !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) || st.st_uid!=getuid() ||
        (st.st_mode&07777)!=0700 || !realpath(path,resolved)) return refused(EPERM);
    int fd=open(resolved,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return 0; int okay=safe_directory(fd,1,0,NULL); close(fd);
    if(!okay) return 0; strcpy(test_root,resolved); return 1;
}
int envara_pf_run_ledger_test_fail_issue(int mode) {
    if(!authorized() || mode<0 || mode>2) return refused(EINVAL);
    test_issue_failure=mode; return 1;
}
#endif
static void close_base(LedgerRoot *base) {
    int saved=errno;
    if(base->root>=0) { (void)flock(base->root,LOCK_UN); close(base->root); }
    if(base->parent>=0) close(base->parent);
    base->root=base->parent=-1; errno=saved;
}
/* A missing root is a verified observation, represented by root=-1. */
static int open_base(int create,int exclusive,LedgerRoot *base) {
    memset(base,0,sizeof(*base)); base->parent=base->root=-1;
    if(!authorized()) return refused(EPERM);
    char parent_path[PATH_MAX]; int fixture_ancestors=0;
#ifdef ENVARA_PF_RUN_LEDGER_INERT
    strcpy(parent_path,test_root); char *slash=strrchr(parent_path,'/');
    if(!slash || slash==parent_path || !slash[1]) return refused(EINVAL);
    strcpy(base->leaf,slash+1); *slash=0; fixture_ancestors=1;
#else
    strcpy(parent_path,"/Library/PrivilegedHelperTools"); strcpy(base->leaf,LEDGER_NAME);
#endif
    strcpy(base->parent_path,parent_path);
    base->parent=open_absolute_directory(parent_path,fixture_ancestors);
    if(base->parent<0 || !safe_directory(base->parent,0,fixture_ancestors,&base->parent_identity)) goto failed;
    if(create && mkdirat(base->parent,base->leaf,0700) && errno!=EEXIST) goto failed;
    base->root=openat(base->parent,base->leaf,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(base->root<0) { if(!create && errno==ENOENT) return 1; goto failed; }
    if(!safe_directory(base->root,1,0,&base->root_identity) ||
        flock(base->root,(exclusive?LOCK_EX:LOCK_SH)|LOCK_NB)) goto failed;
    struct stat path;
    if(fstatat(base->parent,base->leaf,&path,AT_SYMLINK_NOFOLLOW) || !identity(&path,&base->root_identity)) goto failed;
    return 1;
failed: close_base(base); return 0;
}
static int held_base(const LedgerRoot *base) {
    struct stat parent,root,path;
    int fixture_ancestors=0;
#ifdef ENVARA_PF_RUN_LEDGER_INERT
    fixture_ancestors=1;
#endif
    int reopened=open_absolute_directory(base->parent_path,fixture_ancestors);
    struct stat named_parent; int parent_okay=reopened>=0 && !fstat(reopened,&named_parent) &&
        identity(&named_parent,&base->parent_identity);
    if(reopened>=0) close(reopened);
    if(base->parent<0 || base->root<0 || !safe_directory(base->parent,0,fixture_ancestors,&parent) ||
        !parent_okay || !identity(&parent,&base->parent_identity) || !safe_directory(base->root,1,0,&root) ||
        !identity(&root,&base->root_identity) || fstatat(base->parent,base->leaf,&path,AT_SYMLINK_NOFOLLOW) ||
        !identity(&path,&root)) return refused(ESTALE);
    return 1;
}
static int held_run(const EnvaraPFRunLedger *ledger) {
    struct stat held,path;
    return ledger && held_base(&ledger->base) && safe_directory(ledger->run,1,0,&held) &&
        identity(&held,&ledger->run_identity) && !fstatat(ledger->base.root,ledger->run_id,&path,AT_SYMLINK_NOFOLLOW) &&
        identity(&path,&held) ? 1 : refused(ESTALE);
}
/* No-follow event reads also compare held inode, timestamps and bytes length
 * before/after. Unknown content is never a missing/unused event. */
static int read_event(int run,const char *name,char bytes[EVENT_LIMIT+1],size_t *length,int *present) {
    *present=0; *length=0;
    int fd=openat(run,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return errno==ENOENT ? 1 : 0;
    struct stat before,after,path;
    if(!safe_file(fd,&before)) { close(fd); return 0; }
    size_t count=0;
    while(count<(size_t)before.st_size) {
        ssize_t amount=read(fd,bytes+count,(size_t)before.st_size-count);
        if(amount<0 && errno==EINTR) continue;
        if(amount<=0) { close(fd); return refused(EIO); } count+=(size_t)amount;
    }
    char extra; ssize_t more;
    do { more=read(fd,&extra,1); } while(more<0 && errno==EINTR);
    int okay=more==0 && safe_file(fd,&after) && stable_file(&before,&after) &&
        !fstatat(run,name,&path,AT_SYMLINK_NOFOLLOW) && stable_file(&after,&path);
    close(fd); if(!okay) return refused(ESTALE);
    if(memchr(bytes,0,count)) return refused(EPROTO);
    bytes[count]=0; *length=count; *present=1; return 1;
}
static int field(const char **cursor,const char *key,char *value,size_t capacity,int last) {
    char prefix[96]; int size=snprintf(prefix,sizeof(prefix),"\"%s\":\"",key);
    if(size<=0 || strncmp(*cursor,prefix,(size_t)size)) return 0;
    *cursor+=size; size_t length=0;
    while(**cursor && **cursor!='"') {
        unsigned char c=(unsigned char)*(*cursor)++;
        if(c<32 || c>126 || c=='\\' || length+1>=capacity) return 0;
        value[length++]=(char)c;
    }
    if(**cursor!='"') return 0; (*cursor)++; value[length]=0;
    if(**cursor!=(last?'}':',')) return 0; (*cursor)++; return 1;
}
static int lower_hex(const char *text,size_t length) {
    if(strlen(text)!=length) return 0;
    for(size_t i=0;i<length;i++) if(!((text[i]>='0' && text[i]<='9') || (text[i]>='a' && text[i]<='f'))) return 0;
    return 1;
}
static int canonical_lease(const char *run_id,const char *bytes,size_t length) {
    if(!bytes || !length || length>EVENT_LIMIT || memchr(bytes,0,length)) return refused(EINVAL);
    char copy[EVENT_LIMIT+1]; memcpy(copy,bytes,length); copy[length]=0; const char *p=copy;
    char schema[64],run[37],lease[37],anchor[64],owner[64],label[64],ticket[21],a[65],b[65],expected[64];
    if(*p++!='{' || !field(&p,"schema",schema,sizeof(schema),0) || !field(&p,"runId",run,sizeof(run),0) ||
        !field(&p,"leaseId",lease,sizeof(lease),0) || !field(&p,"anchor",anchor,sizeof(anchor),0) ||
        !field(&p,"owner",owner,sizeof(owner),0) || !field(&p,"label",label,sizeof(label),0) ||
        !field(&p,"ticket",ticket,sizeof(ticket),0) || !field(&p,"rootBeforeSHA256",a,sizeof(a),0) ||
        !field(&p,"rootBeforeTextSHA256",b,sizeof(b),1) || *p || strcmp(schema,LEASE_SCHEMA) ||
        !envara_pf_run_uuid_valid(run) || strcmp(run,run_id) || !envara_pf_run_uuid_valid(lease) ||
        !envara_pf_run_anchor(run,expected) || strcmp(anchor,expected) || strcmp(owner,expected) ||
        !lower_hex(a,64) || !lower_hex(b,64) || !*ticket || *ticket=='0') return refused(EPROTO);
    for(const char *digit=ticket;*digit;digit++) if(*digit<'0' || *digit>'9') return refused(EPROTO);
    errno=0; char *end; unsigned long long number=strtoull(ticket,&end,10);
    if(errno || *end || !number) return refused(EPROTO);
    char input[74],hash[65],expected_label[64]; snprintf(input,sizeof(input),"%s|%s",run,lease);
    hash_bytes(input,strlen(input),hash); snprintf(expected_label,sizeof(expected_label),"envara.hook.v2.%.32s",hash);
    return !strcmp(label,expected_label) ? 1 : refused(EPROTO);
}
static int allocation_event(const char *run_id,char *out,size_t capacity) {
    char anchor[64]; if(!envara_pf_run_anchor(run_id,anchor)) return 0;
    int length=snprintf(out,capacity,"{\"schema\":\"%s\",\"runId\":\"%s\",\"anchor\":\"%s\",\"owner\":\"%s\"}\n",ALLOCATION_SCHEMA,run_id,anchor,anchor);
    return length>0 && (size_t)length<capacity ? length : 0;
}
static int intent_event(const char *run_id,const RunRecord *record,int rollback,char *out,size_t capacity) {
    char anchor[64],hash[65]; if(!envara_pf_run_anchor(run_id,anchor) || (!record->issued_length && !rollback)) return 0;
    if(record->issued_length) hash_bytes(record->issued,record->issued_length,hash); else strcpy(hash,"none");
    int length=snprintf(out,capacity,"{\"schema\":\"%s\",\"runId\":\"%s\",\"anchor\":\"%s\",\"issuedLeaseSHA256\":\"%s\",\"operation\":\"%s\"}\n",
        INTENT_SCHEMA,run_id,anchor,hash,rollback?"insert-rollback":"delete");
    return length>0 && (size_t)length<capacity ? length : 0;
}
static int retirement_event(const char *run_id,const RunRecord *record,int rollback,EnvaraPFRunLedgerRetirement retirement,char *out,size_t capacity) {
    const char *disposition=retirement_name(retirement); char anchor[64],hash[65];
    if(!disposition || !envara_pf_run_anchor(run_id,anchor)) return 0;
    if(record->issued_length) hash_bytes(record->issued,record->issued_length,hash); else strcpy(hash,"none");
    int length=snprintf(out,capacity,"{\"schema\":\"%s\",\"runId\":\"%s\",\"anchor\":\"%s\",\"issuedLeaseSHA256\":\"%s\",\"operation\":\"%s\",\"disposition\":\"%s\"}\n",
        RETIRE_SCHEMA,run_id,anchor,hash,rollback?"insert-rollback":"delete",disposition);
    return length>0 && (size_t)length<capacity ? length : 0;
}
static int equal_event(const char *actual,size_t length,const char *expected,int expected_length) {
    return expected_length>0 && length==(size_t)expected_length && !memcmp(actual,expected,length);
}
static int read_run(int run,const char *run_id,RunRecord *record) {
    memset(record,0,sizeof(*record)); record->state=ENVARA_PF_RUN_UNKNOWN;
    if(!safe_directory(run,1,0,NULL)) return 0;
    DIR *directory=fdopendir(dup(run)); if(!directory) return 0; rewinddir(directory);
    unsigned mask=0; int okay=1; struct dirent *entry; errno=0;
    while((entry=readdir(directory))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        unsigned bit=!strcmp(entry->d_name,"allocation.json")?1:!strcmp(entry->d_name,"issued.json")?2:
            !strcmp(entry->d_name,"delete-intent.json")?4:!strcmp(entry->d_name,"retired.json")?8:0;
        if(!bit || (mask&bit)) { okay=0; break; } mask|=bit;
    }
    int scan_error=errno; closedir(directory);
    if(!okay || scan_error || !(mask&1)) return refused(EPROTO);
    char bytes[EVENT_LIMIT+1],expected[EVENT_LIMIT+1]; size_t length; int present;
    if(!read_event(run,"allocation.json",bytes,&length,&present) || !present ||
        !equal_event(bytes,length,expected,allocation_event(run_id,expected,sizeof(expected)))) return refused(EPROTO);
    if(mask&2) {
        if(!read_event(run,"issued.json",record->issued,&record->issued_length,&present) || !present ||
            !canonical_lease(run_id,record->issued,record->issued_length)) return refused(EPROTO);
    }
    if(mask&4) {
        if(!read_event(run,"delete-intent.json",bytes,&length,&present) || !present) return refused(EPROTO);
        int matched=0;
        for(int rollback=1;rollback>=((mask&2)?0:1);rollback--) {
            if(equal_event(bytes,length,expected,intent_event(run_id,record,rollback,expected,sizeof(expected)))) {
                record->intent_rollback=rollback; matched=1; break;
            }
        }
        if(!matched) return refused(EPROTO);
    }
    record->state=(mask&4)?ENVARA_PF_RUN_DELETE_INTENT:(mask&2)?ENVARA_PF_RUN_ISSUED:ENVARA_PF_RUN_ALLOCATION_ONLY;
    if(mask&8) {
        if(!(mask&4)) return refused(EPROTO);
        if(!read_event(run,"retired.json",bytes,&length,&present) || !present) return refused(EPROTO);
        int matched=0;
        for(int value=ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT;value<=ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN && !matched;value++) {
            if(equal_event(bytes,length,expected,retirement_event(run_id,record,record->intent_rollback,(EnvaraPFRunLedgerRetirement)value,expected,sizeof(expected)))) {
                record->retirement=(EnvaraPFRunLedgerRetirement)value; matched=1; break;
            }
        }
        if(!matched) return refused(EPROTO); record->state=ENVARA_PF_RUN_RETIRED;
    }
    return 1;
}
/* An archived run UUID is consumed forever: allocation refuses it, and it is
 * reported as retired rather than unused, so no live state is ever adopted from
 * an archived receipt. Read-only and bounded, like the live inventory. */
static int archived_run(LedgerRoot *base,const char *wanted,int *found) {
    *found=0;
    int directory=openat(base->parent,ARCHIVE_LEAF,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(directory<0) return errno==ENOENT ? 1 : 0;
    struct stat held,path_stat;
    if(!safe_directory(directory,1,0,&held) || fstatat(base->parent,ARCHIVE_LEAF,&path_stat,AT_SYMLINK_NOFOLLOW) ||
        !identity(&held,&path_stat)) { close(directory); return refused(EPERM); }
    DIR *listing=fdopendir(directory);
    if(!listing) { close(directory); return 0; }
    struct dirent *entry; errno=0;
    while((entry=readdir(listing))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if(!strcmp(entry->d_name,wanted)) { *found=1; break; }
    }
    int scan_error=errno; closedir(listing);
    if(scan_error) return refused(EIO);
    return 1;
}
/* Terminal receipts are moved out of the live inventory into the archive
 * directory. Only a fully read_run-verified RETIRED row can move, and the move
 * is name-exclusive: an existing archive entry is never overwritten. */
static int archive_open(LedgerRoot *base) {
    if(mkdirat(base->parent,ARCHIVE_LEAF,0700) && errno!=EEXIST) return 0;
    int directory=openat(base->parent,ARCHIVE_LEAF,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(directory<0) return 0;
    struct stat held,path;
    int okay=safe_directory(directory,1,0,&held) && !fstatat(base->parent,ARCHIVE_LEAF,&path,AT_SYMLINK_NOFOLLOW) &&
        identity(&path,&held);
    if(!okay) { int saved=errno; close(directory); errno=saved; return 0; }
    return directory;
}
static int archive_rename(LedgerRoot *base,int directory,const char *name) {
    if(renameatx_np(base->root,name,directory,name,RENAME_EXCL)==0) return 1;
    if(errno!=EEXIST) return 0;
    /* The name is already archived. Accept it only as a full, safe directory
     * of this owner, never as a partial or foreign entry. */
    int existing=openat(directory,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(existing<0) return 0;
    struct stat held; int okay=safe_directory(existing,1,0,&held);
    close(existing); return okay;
}
static int archive_prune(int directory) {
    struct Entry { time_t seconds; long nanoseconds; char name[NAME_MAX+1]; } rows[ENVARA_PF_RUN_LEDGER_ARCHIVE_MAX];
    size_t count=0; DIR *listing=fdopendir(dup(directory));
    if(!listing) return 0;
    struct dirent *entry; errno=0;
    while((entry=readdir(listing))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if(!envara_pf_run_uuid_valid(entry->d_name)) continue;
        struct stat info;
        if(fstatat(directory,entry->d_name,&info,AT_SYMLINK_NOFOLLOW)) continue;
        if(count<ENVARA_PF_RUN_LEDGER_ARCHIVE_MAX) {
            rows[count].seconds=info.st_mtimespec.tv_sec; rows[count].nanoseconds=info.st_mtimespec.tv_nsec;
            strncpy(rows[count].name,entry->d_name,NAME_MAX); rows[count].name[NAME_MAX]=0; count++;
        }
        errno=0;
    }
    int scan_error=errno; closedir(listing);
    if(scan_error) return refused(EIO);
    /* Oldest first, bounded: a stale archive entry is evidence with no live
     * authority, so dropping the oldest is safe. A failed delete is retried on
     * the next allocation rather than treated as a fatal ledger fault. */
    while(count>ENVARA_PF_RUN_LEDGER_ARCHIVE_MAX-1) {
        size_t oldest=0;
        for(size_t i=1;i<count;i++) if(rows[i].seconds<rows[oldest].seconds ||
            (rows[i].seconds==rows[oldest].seconds && rows[i].nanoseconds<rows[oldest].nanoseconds)) oldest=i;
        if(unlinkat(directory,rows[oldest].name,AT_REMOVEDIR) && errno!=ENOENT) return 0;
        memcpy(&rows[oldest],&rows[count-1],sizeof(rows[0])); count--;
    }
    return 1;
}
/* Validate every bounded sibling record, not merely the requested name. */
static int inventory(LedgerRoot *base,const char *wanted,RunRecord *record,int *found,size_t *count,int archive_terminal) {
    *found=0; *count=0; if(record) { memset(record,0,sizeof(*record)); record->state=ENVARA_PF_RUN_UNUSED; }
    if(base->root<0) return 1;
    if(!held_base(base)) return 0;
    DIR *directory=fdopendir(dup(base->root)); if(!directory) return 0; rewinddir(directory);
    int okay=1; struct dirent *entry; errno=0;
    while((entry=readdir(directory))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if(!envara_pf_run_uuid_valid(entry->d_name) || ++*count>ENVARA_PF_RUN_LEDGER_MAX_RUNS) { okay=0; break; }
        int run=openat(base->root,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        RunRecord row; struct stat held,path;
        if(run<0 || !safe_directory(run,1,0,&held) || !read_run(run,entry->d_name,&row) ||
            fstatat(base->root,entry->d_name,&path,AT_SYMLINK_NOFOLLOW) || !identity(&held,&path)) okay=0;
        if(run>=0) close(run); if(!okay) break;
        if(!strcmp(entry->d_name,wanted)) { if(*found) { okay=0; break; } *found=1; if(record) *record=row; }
        errno=0;
    }
    int scan_error=errno; closedir(directory);
    if(!okay || scan_error || !held_base(base)) return refused(EPROTO);
    if(archive_terminal && *count) {
        /* Only fully verified terminal receipts leave the live inventory, and
         * only while this exclusive handle holds the ledger lock. The requested
         * record is never moved: the caller is about to decide on it. A run
         * that cannot be archived stays live and keeps consuming a slot, so an
         * unclear record is never silently discarded. */
        int archived_directory=archive_open(base);
        if(archived_directory>=0) {
            char(*names)[NAME_MAX+1]=calloc(ENVARA_PF_RUN_LEDGER_MAX_RUNS,sizeof(*names));
            size_t terminal_count=0;
            DIR *listing=fdopendir(dup(base->root));
            if(names && listing) {
                struct dirent *row; errno=0;
                while((row=readdir(listing))) {
                    if(!envara_pf_run_uuid_valid(row->d_name) || !strcmp(row->d_name,wanted)) { errno=0; continue; }
                    int run=openat(base->root,row->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
                    RunRecord candidate; struct stat held,path;
                    int terminal=run>=0 && safe_directory(run,1,0,&held) && read_run(run,row->d_name,&candidate) &&
                        !fstatat(base->root,row->d_name,&path,AT_SYMLINK_NOFOLLOW) && identity(&held,&path) &&
                        candidate.state==ENVARA_PF_RUN_RETIRED &&
                        candidate.retirement==ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT;
                    if(run>=0) close(run);
                    if(terminal && terminal_count<ENVARA_PF_RUN_LEDGER_MAX_RUNS)
                        strncpy(names[terminal_count++],row->d_name,NAME_MAX);
                    errno=0;
                }
                int sweep_error=errno; closedir(listing);
                if(!sweep_error && terminal_count) {
                    int moved=0;
                    for(size_t i=0;i<terminal_count;i++) if(archive_rename(base,archived_directory,names[i])) moved++;
                    if(moved) { (void)fsync(base->root); (void)fsync(archived_directory); (void)archive_prune(archived_directory); }
                }
            } else if(listing) closedir(listing);
            free(names);
            close(archived_directory);
            /* The caller's live count is re-derived after the sweep. */
            *count=0;
            DIR *after=fdopendir(dup(base->root));
            if(!after) return 0;
            struct dirent *leftover; errno=0;
            while((leftover=readdir(after))) if(envara_pf_run_uuid_valid(leftover->d_name) && ++*count>ENVARA_PF_RUN_LEDGER_MAX_RUNS) break;
            int residual=errno; closedir(after);
            if(residual) return refused(EIO);
            if(!held_base(base)) return 0;
        }
    }
    if(!*found) {
        int archived=0;
        if(!archived_run(base,wanted,&archived)) return 0;
        if(archived) { *found=1; if(record) { record->state=ENVARA_PF_RUN_RETIRED;
            record->retirement=ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT; } }
    }
    return 1;
}
static int inspect_internal(const char *run_id,const char *lease,size_t length,int exact,EnvaraPFRunLedgerState *state) {
    if(state) *state=ENVARA_PF_RUN_UNKNOWN;
    if(!state || !envara_pf_run_uuid_valid(run_id) || (exact && !canonical_lease(run_id,lease,length))) return refused(EINVAL);
    LedgerRoot base; if(!open_base(0,0,&base)) return 0;
    RunRecord record; int found; size_t count;
    int okay=inventory(&base,run_id,&record,&found,&count,0);
    if(okay && exact && (!found || !record.issued_length || record.issued_length!=length || memcmp(record.issued,lease,length))) okay=refused(EPROTO);
    if(okay) *state=found?record.state:count>=ENVARA_PF_RUN_LEDGER_MAX_RUNS?ENVARA_PF_RUN_CAPACITY_EXHAUSTED:ENVARA_PF_RUN_UNUSED;
    close_base(&base); return okay;
}
int envara_pf_run_ledger_inspect(const char *run_id,EnvaraPFRunLedgerState *state) { return inspect_internal(run_id,NULL,0,0,state); }
int envara_pf_run_ledger_inspect_lease(const char *run_id,const char *lease,size_t length,EnvaraPFRunLedgerState *state) { return inspect_internal(run_id,lease,length,1,state); }
void envara_pf_run_ledger_close(EnvaraPFRunLedger *ledger) {
    if(!ledger) return; int saved=errno; if(ledger->run>=0) close(ledger->run);
    close_base(&ledger->base); memset(ledger,0,sizeof(*ledger)); free(ledger); errno=saved;
}
static EnvaraPFRunLedger *new_handle(void) {
    EnvaraPFRunLedger *ledger=calloc(1,sizeof(*ledger));
    if(ledger) ledger->run=ledger->base.root=ledger->base.parent=-1; return ledger;
}
static int sync_record(EnvaraPFRunLedger *ledger) {
    return held_run(ledger) && !fsync(ledger->run) && !fsync(ledger->base.root) && !fsync(ledger->base.parent) && held_run(ledger);
}
static int write_event(EnvaraPFRunLedger *ledger,const char *name,const char *bytes,size_t length) {
    if(!held_run(ledger) || !bytes || !length || length>EVENT_LIMIT) return refused(EINVAL);
    int fd=openat(ledger->run,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return 0; struct stat created; int okay=!fstat(fd,&created) && S_ISREG(created.st_mode) &&
        created.st_uid==owner_uid() && (created.st_mode&07777)==0600 && created.st_nlink==1 && !created.st_size && no_acl(fd);
    int injected=0;
#ifdef ENVARA_PF_RUN_LEDGER_INERT
    if(!strcmp(name,"issued.json")) { injected=test_issue_failure; test_issue_failure=0; }
#endif
    size_t written=0,target=injected==1?length/2:length;
    while(okay && written<target) {
        ssize_t amount=write(fd,bytes+written,target-written); if(amount<0 && errno==EINTR) continue;
        if(amount<=0) { okay=0; break; } written+=(size_t)amount;
    }
    if(okay) okay=!fsync(fd); int saved=errno; close(fd); errno=saved;
    if(injected) { if(okay) (void)sync_record(ledger); okay=0; }
    char readback[EVENT_LIMIT+1]; size_t observed; int present;
    if(okay) okay=read_event(ledger->run,name,readback,&observed,&present) && present && observed==length && !memcmp(readback,bytes,length) && sync_record(ledger);
    /* No unlink/rollback of ledger files: even incomplete evidence consumes
     * the namespace and stops later mutation. */
    return okay ? 1 : refused(EIO);
}
static int refresh(EnvaraPFRunLedger *ledger) {
    if(!held_run(ledger)) return 0; RunRecord record; int found; size_t count;
    if(!inventory(&ledger->base,ledger->run_id,&record,&found,&count,0) || !found || !held_run(ledger)) return refused(EPROTO);
    if(ledger->record.issued_length && (record.issued_length!=ledger->record.issued_length ||
        memcmp(record.issued,ledger->record.issued,record.issued_length))) return refused(EPROTO);
    ledger->record=record; return 1;
}
int envara_pf_run_ledger_allocate(const char *run_id,EnvaraPFRunLedger **out) {
    if(out) *out=NULL; if(!out || !envara_pf_run_uuid_valid(run_id)) return refused(EINVAL);
    EnvaraPFRunLedger *ledger=new_handle(); if(!ledger) return 0;
    if(!open_base(1,1,&ledger->base)) goto failed;
    RunRecord record; int found; size_t count;
    if(!inventory(&ledger->base,run_id,&record,&found,&count,1)) goto failed;
    if(found) { refused(EEXIST); goto failed; }
    if(count>=ENVARA_PF_RUN_LEDGER_MAX_RUNS) { refused(ENOSPC); goto failed; }
    strcpy(ledger->run_id,run_id); if(!envara_pf_run_anchor(run_id,ledger->anchor)) goto failed;
    if(mkdirat(ledger->base.root,run_id,0700)) goto failed;
    ledger->run=openat(ledger->base.root,run_id,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(ledger->run<0 || !safe_directory(ledger->run,1,0,&ledger->run_identity)) goto failed;
    char event[EVENT_LIMIT+1]; int length=allocation_event(run_id,event,sizeof(event));
    if(!length || !write_event(ledger,"allocation.json",event,(size_t)length)) goto failed;
    ledger->allocation_handle=1; ledger->record.state=ENVARA_PF_RUN_ALLOCATION_ONLY; *out=ledger; return 1;
failed: envara_pf_run_ledger_close(ledger); return 0;
}
int envara_pf_run_ledger_issue(EnvaraPFRunLedger *ledger,const char *lease,size_t length) {
    if(!ledger || !ledger->allocation_handle || !canonical_lease(ledger->run_id,lease,length) ||
        !refresh(ledger) || ledger->record.state!=ENVARA_PF_RUN_ALLOCATION_ONLY) return refused(EPERM);
    if(!write_event(ledger,"issued.json",lease,length)) { ledger->mutation_uncertain=1; return 0; }
    memcpy(ledger->record.issued,lease,length); ledger->record.issued[length]=0;
    ledger->record.issued_length=length; ledger->record.state=ENVARA_PF_RUN_ISSUED; return 1;
}
int envara_pf_run_ledger_open_issued(const char *run_id,const char *lease,size_t length,EnvaraPFRunLedger **out) {
    if(out) *out=NULL;
    if(!out || !envara_pf_run_uuid_valid(run_id) || !canonical_lease(run_id,lease,length)) return refused(EINVAL);
    EnvaraPFRunLedger *ledger=new_handle(); if(!ledger) return 0;
    if(!open_base(0,1,&ledger->base) || ledger->base.root<0) goto failed;
    int found; size_t count;
    if(!inventory(&ledger->base,run_id,&ledger->record,&found,&count,0) || !found ||
        ledger->record.state!=ENVARA_PF_RUN_ISSUED || ledger->record.issued_length!=length ||
        memcmp(ledger->record.issued,lease,length)) { refused(EPERM); goto failed; }
    strcpy(ledger->run_id,run_id); if(!envara_pf_run_anchor(run_id,ledger->anchor)) goto failed;
    ledger->run=openat(ledger->base.root,run_id,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(ledger->run<0 || !safe_directory(ledger->run,1,0,&ledger->run_identity) || !held_run(ledger)) goto failed;
    *out=ledger; return 1;
failed: envara_pf_run_ledger_close(ledger); return 0;
}
int envara_pf_run_ledger_begin_delete(EnvaraPFRunLedger *ledger) {
    if(!ledger || ledger->mutation_uncertain || !refresh(ledger) ||
        (ledger->record.state!=ENVARA_PF_RUN_ISSUED && !(ledger->allocation_handle && ledger->record.state==ENVARA_PF_RUN_ALLOCATION_ONLY))) return refused(EPERM);
    char event[EVENT_LIMIT+1]; int length=intent_event(ledger->run_id,&ledger->record,ledger->allocation_handle,event,sizeof(event));
    if(!length || !write_event(ledger,"delete-intent.json",event,(size_t)length)) { ledger->mutation_uncertain=1; return 0; }
    ledger->record.state=ENVARA_PF_RUN_DELETE_INTENT; ledger->record.intent_rollback=ledger->allocation_handle; return 1;
}
int envara_pf_run_ledger_retire(EnvaraPFRunLedger *ledger,EnvaraPFRunLedgerRetirement retirement) {
    if(!ledger || ledger->mutation_uncertain || !retirement_name(retirement) || !refresh(ledger)) return refused(EINVAL);
    int permitted=ledger->record.state==ENVARA_PF_RUN_DELETE_INTENT && ledger->record.intent_rollback==ledger->allocation_handle;
    if(!permitted) return refused(EPERM);
    char event[EVENT_LIMIT+1]; int length=retirement_event(ledger->run_id,&ledger->record,ledger->allocation_handle,retirement,event,sizeof(event));
    if(!length || !write_event(ledger,"retired.json",event,(size_t)length)) { ledger->mutation_uncertain=1; return 0; }
    ledger->record.state=ENVARA_PF_RUN_RETIRED; ledger->record.retirement=retirement; return 1;
}
