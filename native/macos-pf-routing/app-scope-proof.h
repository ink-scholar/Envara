#ifndef ENVARA_APP_SCOPE_PROOF_H
#define ENVARA_APP_SCOPE_PROOF_H
#include <sys/types.h>
#include <stdint.h>

/* Read-only native process-credential absence for one owned GID (7100..7999).
 * Returns exactly 1 only for two complete, matching inventories with stable
 * real/effective/saved GIDs and every supplementary slot checked, including
 * zombies. Root UID and EUID and matching kernel/SDK group capacity are required.
 * Unknown, permission, truncation, malformed credentials or a GID hit returns
 * 0 immediately. Exact zero-byte ESRCH or a fully decoded PID/identity/group
 * change discards the entire round, with at most 3 rounds sharing 15 seconds.
 * No PID is skipped, individually reread, or adopted from an earlier round.
 * This snapshot is not an atomic launch/credential barrier, directory-service
 * group absence, PF cleanup, or production readiness. The caller must retain
 * its independent native exclusion and exact owned-process lifecycle proof.
 * Calls may block in the kernel; the inter-call deadline is not a hard deadline.
 * No public injection API, runtime override, filesystem/network mutation. */
int envara_app_scope_gid_absent(gid_t gid);
/* Fixed process-local diagnostics only: no PID, path or credential vectors.
 * Reads do not supply absence authority. Counts accumulate over <=3 rounds. */
typedef enum {
    ENVARA_SCOPE_NOT_RUN = 0,
    ENVARA_SCOPE_ABSENCE_VERIFIED = 1,
    ENVARA_SCOPE_REQUEST_OR_READERS_INVALID = 2,
    ENVARA_SCOPE_ROOT_REFUSED = 3,
    ENVARA_SCOPE_CAPACITY_READER_REFUSED = 4,
    ENVARA_SCOPE_CAPACITY_MISMATCH = 5,
    ENVARA_SCOPE_CLOCK_REFUSED = 6,
    ENVARA_SCOPE_ALLOCATION_REFUSED = 7,
    ENVARA_SCOPE_DEADLINE_REFUSED = 8,
    ENVARA_SCOPE_LIST_READER_REFUSED = 9,
    ENVARA_SCOPE_LIST_BOUND_REFUSED = 10,
    ENVARA_SCOPE_NEGATIVE_PID = 11,
    ENVARA_SCOPE_EMPTY_POSITIVE_LIST = 12,
    ENVARA_SCOPE_DUPLICATE_PID = 13,
    ENVARA_SCOPE_BSD_READER_REFUSED = 14,
    ENVARA_SCOPE_BSD_SHAPE_REFUSED = 15,
    ENVARA_SCOPE_GID_PRESENT = 16,
    ENVARA_SCOPE_SUPPLEMENTARY_READER_REFUSED = 17,
    ENVARA_SCOPE_SUPPLEMENTARY_SHAPE_REFUSED = 18,
    ENVARA_SCOPE_IDENTITY_MISMATCH = 19,
    ENVARA_SCOPE_PID_INVENTORY_CHANGED = 20,
    ENVARA_SCOPE_GROUP_VECTOR_CHANGED = 21
} EnvaraScopeDiagnosticReason;

typedef enum {
    ENVARA_SCOPE_QUERY_NONE = 0,
    ENVARA_SCOPE_QUERY_GROUP_CAPACITY = 1,
    ENVARA_SCOPE_QUERY_PID_ESTIMATE = 2,
    ENVARA_SCOPE_QUERY_PID_LIST = 3,
    ENVARA_SCOPE_QUERY_BSD = 4,
    ENVARA_SCOPE_QUERY_SUPPLEMENTARY = 5,
    ENVARA_SCOPE_QUERY_CLOCK = 6
} EnvaraScopeDiagnosticQuery;

typedef struct {
    uint32_t reason;
    uint32_t first_count;
    uint32_t second_count;
    uint32_t bsd_reads;
    uint32_t supplementary_reads;
    uint32_t native_errno;
    uint32_t native_bytes;
    uint32_t native_query;
    uint32_t rounds, retry_count, retry_exhausted;
    uint32_t first_reason, first_native_errno, first_native_bytes, first_native_query;
} EnvaraScopeDiagnostic;

const EnvaraScopeDiagnostic *envara_app_scope_last_diagnostic(void);
#endif
