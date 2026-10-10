#ifndef ENVARA_PF_RUN_LEDGER_H
#define ENVARA_PF_RUN_LEDGER_H

#include <stddef.h>

/* No PF operation, authorization request, process launch, or path supplied by
 * a production caller is exposed here. Only explicit INSERT/DELETE callers
 * may invoke the mutating APIs. Inspect never creates a directory or file. */
#define ENVARA_PF_RUN_LEDGER_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-run-ledger"
#define ENVARA_PF_RUN_LEDGER_MAX_RUNS 64
#define ENVARA_PF_RUN_UUID_BYTES 37
#define ENVARA_PF_RUN_ANCHOR_BYTES 54
#define ENVARA_PF_RUN_LEASE_LIMIT 4096

typedef struct EnvaraPFRunLedger EnvaraPFRunLedger;
typedef enum {
    ENVARA_PF_RUN_UNUSED = 0,
    ENVARA_PF_RUN_ALLOCATION_ONLY,
    ENVARA_PF_RUN_ISSUED,
    ENVARA_PF_RUN_DELETE_INTENT,
    ENVARA_PF_RUN_RETIRED,
    ENVARA_PF_RUN_CAPACITY_EXHAUSTED,
    ENVARA_PF_RUN_UNKNOWN
} EnvaraPFRunLedgerState;
typedef EnvaraPFRunLedgerState EnvaraPFRunLedgerBucket;
typedef enum {
    ENVARA_PF_RUN_RETIRE_NONE = 0,
    ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT,
    ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_PRESENT,
    ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN
} EnvaraPFRunLedgerRetirement;
typedef struct {
    EnvaraPFRunLedgerBucket bucket;
    EnvaraPFRunLedgerRetirement retirement;
    int run_consumed;
} EnvaraPFRunLedgerObservation;

/* Strict lowercase UUID v4 with RFC variant. The complete 36-byte UUID is
 * preserved in the single-component 53-byte anchor; no normalization/hash. */
int envara_pf_run_uuid_valid(const char *run_id);
int envara_pf_run_anchor(const char *run_id, char anchor[64]);
const char *envara_pf_run_ledger_state_name(EnvaraPFRunLedgerState state);

/* Every integer API returns 1 on success, 0 on refusal with errno. Inspect
 * returns 1 only for a verified observation. On any error, state is
 * UNKNOWN, never UNUSED. ENOENT is accepted only after safe held ancestors. */
int envara_pf_run_ledger_inspect(const char *run_id, EnvaraPFRunLedgerState *state);
/* Read-only exact historical receipt proof, including delete-intent/retired.
 * It cannot yield a DELETE handle and requires persisted issued bytes. */
int envara_pf_run_ledger_inspect_lease(const char *run_id, const char *canonical_lease,
                                     size_t length, EnvaraPFRunLedgerState *state);

/* EXCL allocation is durable before this returns. Every allocated UUID stays
 * consumed permanently, including failed INSERTs. Existing/unknown/bounded
 * inventory is never removed to permit a retry. Returned handle holds the
 * verified ledger directory's exclusive nonblocking cooperative lock. */
int envara_pf_run_ledger_allocate(const char *run_id, EnvaraPFRunLedger **out);

/* The private lease is exact minified canonical JSON in the hook's field
 * order, without newline/NUL. It must be v2, run/anchor/owner/label bound,
 * nonzero uint64-ticket-bearing. Durable issue must precede a success reply. */
int envara_pf_run_ledger_issue(EnvaraPFRunLedger *ledger, const char *canonical_lease, size_t length);

/* Open only this exact persisted issued lease. v1, missing, retired, unknown
 * and delete-intent records refuse before any PF DELETE. This API never
 * creates state and never adopts a ticket read from the kernel. */
int envara_pf_run_ledger_open_issued(const char *run_id, const char *canonical_lease,
                                   size_t length, EnvaraPFRunLedger **out);

/* Durable intent consumes the only DELETE attempt. Once this succeeds,
 * callers must not repeat DELETE, including after a lost reply or restart. */
int envara_pf_run_ledger_begin_delete(EnvaraPFRunLedger *ledger);

/* Caller must independently prove original root restoration. Namespace
 * absence is a disposition, not a prerequisite. Allowed for an allocated
 * INSERT handle's internal rollback or an opened issued handle, always after
 * durable delete intent. Existing retirement refuses all mutation APIs. */
int envara_pf_run_ledger_retire(EnvaraPFRunLedger *ledger, EnvaraPFRunLedgerRetirement retirement);
void envara_pf_run_ledger_close(EnvaraPFRunLedger *ledger);

#ifdef ENVARA_PF_RUN_LEDGER_INERT
/* Test-only: nonroot caller, already existing self-owned exact 0700 fixture
 * directory. Production builds expose no arbitrary root-path entry point. */
int envara_pf_run_ledger_test_root(const char *existing_fixture_root);
/* Next issue only: 1 leaves partial issued bytes, 2 leaves complete synced
 * bytes but returns failure. Neither uncertain handle may begin DELETE. */
int envara_pf_run_ledger_test_fail_issue(int mode);
#endif

#endif
