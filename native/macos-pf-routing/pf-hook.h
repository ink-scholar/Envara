#ifndef ENVARA_PF_ROOT_HOOK_H
#define ENVARA_PF_ROOT_HOOK_H
/* Private root-controller primitives, never an authorization or app launcher.
 * Command argv is fixed; receipts enter/leave only private stdin/stdout.
 * v2 full-run-UUID namespaces require durable native ledger events. Historical
 * v1 leases are not accepted by any current mutation path.
 * Production application-routing readiness is always false. */
int envara_pf_hook_main(int argc, char **argv);
/* An issued v2 lease is held exclusively while its FILTER class is replaced.
 * These functions are read-only with respect to PF and the durable ledger.
 * They never INSERT/DELETE, enable PF, or claim production readiness. */
typedef struct EnvaraPFHookFilterLease EnvaraPFHookFilterLease;
int envara_pf_hook_filter_open(const char *run_id, const char *lease_json,
    unsigned long lease_length, EnvaraPFHookFilterLease **out);
int envara_pf_hook_filter_matches(const EnvaraPFHookFilterLease *held,
    const char *lease_json, unsigned long lease_length);
int envara_pf_hook_filter_guard(EnvaraPFHookFilterLease *held, int write_fd);
void envara_pf_hook_filter_close(EnvaraPFHookFilterLease *held);
#endif
