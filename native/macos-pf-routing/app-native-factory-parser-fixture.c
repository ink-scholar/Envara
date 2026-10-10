/* Test-only translation unit: call the production parser and lease generator.
 * None of the PF/ledger/root command entry points is invoked by this fixture. */
#include "pf-hook.c"

int envara_factory_fixture_parse_hook(const char *bytes, size_t length) {
    HookLease lease;
    return filter_lease_parse(bytes, (unsigned long)length, &lease);
}
size_t envara_factory_fixture_hook(char output[ENVARA_PF_RUN_LEASE_LIMIT + 1]) {
    HookLease lease = {0};
    strcpy(lease.schema, LEASE_SCHEMA);
    strcpy(lease.runId, "00000000-0000-4000-8000-000000000001");
    strcpy(lease.leaseId, "00000000-0000-4000-8000-000000000002");
    if (!envara_pf_run_anchor(lease.runId, lease.anchor)) return 0;
    strcpy(lease.owner, lease.anchor); lease_label(&lease, lease.label);
    strcpy(lease.ticket, "123456");
    strcpy(lease.rootBeforeSHA256, ROOT_RULE_HASH);
    strcpy(lease.rootBeforeTextSHA256, ROOT_TEXT_HASH);
    return lease_json(&lease, output);
}
