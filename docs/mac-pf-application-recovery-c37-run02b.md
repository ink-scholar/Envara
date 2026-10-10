The 2026-10-09 controlled Notion test failed before native bootstrap and app
launch. Its fixed installed manifest is
`c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0`,
run `02b1a222-90c2-4595-a9b3-843f99508d1b`, environment
`34d9c77c-eb83-46fe-b655-df708a5e6df6`.

An independent fixed recovery tool passed an actual privileged read-only
inspection, then a separate single cleanup operation completed. It released
only the recorded PF reference, retired the exact empty root entry, removed
the dedicated empty group, and preserved private records in
`/Library/PrivilegedHelperTools/io.envara.pf-retired-c37-02b1a222`.
The old 46ae/904 archive was preserved. Do not replay either PF reference
release or entry deletion.

Actual receipts are `test-artifacts/mac-pf-routing/recovery-c37-readonly-result-20261009.json`
and `test-artifacts/mac-pf-routing/recovery-c37-cleanup-result-20261009.json`.
Cleanup and archival are confirmed. The recovery persisted its own host
network baseline before mutation and verified it unchanged afterwards.
The earlier application attempt's original host baseline remains unverified;
this recovery cannot reconstruct it.

The installation and recovery do not establish Notion launch, application
traffic, disconnect protection, generic application routing, or production
readiness. Those gates remain closed pending a new controlled acceptance run.
