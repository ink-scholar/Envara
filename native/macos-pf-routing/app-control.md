# Fixed native application commands

This source slice implements a standalone command dispatcher and a private
native preparation-ticket store. It directly uses `app-registry` for real
registration, current-version resolution and retirement. No installation or
frozen routing resource includes these new files yet.

Exact commands for future dispatch from the fixed `envara-pf-native` entry:

```text
app-register REGISTRATION_UUID VERSION_UUID ORIGINAL.app PREVIOUS_VERSION_UUID_OR_-
app-plan REGISTRATION_UUID VERSION_UUID ENVIRONMENT_UUID RUN_UUID
app-retire REGISTRATION_UUID
app-ticket-prepare TICKET_UUID REGISTRATION_UUID VERSION_UUID ENVIRONMENT_UUID RUN_UUID
app-ticket-inspect TICKET_UUID
```

Production refuses outside the fixed root-owned native entry. There is no
fixture CLI, arbitrary command/argv/environment, proxy password, UID/GID or
caller-manifest override. `app-plan` and ticket inspection open existing stores
read-only. Plan can report a verified registered app while honestly reporting
the unavailable environment authority. Every response keeps readiness and
protection false. `gui-launch-lease` deliberately refuses in the transient
dispatcher: it requires a persistent native supervisor entry.

The separate root-`0700` store is
`/Library/PrivilegedHelperTools/io.envara.pf-app-tickets`. Its immutable records
bind exact current registration/version/manifests, environment/run, native
request and private environment-lease digest. No node secret is persisted.
Lease and run indices are flushed before issuing a ticket; both IDs are burned
permanently even after a failed preparation. A new ticket UUID cannot reuse
either. A ticket lasts at most 60 seconds in the same boot session, using
continuous monotonic time. All history, partial files and uncertain claims are
retained; capacity is bounded to 64 scopes with no pruning or deletion API.

Claim re-resolves the original and sealed snapshot and re-derives the exact
environment request/lease from fixed native authority. The `claimed` record
and directory are flushed before any stage. Any claimed pathname, including a
partial or malformed one, prohibits another claim. The stage API passes only
these private resolver/ticket values to `envara_gui_stage`, rechecks live
authority immediately before fork, and requires guardian adoption of the exact
stopped child before returning. Failed adoption cancels only the known leader,
retains the consumed ticket and deny, and marks the lifecycle uncertain; it
does not claim family quiescence or release protection.

Required integration remains concrete: add this dispatcher to authenticated
fixed native `main`, install the new source/resources through the ordinary
reviewed build, provide native read-only environment lease inspection and live
deny/route/front/DNS/independent-guardian verification, and implement the
persistent `gui-launch-lease` keeper with exact child custody. Connect UI app
selection/registration IDs and the production coordinator to these commands.
Root-store/signature operation, real console bootstrap, helper boundaries,
whole-guard and live network acceptance remain unverified. No production
resume implementation is added by this slice.
