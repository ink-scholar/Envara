# Concurrent attachments (up to 5) — design notes

Working note for phase 2. Delete when the delivery is verified.

## Goal

Up to five attached applications run at the same time, alongside the browser and
terminals, which do not consume a slot. One administrator password per Envara
launch still covers all of them.

## The constraint found while building this

The hook binds every rule to its lease through two fixed 64-byte fields:

- `rule.owner` — must equal `lease->owner` (`owned_identity` in `pf-hook.c`)
- `request.anchor_call` — must equal `lease->anchor`

A single run anchor is `io.envara.pf.run.` + 36-char UUID = 53 bytes, so it fits.
A sub-anchor needs both the shared session UUID and the application UUID:

    io.envara.pf.run.<session-uuid>/<app-uuid>   = 90 bytes

That does not fit a 64-byte field. So a plain nested path cannot be expressed in
the existing lease identity. Three ways out, in order of preference:

1. **Shorten the owned identity rather than the path.** Keep the rule owner as
   the 53-byte session anchor and put only the *child* UUID in `rule.label`
   (64 bytes, already carries a 61-char derived label today). The anchor path
   stays in `request.anchor[1024]`, which has room. This needs a new lease field
   for the child id and a matching change in `owned_identity`.
2. **One anchor per application, no nesting.** Give each application its own
   top-level anchor (`io.envara.pf.run.<app-uuid>`), and let the shared root hook
   hold up to five fixed call lines, one per active anchor. This keeps every
   existing identity check exactly as it is; the new work is only in the call-line
   writer and in the shared/exclusive ledger lock. **This is the smallest change
   that preserves the currently verified 53-byte identity, and it is what the
   plan already describes for the call lines.**
3. Extend the 64-byte field, which changes the pinned kernel ABI. Rejected: the
   layout is a frozen observation, not a negotiated structure.

Option 2 is the direction. Options 1 and 3 are recorded only so the reasoning is
not lost.

## Ordering hazard that still applies (unchanged from the plan)

`BEGIN_ADDRS` clears the *global* `pf_pabuf`, so two applications must never run
a filter transaction concurrently. Every sub-anchor transaction therefore needs
one native lock, and that lock also has to be the one the call-line writer takes.

## What this means for the ledger

The keeper holds the ledger lock for as long as it runs, and it runs for as long
as the application does. With five applications that is five holders. The ledger
lock therefore becomes two-level:

- shared: every live keeper, and the call-line writer
- exclusive: deleting the hook, which requires the shared anchor to be empty first

## Status

Not started. The prior-list defect that blocked the component update is fixed and
committed; that fix is what the user is testing next.
