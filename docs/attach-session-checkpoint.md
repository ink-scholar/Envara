# Attach-session checkpoint (2026-10-12)

Working note for the in-progress feature. Delete this file once the delivery is verified.

## Goal

An attached application, once authorized, keeps running until the user stops it, the application
exits, or Envara quits. The administrator password is asked **once per Envara launch**, not once per
attach. Up to 5 applications may eventually run at the same time (browser and terminals excluded).
Everything attached must still leave through its environment's network.

## Status

**Phase 1 is compiled, tested and packaged; not yet exercised on real hardware.**

- Built and packaged at `release/mac-arm64/Envara.app`, component manifest
  `7beb7b50ced9…`, carrier `265ba4078a35…`; both match `PF_NOTION_TRIAL_CANDIDATE`
  and the packaged-resource verification passes.
- Full suite green (1611 tests, 1609 pass, 2 skip, 0 fail).
- **The first packaged build could not update the installed component at all.** The
  `03245359` snapshot header had been generated and included in `authorize-install.c`
  but was never added to the `known_prior_snapshots[]` table, so the carrier
  classified the installed component as unrecognized and refused with
  `existing-installation-conflict`. Fixed and rebuilt; the packaged carrier now
  recognizes it.
- Hardware verification (one password per launch, runs until stopped, survives
  sleep, clean quit) is still outstanding and is what the user is testing next.

Everything below in "What changed" describes the code, not verified behaviour.

## What changed (phase 1)

Native:

- `authorize-install.c` — the carrier relay no longer has a wall-clock deadline
  (`RELAY_SECONDS 0.0` means "until Envara ends the session or the root controller exits"); the
  authorization prompt now describes the real behaviour (one password per launch, runs until you
  stop it or quit, no permanent daemon).
- `launch-guardian.{h,c}` — the lease ceiling is 30 days instead of one hour, and the guardian now
  enforces a controller **heartbeat**: no `K` for `heartbeat_timeout_milliseconds` of *awake* time
  (`CLOCK_UPTIME_RAW`, so sleeping the Mac cannot revoke) means one revocation. The watchdog arms on
  the first heartbeat, so the long cold-stage is never mistaken for a dead controller.
- `app-supervisor.c` — guard preflight accepts the new ceiling and requires a heartbeat window.
- `app-native-factory.{h,m}` — the 180 s lease bound is replaced by the shared 30-day bound, and the
  guard request carries `ENVARA_APP_HEARTBEAT_TIMEOUT_MS`.
- `pf-run-ledger.{c,h}` — terminal receipts (root restored, namespace absent) are swept into a
  sibling `io.envara.pf-run-ledger-archive` directory during the next allocation, so a long-lived
  installation cannot exhaust the 64-entry live inventory. An archived UUID still blocks reuse; the
  archive is itself capped at 512 entries, oldest first.
- `launch-guardian-fixture.c` / `launch-guardian.test.mjs` — new `heartbeat-lost` and
  `heartbeat-kept` scenarios and their expected reasons (12 and 1).

Controller / front:

- `controller.mjs` — the lease bound is `PF_APP_SESSION_LEASE_SECONDS` (30 days); the run no longer
  stops itself at 180 s; the heartbeat writes `K` **directly** rather than through the serialized
  queue, so preparing another attachment cannot starve a running one; a separate 5 s liveness tick
  re-verifies the sealed lease and the keeper identity; one root session now serves many sequential
  attachments (`beginNextApplicationRun()` resets every per-run latch and refuses unless the previous
  run's resources are fully released); `applicationEnded` is no longer recorded for a stop we
  requested ourselves; a cleaned run leaves the live status inventory and its route is retired.
- `notion-front-service.mjs` — the lease bound follows the 30-day constant and the expiry timer is
  re-armed in bounded steps (`MAXIMUM_TIMER_MS`) so a 30-day delay cannot overflow Node's timer.

Electron:

- `macos-pf-channel-mux.mjs` (new) — one authorized root channel per Envara launch, multiplexed into
  per-run virtual processes; responses are routed by request id; ending one run detaches only that
  run; `dispose()` is the quit path.
- `macos-pf-notion-session.mjs` — `lifetimeMs` (default 180000 for the bounded trial,
  `PF_SESSION_CHANNEL_LIFETIME_MS` for a session), `acquireChannel`/`channelKey` for the shared
  channel, `requestSerial` for a caller-supplied queue; diagnostics tolerate an unbounded lifetime.
- `macos-pf-notion-trial.mjs` — still the attach manager: the client is created per run through the
  shared mux, `observationMs` defaults to 0 (run until stopped), polling every 2 s detects an
  application that ended on its own, `disposeShared()` closes the root session.
- `macos-pf-application-routing.mjs` — `shutdown()` disposes the shared session before releasing
  routes, so quitting Envara closes the root controller.

UI / i18n:

- `workspace-pages.jsx`, `network-flow-english.mjs`, `network-flow-translations.mjs`, `i18n.mjs`,
  `src/locales/*.json` — the attach controls say attach/stop rather than "trial", no longer promise
  a maximum duration, and explain that the first attach asks for one administrator authorization.

## Known gaps

1. **Nothing is verified.** No compile, no test run, no packaging.
2. `electron/macos-pf-attach-session.mjs` is an earlier draft that the manager no longer imports.
   Decide whether to delete it or wire the manager through it.
3. `electron/terminal-network-fence.mjs` and `tests/terminal-network-fence.test.mjs` are untracked
   work from the terminal-network-fence task, not part of this feature.
4. `release-verified-4/`, `build/local-authorization-archive/`, `native/macos-pf-routing/installer-upgrade-*.h`
   and `native/macos-pf-routing/known-installations/*.json` are untracked build artifacts; the
   installer-upgrade headers and known-installation manifests are build inputs for the upgrade path,
   so they must exist locally before the component is rebuilt.
5. Untested by design until phase 2 lands: only one attached application at a time. The controller
   refuses a second concurrent run, and the native PF hook still assumes exactly one owned hook.
6. The 30-day ceiling is an outer bound, not the intended end of a session: a session normally ends
   when the user stops the application or quits Envara.

## How to resume

```
cd /path/to/Envara
wc -c electron/macos-pf-channel-mux.mjs
node --test tests/macos-pf-notion-trial.test.mjs tests/macos-pf-notion-session.test.mjs tests/macos-pf-controller.test.mjs tests/macos-pf-application-orchestration.test.mjs
node scripts/build-macos-pf-routing.mjs        # compiled native component (needs the network/proxy)
node --test native/macos-pf-routing/launch-guardian.test.mjs
npm test
```

Then, to hand the feature to the user: register the currently installed component as a known prior,
rebuild the component and the authorization carrier, update `PF_NOTION_TRIAL_CANDIDATE`, run
`scripts/verify-package-resources.mjs`, package a new `release-verified-N` and open it. The user then
clicks "Update network component" once (one password) and attaches an application manually.


## Where phase 2 stands (2026-10-12)

Two pieces of phase 2 are done and verified here:

- Keeper reports bind to each run's own profile, so a cold-profile application
  that ends on its own is reported as ended instead of staying "running".
- Per-application filter rules stay in their own top-level anchor. This was
  established by trying the nested layout first and measuring that it is
  unrepresentable: 90 bytes against two separate 64-byte fields
  (`ProductionPlan.anchor` and `rule.owner`).

What remains is the shared-root-hook work itself: the call-line writer, the
two-level ledger lock (shared for live keepers, exclusive for deleting the hook),
the registry change that lets five applications share one hook, and the
five-slot limit with per-application resource split in the controller. None of it
is started. It needs the real machine, because every native invariant it touches
(`BEGIN_ADDRS` clearing the global `pf_pabuf`, original root rule counts of 7 or
8, the keeper's exclusive ledger lock) can only be settled against actual PF.
