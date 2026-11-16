# Application updates

The Settings page provides **Check for updates**, **Download update**, and **Install and restart**. Checking and downloading happen only after a click. Updates use the host's system network settings to reach the official `ink-scholar/Envara` GitHub releases; they do not change an environment's selected route.

The first implementation supports packaged macOS Apple Silicon applications in a location writable by the current user. Development builds, other platforms, read-only volumes, App Translocation and protected installation locations cannot replace the application. No administrator password is requested and no host security settings are changed. A version without this updater needs one initial installation of a version that includes it.

## Existing data

An update replaces only the running `.app` bundle. Environment settings, browser profiles, terminal history, named login profiles, attached-application data and Keychain entries remain in their existing locations. The installer neither exports nor moves those locations. It also does not update or activate system routing components.

Downloading is allowed while working. Installation requires all browser, terminal and attached-application sessions to be ended, and imports, exports, component installations and other pending operations to finish. The main process checks this again, reserves backend admission against REST/MCP operations, and confirms owned-service shutdown before authorizing replacement. An uncertain shutdown does not grant installation authority.

## Verification and installation

The updater accepts only stable newer versions and the exact architecture asset from the fixed official repository. It checks both GitHub's asset SHA-256 digest and the release's `SHA256SUMS.txt`, then validates archive paths, sizes, CRC, bundle identifier, architecture, version and macOS code-signature integrity. Staging is private; renderer requests contain neither paths nor download URLs.

The source of authenticity is the official repository over HTTPS. The matching checksums are integrity checks from that same publisher, not an independent signing authority. Ad-hoc code signatures do not provide Developer ID certification or notarization. GitHub repository compromise remains a trust boundary.

A bundled native helper prepares a copy on the installation volume. It requires a private authorization from its exact parent and waits for that parent's exit before an atomic directory exchange. A replacement validation failure triggers a swap back only while the exact two application directory identities are still known. A new process opened during the transaction waits or exits before starting environments; a process that loaded old code must relaunch from the updated bundle.

The old application is retained in the helper's private `.envara-update-*` sibling directory. Downloaded transaction files and its bounded result receipt are retained under the application's `application-updates` directory after installation handoff. This costs disk space but keeps recovery evidence; no generic cache pruning removes them. A receipt can report a failed relaunch separately from a completed installation. Do not restore an old application over a running instance or assume an application rollback reverses a data migration.

## Release requirements

`npm run updater:prepare` builds the macOS helper from the reviewed source. The manual macOS release pipeline includes it and the package resource verifier compares its executable and source/builder digests. Existing release checks and manual publication authorization still apply; adding this feature does not enable automatic GitHub builds or publishing.

Publish the verified architecture ZIP and `SHA256SUMS.txt` in the same release, with GitHub asset digests available. Do not replace assets behind an existing published version. A future data migration must remain compatible with this preservation contract or add an explicit migration transaction before release.

## Validation boundaries

Tests use disposable signed fixture applications, synthetic account files, controlled release responses and hidden Electron windows. They cover malformed downloads, cancellation, archive escape attempts, duplicate requests, admission races, parent authorization, atomic replacement, rollback and nine-language interface states. These fixtures do not establish acceptance of a published package, Gatekeeper prompts, protected installation locations or a real user's cross-version sign-in sessions. Those remain checks for the exact release candidate.
