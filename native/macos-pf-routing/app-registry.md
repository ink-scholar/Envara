# Native application registry source

`app-registry.c` implements registration, immutable snapshot copying, current
version resolution and permanent retirement. It is a library; no installed CLI,
controller, installer or resource map calls it. Its inspection results always
have `ready=false` and `protected_ready=false`. It has no launch, resume or
snapshot deletion API.

Production uses only `/Library/PrivilegedHelperTools/io.envara.pf-apps`, separate
from the installed routing component. It requires real/effective root and
canonical, root-owned, nonwritable, ACL-free ancestors. Opening with `create=0`
and resolving records perform no writes. Fixture mode requires a nonroot caller
and a canonical, self-owned `0700` temporary parent; its records cannot be used
in production.

An immutable descriptor pins the original canonical bundle, bundle identifier
and designated signature requirement. Before copying, registration appends and
flushes a version intent. An incomplete or uncertain intent permanently blocks
that registration; it never silently restores an older snapshot. Committing
requires a complete copied-tree manifest, strict original and copied nested
signature validation, equal code identity/content/executable hashes, unchanged
original identity, exact directory inventories and current named-file identity.
The commit and directories are flushed before acknowledgement. A lost reply may
be recovered by read-only resolution of that exact committed version.

Copies preserve original file bytes, relative names, executable bits and bounded
relative internal framework symlink text. They seal directories to `0555` and
regular files to `0444` plus original execution bits. External, absolute,
dangling or cyclic links; regular-file hardlinks; setid bits; extended ACLs;
special nodes; and unknown extended attributes refuse. macOS-generated
`com.apple.provenance` of at most 256 bytes is permitted outside the content
manifest and is never removed or rewritten. Other metadata-dependent bundles
need an explicitly reviewed preservation policy; refusal is intentional.

Updates require the exact previous current version and the pinned original
path/identifier/designated requirement. An original update invalidates existing
resolution. Only the latest complete version resolves. Retirement appends a
durable tombstone and retains every object. Capacity is bounded to 32 app IDs,
8 permanent versions per app and 20,000 entries/2 GiB per snapshot; unknown
content or exhausted capacity stops work rather than deleting history.

The next integration must add fixed authenticated native registration/resolution
commands to the root helper, bind registration/version IDs to its private launch
lease, and pass resolver-produced original/snapshot manifests to `envara_gui_stage`.
Wire callers must not supply manifests, arbitrary paths, commands or function
pointers. This registry establishes snapshot identity only. Console bootstrap,
durable realm denial, app/child/helper ownership, private SOCKS/DNS delegation,
independent whole-guard and all live network acceptance gates remain required
before a separate authorized resume implementation can exist.

The standalone fixture suite compiles with warnings as errors and uses only
temporary self-owned bundles. It skips production signature/root validation and
does not execute copied application bytes, install anything or alter networking.
