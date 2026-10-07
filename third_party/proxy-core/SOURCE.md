# Mihomo proxy core source and notices

Envara includes the **unmodified Mihomo v1.19.32 executable** as a separately
launched process. Mihomo is copyright its upstream authors and contributors,
and is distributed under the GNU General Public License version 3. The complete
license text is in `LICENSE`. Envara's MIT license does not replace the license
of this core or its dependencies.

- Official release: https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32
- Fixed source commit: `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`
- Source archive: https://codeload.github.com/MetaCubeX/mihomo/tar.gz/88dcbf7f1614a67c3b36b848ee3592dfa92ada36
- Source archive SHA-256: `77643ec763a92b330a0b4a44870f78ee05c08792897e7f5e40a3654415c5f077`
- Official asset digests and the observed executable digest are recorded in
  the adjacent `provenance.json`.

`mihomo-corresponding-source.tar.gz` is included next to this notice and the
executable, including in packaged app resources. It contains the full upstream
source at the fixed commit, its original build scripts and notices, and a
`vendor/` directory of the dependencies selected by the unmodified `go.mod`
and `go.sum`. Go verifies downloaded module checksums before vendoring. The
source bundle adds a build helper and provenance file. Upstream program source
is not patched. The release workflow fills its empty CA embed file before
compiling; this build input is reproduced with the public CA bundle extracted
verbatim from the checksum-verified official executable, and recorded in source
provenance. Dependency copyright and license files stay in their original source
directories.

To rebuild, extract the source archive and run
`node ENVARA_BUILD_FROM_SOURCE.mjs` inside the extracted directory with a
compatible Go toolchain installed. This compiles the upstream `with_gvisor`
build with vendored dependencies and produces `mihomo-rebuilt` (or `.exe`). The
helper builds without fetching modules. You can modify that source and build
your own executable under its license.

The supplied executable is the checksum-verified official release asset.
The source helper reproduces its version and upstream build options, but does
not promise byte-for-byte reproduction of release timestamps or the patched
compiler. The original upstream workflow is included
at `.github/workflows/build.yml`; its Go compiler is maintained separately at
https://github.com/MetaCubeX/go. Envara adds no patches to the supplied binary.

Packaging runs `node scripts/prepare-proxy-core.mjs`. The script pins the
release, fixed source commit, and official binary archive digests; rejects
mismatched checksums; prepares corresponding source before replacing an
existing build; and checks the executable's version on the native packaging
runner. Never ship the executable without this license, source archive, and
provenance. Current native verification covers macOS arm64. Linux x64 and
Windows x64 asset mappings are preparation candidates, not native acceptance.
