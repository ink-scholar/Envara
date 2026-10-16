# Camoufox identity tuples

This directory contains 24 build-time generated Firefox identity tuples: eight
each for macOS, Windows and Linux. The Go backend embeds `catalog.json`; it does
not install Python, download fingerprint models, inspect the user's hardware or
read another browser's profile at runtime.

## Sources and generation

- Official Camoufox Python wrapper **0.4.11**, from the
  [v135.0.1-beta.24 source](https://github.com/daijro/camoufox/tree/v135.0.1-beta.24/pythonlib).
- BrowserForge **1.2.1** and its pinned Apify fingerprint-suite **v2.1.58** models.
- The unmodified Camoufox **135.0.1-beta.24** native `properties.json`, retained
  here as `native-properties.json` to validate every generated top-level field.
- Camoufox's original `fonts.json`, `browserforge.yml` conversion and
  `webgl_data.db` sampling functions. GPU vendor, renderer, extensions,
  parameters, shader precision and context attributes stay a whole sample valid
  for the selected OS. This is not a promise of a specific physical device model.

`provenance.json` records the input hashes, native schema hash, generator
versions and output hash. `generate.py` calls the upstream generator and
conversion functions; it neither launches a browser nor queries host displays,
installed fonts, public egress or hardware identifiers. Its screen bounds are
explicit. Only complete samples with WebGL 2 enabled are retained, matching the
current Firefox launch preferences.

To regenerate in an isolated development Python environment:

```sh
python3 -m venv /tmp/envara-camoufox-generator
/tmp/envara-camoufox-generator/bin/python -m pip install camoufox==0.4.11 browserforge==1.2.1 numpy==2.5.4
/tmp/envara-camoufox-generator/bin/python generate.py --properties native-properties.json
```

The first BrowserForge import can fetch its pinned public models. Review the
new provenance and run the Go tests plus real Camoufox acceptance before
updating the catalog. The fixed generator sampling seed makes catalog review
repeatable within the recorded toolchain; byte-identical output across other
Python/dependency versions is not promised.

## Runtime policy

`NewCamoufoxIdentity` uses the operating system's cryptographic random source to
select one complete OS tuple and set the three additional native properties
used by the pinned official wrapper:

- `fonts:spacing_seed`: 0 through 1,073,741,823;
- `canvas:aaOffset`: -50 through 50;
- `canvas:aaCapOffset`: `true`.

The caller saves the result when creating an environment. Reloading or importing
an existing environment must keep its saved fields. The finite tuple collection
does not make every hardware field unique, and no unsupported audio-noise seed
is generated. Browser-native audio behavior remains the provider's behavior.

Language, timezone, geolocation and WebRTC address values are deliberately
excluded. Envara resolves the environment's network context for a session;
catalog language values must not turn automatic language selection into a fixed
locale. This catalog does not establish public egress or WebRTC leak protection.

## Attribution and licenses

Camoufox's source repository and native schema retain the full MPL-2.0 notice in
`LICENSE-Camoufox.txt`; its Python wrapper declares MIT in its package metadata.
BrowserForge and the Apify fingerprint-suite models retain their separate full
Apache-2.0 texts in `LICENSE-BrowserForge.txt` and
`LICENSE-Fingerprint-Suite.txt`. The generated data, original notices and source
references remain attributed here; Envara's original MIT license does not
replace these third-party terms. No upstream browser executable is included in
this directory or modified by the generator.
