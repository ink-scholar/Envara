# BrowseForge

[繁體中文](README.zh-TW.md)

BrowseForge is an automation-ready anti-detect browser workspace for teams that need repeatable, isolated browser identities across desktop, server, Docker, REST API, MCP, and Playwright workflows.

It combines Firefox/Camoufox, Chromium/CloakBrowser, and the source-level BrowseForge Chromium runtime with profile isolation, fingerprint management, remote control, backup/restore, and agent-friendly automation surfaces.

## Why BrowseForge

- Run isolated browser identities without rebuilding automation around each browser engine.
- Control profiles through a web UI, REST API, MCP tools, YAML workflows, or Playwright clients.
- Deploy locally for development or on Linux servers with Docker and KasmVNC.
- Keep release and platform behavior auditable through documented support matrices, guarded release scripts, and CI checks.
- Build on an international-ready foundation with English-first docs, Traditional Chinese docs, and UI i18n.

## Who It Is For

- QA and automation teams validating multi-account or multi-region browser flows.
- Browser-runtime researchers comparing fingerprint and anti-detection behavior.
- AI agent builders that need MCP-controlled browser sessions.
- Operators who need repeatable profile storage, backup, restore, and remote browser access.

## Trust and Safety

- MIT licensed.
- Public security policy and support process.
- Token-authenticated REST API, MCP HTTP, and Playwright proxy access.
- Version-pinned Docker guidance for production deployments.
- Release preflight checks for tests, i18n, Docker build, Camoufox Bind runtime, and release artifact consistency.

## Features

- Multi-runtime engines: Firefox via Camoufox, Chromium via CloakBrowser, and alpha source-level Chromium via BrowseForge Chromium.
- Isolated profiles: each profile has separate cookies, local storage, proxy settings, group proxy policy, and fingerprint settings.
- Fingerprint pool: generated fingerprints with local/proxy-aware timezone and locale adjustment.
- Web Dashboard: searchable profile, tag, session, and group proxy management at `http://127.0.0.1:19280`.
- REST API: programmatic profile, session, backup, restore, and workflow control.
- MCP server: stdio and Streamable HTTP modes for AI agents.
- Playwright connect: external Playwright clients can attach to running BrowseForge sessions.
- Docker deployment: KasmVNC desktop, Dashboard/API, MCP HTTP, and browser runtime dependencies.
- Portable binary: first launch downloads browser engines when needed.

## Project Resources

- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Release Process](docs/release.md)
- [Platform Support](docs/platform-support.md)
- [Internationalization](docs/i18n.md)
- [Changelog](CHANGELOG.md)
- [API Reference](API.md)

## Quick Start

Download the matching ZIP from [Releases](https://github.com/nczz/BrowseForge/releases):

| Platform | Asset |
|------|------|
| macOS Intel | `BrowseForge-vX.X.X-lite-macos-x64.zip` |
| macOS Apple Silicon | `BrowseForge-vX.X.X-lite-macos-arm64.zip` |
| Linux x64 | `BrowseForge-vX.X.X-lite-linux-x64.zip` |
| Linux arm64 | `BrowseForge-vX.X.X-lite-linux-arm64.zip` |
| Windows x64 | `BrowseForge-vX.X.X-lite-windows-x64.zip` |

```bash
unzip BrowseForge-vX.X.X-lite-macos-arm64.zip
cd BrowseForge-lite
./BrowseForge
```

The Dashboard opens at `http://127.0.0.1:19280`. Browser engines are downloaded on first launch when they are not already installed.

## Docker

For production deployments, pin a release tag instead of using `latest`:

```bash
mkdir -p ./browseforge/{profiles,data,browsers,logs,backups}

docker run -d --name browseforge \
  -p 19280:19280 -p 6901:6901 \
  -e VNC_PASSWORD=browseforge \
  -e BROWSEFORGE_PUBLIC_BASE_URL=${BROWSEFORGE_PUBLIC_BASE_URL:-http://localhost:19280} \
  -v "$PWD/browseforge/profiles:/app/profiles" \
  -v "$PWD/browseforge/data:/app/data" \
  -v "$PWD/browseforge/browsers:/app/browsers" \
  -v "$PWD/browseforge/logs:/app/logs" \
  -v "$PWD/browseforge/backups:/app/backups" \
  -e BROWSEFORGE_SEED_BROWSERS=1 \
  --restart unless-stopped \
  ghcr.io/nczz/browseforge:v2.1.15
```

The `./browseforge/` host directory is the durable runtime. Reusing these mounts when pulling a new image or recreating the container preserves profiles, tokens, browser data, logs, and backups.

The quick Docker command binds BrowseForge inside the container while defaulting `BROWSEFORGE_PUBLIC_BASE_URL` to `http://localhost:19280`, a fetchable origin for same-host agents. For remote servers or reverse proxies, export `BROWSEFORGE_PUBLIC_BASE_URL` with the externally reachable origin, including any path prefix.

| Service | URL |
|------|-----|
| Dashboard + REST API + Playwright proxy | `http://localhost:19280` |
| MCP Streamable HTTP | `http://localhost:19280/mcp` |
| KasmVNC remote desktop | `http://localhost:6901` |
| VNC credentials | `user` / `VNC_PASSWORD` |
| API token | `docker exec browseforge /app/BrowseForge token` |

Local source build:

```bash
cd docker
docker compose up -d --build
```

The GHCR Docker image publishes native `linux/amd64` and `linux/arm64` manifests. Docker pulls the matching image automatically on x64 servers, Apple Silicon, and ARM servers; use `--platform linux/amd64` only for compatibility debugging.

See [docs/linux-server.md](docs/linux-server.md) for server deployment details.

## CLI

```bash
# Show commands and version
./BrowseForge --help
./BrowseForge version

# Initialize config.json, profiles/, data/, and logs/
./BrowseForge init

# Start the server
./BrowseForge serve
./BrowseForge serve --host 0.0.0.0 --no-sandbox --no-open

# Print the API token
./BrowseForge token
./BrowseForge token --json

# Check local browser/runtime state
./BrowseForge doctor
./BrowseForge doctor --strict --json
./BrowseForge status --json
./BrowseForge browsers status --json
./BrowseForge open

# Show integration capabilities and validate server transports
./BrowseForge capabilities --json
./BrowseForge smoke rest --base-url http://127.0.0.1:19280 --wait --json
./BrowseForge smoke mcp --base-url http://127.0.0.1:19280 --token "$TOKEN" --wait --json
./BrowseForge mcp-config stdio --json

# Backup and browser preparation
./BrowseForge browsers install --runtimes camoufox,browseforge-chromium
./BrowseForge backup create --full --output ./backups --json

# Run server-backed workflows and inspect API resources
./BrowseForge workflow run examples/multi-login.yaml --token "$TOKEN" --json
./BrowseForge profiles list --token "$TOKEN" --json
./BrowseForge sessions list --token "$TOKEN" --json

# MCP stdio mode
./BrowseForge --mcp
./BrowseForge mcp-stdio
```

Global CLI flags:

| Flag | Description |
|------|-------------|
| `--base-dir DIR` | Runtime directory for config, profiles, data, logs, and browser engines. Defaults to the binary directory. |
| `--config PATH` | Config file path. Relative paths are resolved from `--base-dir`. Defaults to `config.json`. |

Agent and CI integrations should prefer `--json` on `token`, `doctor`, `capabilities`, and `smoke` so outputs are stable to parse. Unknown commands return a non-zero exit code and print usage instead of starting the server.

See [docs/cli.md](docs/cli.md) for the full command reference, exit codes, JSON shapes, and agent integration checklist.

## Configuration

BrowseForge creates `config.json` on first launch:

```json
{
  "host": "127.0.0.1",
  "port": "19280",
  "profiles_dir": "profiles",
  "data_dir": "data",
  "log_file": "logs/server.log",
  "default_runtime_id": "camoufox",
  "runtimes": {
    "camoufox": {
      "enabled": true,
      "binary_path": "/path/to/browsers/camoufox/...",
      "family": "firefox",
      "display_name": "Camoufox"
    },
    "cloakbrowser": {
      "enabled": true,
      "binary_path": "/path/to/browsers/cloakbrowser/...",
      "family": "chromium",
      "display_name": "CloakBrowser",
      "settings": {
        "safe_gpu": false,
        "auto_safe_gpu_fallback": false,
        "isolated_runtime_cache": false,
        "repair_transient_cache_on_launch_failure": false,
        "fingerprint_platform": "auto",
        "fonts_dir": "",
        "storage_quota_mb": 0,
        "target_platform_policy": "warn",
        "extra_args": []
      }
    },
    "browseforge-chromium": {
      "enabled": true,
      "binary_path": "browsers/browseforge-chromium/chrome",
      "skip_auto_update": false,
      "family": "chromium",
      "display_name": "BrowseForge Chromium",
      "settings": {
        "safe_gpu": false,
        "auto_safe_gpu_fallback": true,
        "isolated_runtime_cache": true,
        "repair_transient_cache_on_launch_failure": true,
        "fingerprint_platform": "auto",
        "fonts_dir": "",
        "storage_quota_mb": 0,
        "target_platform_policy": "warn",
        "native_mode": "enabled",
        "plugins_pdf": "enabled",
        "extra_args": []
      }
    }
  },
  "fingerprint_dir": "data"
}
```

| Field | Description | Default |
|------|-------------|---------|
| `host` | Listen address | `127.0.0.1`; Docker auto-detects `0.0.0.0` |
| `port` | REST API and Dashboard port | `19280` |
| `no_sandbox` | Disable Chromium sandbox | `false`; Docker enables it automatically |
| `profiles_dir` | Profile data directory | `profiles` |
| `data_dir` | Token and fingerprint data directory | `data` |
| `log_file` | Server log file | `logs/server.log` |
| `default_runtime_id` | Default runtime selected by generated config and UI flows | `camoufox` |
| `runtimes.<id>.enabled` | Whether a runtime provider is available for profile creation/launch | Runtime-specific |
| `runtimes.<id>.binary_path` | Runtime provider binary path. Built-in/provider ids include `camoufox`, `cloakbrowser`, and alpha `browseforge-chromium`. For BrowseForge Chromium, point to the unpacked browser binary (`chrome`, `Chromium.app/Contents/MacOS/Chromium`, or `chrome.exe`), not the standalone wrapper. | Auto-detected or operator-provided |
| `runtimes.<id>.skip_auto_update` | Keep an already-installed runtime even when the bundled expected version changes. Startup fails if this is true and no binary can be found. `BROWSEFORGE_SKIP_BROWSER_AUTO_UPDATE=true` applies globally; `BROWSEFORGE_SKIP_<RUNTIME_ID>_AUTO_UPDATE=true` applies to one runtime with `-` replaced by `_`. | `false` |
| `runtimes.<id>.family` | Runtime browser family metadata: `firefox` or `chromium` | Provider default |
| `runtimes.<id>.display_name` | Runtime name shown by `/api/runtimes`, MCP `list_runtimes`, and the Dashboard create form | Provider default |
| `runtimes.cloakbrowser.settings.safe_gpu` | Add Chromium GPU-safe launch flags for Windows VM/headful compatibility | `false` |
| `runtimes.cloakbrowser.settings.auto_safe_gpu_fallback` | Keep the first launch unchanged, then retry once with safe GPU and isolated runtime cache only after a GPU/cache launch failure | `false` |
| `runtimes.cloakbrowser.settings.isolated_runtime_cache` | Use a per-launch Chromium disk cache directory under the profile runtime cache | `false` |
| `runtimes.cloakbrowser.settings.repair_transient_cache_on_launch_failure` | Remove rebuildable Chromium cache directories after GPU/cache launch failures before the automatic retry | `false` |
| `runtimes.cloakbrowser.settings.fingerprint_platform` | CloakBrowser fingerprint platform flag: `auto`, `macos`, `windows`, or `linux`; `auto` follows CloakBrowser wrapper defaults (`macos` on macOS, `windows` elsewhere) | `auto` |
| `runtimes.cloakbrowser.settings.fonts_dir` | Optional directory passed as `--fingerprint-fonts-dir`; use a target-platform font pack to improve font/canvas consistency | empty |
| `runtimes.cloakbrowser.settings.storage_quota_mb` | Optional `--fingerprint-storage-quota` override in MB; higher values can satisfy BrowserScan non-incognito checks but may trade off against FingerprintJS | `0` |
| `runtimes.cloakbrowser.settings.target_platform_policy` | Runtime/identity coherence policy: `strict` rejects high-risk target/platform combinations, `warn` logs them, `allow` skips the guardrail | `warn` |
| `runtimes.cloakbrowser.settings.extra_args` | Additional CloakBrowser/Chromium args. BrowseForge ignores args that would override profile, proxy, cache, or debugging ownership. | `[]` |
| `fingerprint_dir` | Fingerprint JSON directory | `data` |

The `runtimes.cloakbrowser.settings` block separates VM/runtime stability knobs from auditable fingerprint knobs. `safe_gpu`, `auto_safe_gpu_fallback`, `isolated_runtime_cache`, and `repair_transient_cache_on_launch_failure` are launch-stability policy. `fingerprint_platform`, `fonts_dir`, and `storage_quota_mb` are explicit CloakBrowser identity inputs instead of hidden `extra_args`. The block only affects the `cloakbrowser` runtime; `camoufox` profiles do not read these settings. For Windows VM environments where Chromium exits with GPU/cache errors such as `GPU process isn't usable` or `Unable to create cache`, use:


```json
{
  "runtimes": {
    "cloakbrowser": {
      "settings": {
        "auto_safe_gpu_fallback": true,
        "repair_transient_cache_on_launch_failure": true
      }
    }
  }
}
```

`browseforge-chromium` is the source-level Chromium alpha runtime consumed from `browseforge-runtime-chromium` release artifacts. It is enabled in the default Docker/GHCR config with `browsers/browseforge-chromium/chrome` so images can preinstall Camoufox plus BrowseForge Chromium and keep CloakBrowser as an opt-in/manual runtime. Release artifacts are currently unsigned alpha outputs; users must verify checksums and self-authorize unsigned binaries on macOS/Windows, and `camoufox` remains the default runtime for production profile creation until signing/notarization policy is resolved.

## MCP

BrowseForge provides MCP in two modes.

### Streamable HTTP

When the server is running, MCP HTTP is available at `http://127.0.0.1:19280/mcp` on the main BrowseForge service port.

Migration note: older clients that used the separate `:19281` MCP listener should update their URL to the main service port plus `/mcp`.

HTTP MCP uses the same Bearer token as the REST API:

```http
Authorization: Bearer <token>
```

The `web_search` MCP tool supports provider-backed search with `google` as the default engine and optional `bing` or `duckduckgo` engines. MCP also includes agent-ready page utilities for waiting on selectors, reading page state, filling forms, selecting/checking controls, pressing keys, managing cookies/downloads, returning temporary screenshot URLs for remote agents, running workflows, and diagnosing profile readiness. For agent prompting guidance, see [docs/agent-prompt-guide.md](docs/agent-prompt-guide.md).

Example remote MCP configuration:

```json
{
  "mcpServers": {
    "browseforge": {
      "url": "http://YOUR_SERVER:19280/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

### stdio

```bash
BrowseForge --mcp
```

Example Kiro/Claude command configuration:

```json
{
  "browseforge": {
    "command": "/path/to/BrowseForge",
    "args": ["--mcp"]
  }
}
```

## REST API

Base URL:

```text
http://127.0.0.1:19280/api
```

All API endpoints except `/api/status` require a Bearer token:

```http
Authorization: Bearer <token>
```

The token is generated on first server start and stored in `data/.api-token`.

See [API.md](API.md) for the full API reference.

## Playwright Connect

BrowseForge can expose a Playwright-compatible WebSocket endpoint for each running session.

```bash
curl http://127.0.0.1:19280/api/playwright/endpoint \
  -H "Authorization: Bearer $TOKEN"
```

Node.js example:

```javascript
import { firefox } from 'playwright';

const browser = await firefox.connect(
  'ws://YOUR_SERVER:19280/api/playwright/ws/sess_prof_xxx',
  { headers: { Authorization: 'Bearer YOUR_TOKEN' } }
);

const page = browser.contexts()[0].pages()[0];
await page.goto('https://example.com');
console.log(await page.title());
await browser.close();
```

Compatibility:

| Item | Policy |
|------|--------|
| Client version | Use a Playwright client compatible with BrowseForge's driver. Current target: Playwright `1.60.x`. |
| Docker | Expose only `19280` for Playwright proxy mode. |
| Authentication | Bearer token in proxy mode. |
| Anti-detect runtime | Playwright connect uses the internal Playwright protocol and does not expose CDP. |

## YAML Workflows

BrowseForge can execute workflow YAML through the REST API:

```yaml
name: Multi-account login
steps:
  - name: Create profile
    action: create_profile
    params: { name: "FB Account", runtime_id: camoufox, var: p1 }

  - name: Open browser
    action: open_browser
    profile_id: $p1

  - name: Navigate
    action: navigate
    profile_id: $p1
    params: { url: "https://facebook.com" }

  - name: Wait
    action: sleep
    params: { seconds: 30 }

  - name: Close
    action: close_browser
    profile_id: $p1
```

```bash
TOKEN=$(cat data/.api-token)
curl -X POST http://127.0.0.1:19280/api/workflow/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @examples/multi-login.yaml
```

Supported actions include `create_profile`, `open_browser`, `close_browser`, `navigate`, `click`, `type`, `eval`, `wait`, `screenshot`, and `sleep`.

## Profile Data

Each profile is stored under `profiles/`:

```text
profiles/
  prof_abc123/
    profile.json
    browser-data/
```

Treat profiles, backup ZIPs, exported profiles, cookies, and `data/.api-token` as sensitive.

## Platform Support

| Platform | BrowseForge | Camoufox | CloakBrowser | BrowseForge Chromium |
|------|:---:|:---:|:---:|:---:|
| macOS x64 | Supported | Supported | Supported | Artifact pending |
| macOS arm64 | Supported | Supported | Supported | Alpha artifact |
| Linux x64 | Supported | Supported | Supported | Alpha artifact |
| Linux arm64 | Binary supported | Supported | Supported | Alpha artifact |
| Windows x64 | Supported | Supported | Supported | Alpha artifact |

See [docs/platform-support.md](docs/platform-support.md) for detailed support notes.

For the current dual-browser anti-detection design, see [docs/dual-browser-architecture.md](docs/dual-browser-architecture.md).

## Build From Source

```bash
git clone https://github.com/nczz/BrowseForge.git
cd BrowseForge

npm install
node scripts/generate-fingerprints.js --browser firefox --os windows --count 500
node scripts/generate-fingerprints.js --browser firefox --os macos --count 500
node scripts/generate-fingerprints.js --browser chrome --os windows --count 500
node scripts/generate-fingerprints.js --browser chrome --os macos --count 500

go build -ldflags="-s -w" -o BrowseForge ./cmd/server
./BrowseForge
```

## Development Checks

```bash
go test -count=1 ./...
go vet ./...
bash -n scripts/release-preflight.sh scripts/release-push.sh
docker compose -f docker/docker-compose.yml config
```

For release publishing, use the guarded flow in [docs/release.md](docs/release.md). Do not create or push release tags manually.

## Architecture

```text
BrowseForge
  Main HTTP service (:19280)
    REST API (/api)
    MCP Streamable HTTP (/mcp)
    Web Dashboard (/)
    Playwright-compatible browser control

  Browser runtime
    Camoufox profiles
    CloakBrowser profiles
  Profile store
  Fingerprint data
```

## Responsible Use

BrowseForge is intended for legitimate QA, automation, privacy research, compatibility testing, and controlled browser operations. Do not use it for unauthorized access, credential abuse, spam, fraud, or evasion of systems you do not own or have permission to test.

## License

MIT. See [LICENSE](LICENSE).
