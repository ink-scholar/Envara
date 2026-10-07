# Prototype Instructions

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

The user requires sensible features and layout, a source-grounded BrowseForge capability comparison, and multiple browser providers. Verify real desktop and browser behavior before claiming completion. Publication is paused at the user's request: do not push, tag, publish a release, or re-enable automatic releases until the user authorizes it. Existing public source remains available; installation releases are drafts.

Each environment should support an embedded terminal, a user-selected local working directory, and separate tool configuration/history. Detect the actual authenticated proxy egress and its timezone; do not substitute the proxy entry address or a default timezone for a successful detection. Browser and terminal should share the resolved workspace context. Keep timezone and configuration changes scoped to owned child processes. Configuration isolation is not an OS sandbox, and neither IP geolocation nor account isolation guarantees a residential street address or protection from service suspension. Keep the established three-column layout and use a collapsible terminal panel.

The terminal must support dragging its height, expanding into the main area and restoring, and opening an independent window. Duplicating a terminal creates an independent process in the same environment, sharing its selected directory, proxy, timezone, tool configuration and history. Do not replay running commands or duplicate process state. Closing a terminal view leaves its session available; explicitly closing a session ends that process.

AnyTLS nodes must work through an application-owned, bundled proxy core without requiring a separately configured Clash client. Preserve node SNI, ALPN, client fingerprint and UDP settings; verify TLS certificates by default. Browser and terminal must use the same managed node route, with separate routes for different node identities. Do not silently fall back to direct traffic, including when a raw REST or MCP caller bypasses the desktop manager. Keep runtime listener credentials out of persistent BrowseForge profiles and exported configuration. User node passwords and subscription tokens must never enter source, public examples or diagnostic output.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

Build app UI in `src/`. Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs`, and `tests/sites-worker.test.mjs` intact so the same local prototype can be handed to Sites. Before a Sites handoff, run `npm run build` and `npm run test:sites`; the build must leave `dist/client/index.html`, `dist/server/index.js`, and `dist/.openai/hosting.json`.
