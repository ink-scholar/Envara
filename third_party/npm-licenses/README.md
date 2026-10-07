# Terminal and proxy dependencies

The local 0.3.0 candidate pins these direct additions. `package-lock.json` records
the official npm tarball integrity digests; `npm run native:prepare` copies the
installed packages' complete notices and their dependency notices to
`build/native/licenses/manifest.json`. The app bundles that directory as
`resources/licenses/npm`. This preparation step does not download browsers.

| Package | Version | Purpose | License | Official source |
| --- | --- | --- | --- | --- |
| node-pty | 1.1.0 | Native terminal process | MIT | [Microsoft node-pty](https://github.com/microsoft/node-pty/tree/v1.1.0) |
| socks | 2.8.10 | SOCKS5 terminal proxy connection | MIT | [SocksClient](https://github.com/JoshGlazebrook/socks) |
| https-proxy-agent | 9.1.0 | HTTP/HTTPS CONNECT agent | MIT | [proxy-agents](https://github.com/TooTallNate/proxy-agents/tree/main/packages/https-proxy-agent) |
| socks-proxy-agent | 10.1.0 | SOCKS HTTP/HTTPS agent | MIT | [proxy-agents](https://github.com/TooTallNate/proxy-agents/tree/main/packages/socks-proxy-agent) |
| ipaddr.js | 2.5.0 | IP address classification | MIT | [ipaddr.js](https://github.com/whitequark/ipaddr.js) |
| @xterm/xterm | 6.0.0 | Renderer terminal | MIT | [xterm.js](https://github.com/xtermjs/xterm.js) |
| @xterm/addon-fit | 0.11.0 | Renderer terminal size | MIT | [fit addon](https://github.com/xtermjs/xterm.js/tree/master/addons/addon-fit) |
| @electron/rebuild | 4.2.1 | Development build tool | MIT | [Electron rebuild](https://github.com/electron/rebuild/tree/v4.2.1) |

The renderer packages are compiled by Vite. The rebuild tool is a development
dependency; the app never installs Go, Node, or compiler toolchains at runtime.
node-pty 1.1.0 uses Node-API. A build checks actual PTY input/output/resize/exit in
the pinned Electron runtime and compiles only node-pty from source if that check
fails. `npm run native:rebuild` explicitly requests a source rebuild. Windows and
Linux must be built and verified on their native CI runner; a macOS check does
not establish their acceptance.

The complete node-pty package is unpacked so its native modules, spawn helper,
Windows worker, winpty fallback, and Microsoft Terminal ConPTY files retain
filesystem paths. winpty's distributed MIT license is copied separately. The
bundled ConPTY/OpenConsole files carry the supplementary Microsoft Terminal MIT
notice obtained from the [official repository](https://github.com/microsoft/terminal/blob/main/LICENSE).

proxy-agent-negotiate 1.1.0 declares MIT in its npm metadata and identifies Nathan
Rajlich as its author, but its npm tarball contains no standalone license file.
`proxy-agent-negotiate-NOTICE.txt` explicitly records that gap and retains the MIT
text distributed by the same maintainer with https-proxy-agent 9.1.0. It is an
Envara supplementary notice. Kerberos is an optional peer of that package and is
not installed or used by Envara's explicit Basic proxy connections.
