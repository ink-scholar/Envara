import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Run this copied script inside the extracted corresponding-source directory.
// Dependencies are vendored, so the build does not require a Go module service.
const directory = path.dirname(fileURLToPath(import.meta.url));
const version = 'v1.19.32';
const flags = [
  '-extldflags --static',
  `-X github.com/metacubex/mihomo/constant.Version=${version}`,
  '-X github.com/metacubex/mihomo/constant.BuildTime=Envara-corresponding-source',
  '-w -s -buildid=',
].join(' ');
const child = spawn('go', ['build', '-mod=vendor', '-tags', 'with_gvisor', '-trimpath', '-ldflags', flags,
  '-o', process.platform === 'win32' ? 'mihomo-rebuilt.exe' : 'mihomo-rebuilt', '.'], {
  cwd: directory, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0', GOFLAGS: '', GOPROXY: 'off' },
});
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
