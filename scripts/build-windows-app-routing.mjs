import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const source = path.join(root, 'native/windows-app-routing');

for (const [arch, goarch] of [['x64', 'amd64'], ['arm64', 'arm64']]) {
  const output = path.join(root, 'build/app-routing/win32', arch);
  mkdirSync(output, { recursive: true });
  const result = spawnSync('go', ['build', '-trimpath', '-ldflags=-s -w', '-o', path.join(output, 'EnvaraAppRouting.exe'), './cmd/envara-app-routing'], {
    cwd: source,
    env: { ...process.env, GOOS: 'windows', GOARCH: goarch, CGO_ENABLED: '0' },
    stdio: 'inherit',
  });
  if (result.error || result.status !== 0) {
    throw new Error(`Windows ${arch} helper build failed; install a supported Go compiler.`, { cause: result.error });
  }
  copyFileSync(path.join(source, 'THIRD-PARTY-NOTICES.txt'), path.join(output, 'THIRD-PARTY-NOTICES.txt'));
  console.log(`Built Windows ${arch} helper source; driver signing and Windows acceptance remain required.`);
}
