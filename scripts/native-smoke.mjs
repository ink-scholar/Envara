import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import electron from 'electron';

const dataDir = await mkdtemp(path.join(os.tmpdir(), 'envara-native-smoke-'));
const artifactDir = path.resolve('test-artifacts');
await mkdir(artifactDir, { recursive: true });
const env = { ...process.env, ENVARA_SMOKE: '1', ENVARA_SMOKE_DATA: dataDir, ENVARA_SMOKE_ARTIFACTS: artifactDir, ENVARA_SMOKE_ENGINE_DIR: path.join(artifactDir, 'engine-cache') };
delete env.ELECTRON_RUN_AS_NODE;
const processHandle = spawn(electron, ['.'], { stdio: 'inherit', env });
const timer = setTimeout(() => { console.error('Native smoke timed out.'); processHandle.kill('SIGTERM'); }, 10 * 60 * 1000);
const code = await new Promise(resolve => processHandle.on('exit', resolve));
clearTimeout(timer);
if (code !== 0) process.exitCode = code || 1;
else {
  const result = JSON.parse(await readFile(path.join(artifactDir, 'native-smoke.json'), 'utf8'));
  console.log(JSON.stringify(result, null, 2));
}
