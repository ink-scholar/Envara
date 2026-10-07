import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import electron from 'electron';

const dataDir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-workspace-smoke-')));
const selectedDirectory = path.join(dataDir, 'selected-workspace'); await mkdir(selectedDirectory, { mode: 0o700 });
const artifactDir = path.resolve('test-artifacts/workspace-smoke'); await mkdir(artifactDir, { recursive: true });
await rm(path.join(artifactDir, 'workspace-smoke.json'), { force: true });
const env = { ...process.env, ENVARA_WORKSPACE_SMOKE: '1', ENVARA_WORKSPACE_SMOKE_DATA: dataDir,
  ENVARA_WORKSPACE_SMOKE_CWD: selectedDirectory, ENVARA_WORKSPACE_SMOKE_ARTIFACTS: artifactDir };
for (const key of ['ELECTRON_RUN_AS_NODE', 'ENVARA_BACKEND', 'ENVARA_SMOKE', 'ENVARA_DEV_URL', 'ENVARA_DEV_DATA']) delete env[key];
const child = spawn(electron, ['.'], { stdio: 'inherit', env, cwd: path.resolve('.') });
let timedOut = false;
const timer = setTimeout(() => { timedOut = true; console.error('Workspace smoke exceeded 120 seconds.'); child.kill('SIGTERM'); }, 120000);
const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
clearTimeout(timer);
let result;
try { result = JSON.parse(await readFile(path.join(artifactDir, 'workspace-smoke.json'), 'utf8')); }
catch (error) { console.error(`Workspace smoke produced no readable report: ${error.message}`); }
if (result) console.log(JSON.stringify(result, null, 2));
console.log(`Temporary workspace retained at ${dataDir}`);
if (timedOut || code !== 0 || !result?.passed) process.exitCode = 1;
