import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRequire } from 'node:module';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const require = createRequire(import.meta.url);
test('owned real Electron PTY accepts the attachment path only as pending input until explicit Enter', { skip: process.platform !== 'darwin', timeout: 15000 }, async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-attachment-pty-')));
  const input = 'stty -echo; printf "%s\\n" ATTACHMENT_READY; IFS= read -r line; printf "%s" "$line" > "$HOME/received"; printf "%s\\n" ATTACHMENT_DONE; exit\r';
  const worker = `
import assert from 'node:assert/strict';
import path from 'node:path';
import {mkdir,readFile,stat} from 'node:fs/promises';
import {EventEmitter} from 'node:events';
import {createRequire} from 'node:module';
import {TerminalAttachments} from ${JSON.stringify(new URL('../electron/terminal-attachments.mjs', import.meta.url).href)};
const require=createRequire(${JSON.stringify(import.meta.url)}), pty=require('node-pty');
const root=${JSON.stringify(root)}, profilesDir=path.join(root,'profiles'), home=path.join(root,'home');
await mkdir(profilesDir);await mkdir(path.join(profilesDir,'owned'));await mkdir(home);
const child=pty.spawn('/bin/zsh',['-f'],{name:'xterm-256color',cols:80,rows:24,cwd:home,env:{HOME:home,ZDOTDIR:home,PATH:'/usr/bin:/bin',TERM:'xterm-256color'}});
let output='',exited=false;child.onData(data=>{output+=data});child.onExit(()=>{exited=true});
const wait=async check=>{const until=Date.now()+5000;while(!check()){if(Date.now()>until)throw new Error('owned PTY fixture deadline');await new Promise(resolve=>setTimeout(resolve,5));}};
try {
  child.write(${JSON.stringify(input)});
  await wait(()=>child.process==='zsh'&&output.includes('ATTACHMENT_READY\\r\\n'));
  const sessionId='term_'+'a'.repeat(32),transferId='b'.repeat(32);
  const session={sessionId,profileId:'owned',kind:'shell',status:'running',pty:child,abortController:new AbortController()};
  const owner=Object.assign(new EventEmitter(),{isDestroyed:()=>false});
  const terminal={profilesDir,ready:Promise.resolve(),session:()=>session,write:async({data})=>{child.write(data);return {accepted:true}}};
  assert.equal(child.process,'zsh');
  const attachments=new TerminalAttachments({terminal});
  const result=await attachments.stage({sessionId,transferId,files:[{name:'proof.txt',bytes:new Uint8Array([1,2,3])}]},{window:owner});
  await attachments.finish({sessionId,transferId,accepted:true},{window:owner});
  await new Promise(resolve=>setTimeout(resolve,80));
  assert.equal(await stat(path.join(home,'received')).then(()=>true,()=>false),false,'no automatic Enter');
  child.write('\\r');await wait(()=>exited);
  assert.equal(await readFile(path.join(home,'received'),'utf8'),result.quotedPaths);
  assert.deepEqual([...await readFile(result.quotedPaths.slice(1,-2))],[1,2,3]);
  process.stdout.write('ATTACHMENT_PTY_OK\\n');
} finally { if(!exited){child.kill();await wait(()=>exited).catch(()=>child.kill('SIGKILL'));} }
`;
  try {
    const { stdout } = await promisify(execFile)(require('electron'), ['--input-type=module', '-e', worker], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, timeout: 12000, maxBuffer: 65536 });
    assert.match(stdout, /ATTACHMENT_PTY_OK/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
