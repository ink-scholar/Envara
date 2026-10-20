// A host-key observation, never trust or login. OpenSSH's KnownHostsCommand
// captures the offered public key and deliberately fails host verification.
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { validateSshTarget, sameSshTarget } from './terminal-ssh-proxy.mjs';
import { createSshDirectTransport } from './terminal-ssh-direct.mjs';
import { parseSshPublicKey } from './terminal-ssh-key.mjs';
import { terminalFenceProfile, TERMINAL_FENCE_EXECUTABLE } from './terminal-network-fence.mjs';
import { captureTerminalProcess, closeTerminalProcess } from './terminal-process.mjs';

const fail = code => Object.assign(new Error('The SSH host key could not be observed safely.'), { code });
const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const safePath = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value &&
  value.length <= 4096 && !/[\x00-\x1f\x7f]/.test(value);
async function directoryIdentity(directory) {
  if (!safePath(directory)) throw fail('SSH_HOST_PROBE_INVALID');
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077 ||
      process.getuid && info.uid !== process.getuid() || await realpath(directory) !== directory) throw fail('SSH_HOST_PROBE_INVALID');
  return info;
}
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;
const captureSource = String.raw`const fs=require('node:fs');
const [file,nonce,reason,type,key]=process.argv.slice(2);
if(reason==='ORDER')process.exit(0);
if(reason!=='HOSTNAME'||!/^([a-f0-9]{64})$/.test(nonce)||
 !['ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'].includes(type)||
 typeof key!=='string'||key.length>24576||! /^[A-Za-z0-9+/]+={0,2}$/.test(key))process.exit(18);
try {fs.writeFileSync(file,JSON.stringify({version:1,nonce,type,key}),{mode:0o600,flag:'wx'});}catch{process.exit(19);}
// Empty stdout and an unsuccessful helper prohibit trusting this observation.
process.exit(17);
`;

/** The connector is main-process authority for this exact target and route.
 * It must return its selected connected socket or fail; there is no fallback. */
export async function probeSshHostKey({ target, routeBinding, connector, isActive, signal,
  nodeExecutable = process.execPath, root, hostHome, timeoutMs = 10000, createTransport = createSshDirectTransport } = {}) {
  let checked;
  try {
    checked = validateSshTarget(target?.host, target?.port);
    if (process.platform !== 'darwin' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000 ||
        typeof connector !== 'function' || typeof createTransport !== 'function' || typeof isActive !== 'function' || typeof routeBinding !== 'string' ||
        !routeBinding || routeBinding.length > 256 || /[\x00-\x1f\x7f]/.test(routeBinding) ||
        !safePath(nodeExecutable) || !safePath(hostHome)) throw fail('SSH_HOST_PROBE_INVALID');
    await directoryIdentity(root);
    const executable = await lstat(nodeExecutable), sandbox = await lstat(TERMINAL_FENCE_EXECUTABLE);
    if (!executable.isFile() || executable.isSymbolicLink() || executable.mode & 0o022 || await realpath(nodeExecutable) !== nodeExecutable ||
        !sandbox.isFile() || sandbox.isSymbolicLink() || sandbox.uid !== 0 || sandbox.mode & 0o022) throw fail('SSH_HOST_PROBE_INVALID');
  } catch { throw fail('SSH_HOST_PROBE_INVALID'); }
  const active = () => { try { return !signal?.aborted && isActive() === true; } catch { return false; } };
  if (signal?.aborted) throw fail('SSH_HOST_PROBE_CANCELLED');
  if (!active()) throw fail('SSH_HOST_PROBE_REVOKED');
  const ownedDirectory = await mkdtemp(path.join(root, 'probe-'));
  const ownedIdentity = await directoryIdentity(ownedDirectory);
  const publicDirectory = path.join(ownedDirectory, 'public');
  const outputDirectory = path.join(ownedDirectory, 'capture');
  const home = path.join(ownedDirectory, 'home');
  let transport, partialTransportCleanup, child, identity, exit, cleanupPending, failure, result, deadlineTimer, revokeTimer;
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once:true });
  const cleanup = async () => {
    controller.abort();
    let uncertain = false;
    if(partialTransportCleanup){try{await partialTransportCleanup();partialTransportCleanup=null;}catch{uncertain=true;}}
    if (transport) { try { await transport.dispose(); } catch { uncertain = true; } }
    if (identity && child) {
      try { if ((await closeTerminalProcess({ pty:{pid:child.pid}, identity, timeoutMs:2000 })).ok !== true) uncertain = true; }
      catch { uncertain = true; }
    } else if (child && child.exitCode === null && child.signalCode === null) {
      // The launch gate never permits OpenSSH before capture. Closing its pipe
      // lets only that waiting shell exit; no unverified PID is signalled.
      child.stdin?.destroy();
      if (exit) await Promise.race([exit,delay(1000)]);
      if (child.exitCode === null && child.signalCode === null) uncertain = true;
    }
    if (uncertain) throw fail('SSH_HOST_PROBE_CLEANUP_FAILED');
    if (!sameFile(ownedIdentity, await directoryIdentity(ownedDirectory))) throw fail('SSH_HOST_PROBE_CLEANUP_FAILED');
    await chmod(publicDirectory,0o700).catch(error=>{if(error.code!=='ENOENT')throw error;});
    await rm(ownedDirectory,{recursive:true});
  };
  try {
    for (const directory of [publicDirectory,outputDirectory,home]) await mkdir(directory,{mode:0o700});
    const direct = path.join(publicDirectory,'terminal-ssh-direct.mjs');
    const proxy = path.join(publicDirectory,'terminal-ssh-proxy.mjs');
    const helper = path.join(publicDirectory,'capture.cjs');
    for (const [file,source] of [[direct,new URL('./terminal-ssh-direct.mjs',import.meta.url)],[proxy,new URL('./terminal-ssh-proxy.mjs',import.meta.url)]])
      await writeFile(file,await readFile(source),{mode:0o400,flag:'wx'});
    await writeFile(helper,captureSource,{mode:0o400,flag:'wx'});
    const alias = 'envara-host-key-probe', nonce=randomBytes(32).toString('hex');
    const captureFile=path.join(outputDirectory,'key.json');
    transport=await createTransport({directory:ownedDirectory,connections:[{alias,...checked}],
      isActive:() => !controller.signal.aborted && active(), connectTimeoutMs:Math.min(timeoutMs,10000),
      connect:options=>{
        if (!active() || controller.signal.aborted || !sameSshTarget(options,checked)) throw fail('SSH_HOST_PROBE_REVOKED');
        return connector({...options,signal:controller.signal});
      }});
    const command=`${shellQuote(nodeExecutable)} ${shellQuote(direct)} --alias ${alias}`.replaceAll('%','%%');
    const knownCommand=`${shellQuote(nodeExecutable)} ${shellQuote(helper)} ${shellQuote(captureFile)} ${nonce}`.replaceAll('%','%%')+' %I %t %K';
    const config=path.join(publicDirectory,'ssh_config');
    await writeFile(config,[
      `Host ${alias}`,`  HostName ${checked.host}`,`  Port ${checked.port}`,'  User envara-host-key-probe',
      '  UserKnownHostsFile /dev/null','  GlobalKnownHostsFile /dev/null','  StrictHostKeyChecking yes',
      '  VerifyHostKeyDNS no','  CheckHostIP no','  UpdateHostKeys no','  CanonicalizeHostname no',
      '  HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256',
      '  IdentityFile none','  CertificateFile none','  IdentityAgent none','  AddKeysToAgent no','  UseKeychain no','  PKCS11Provider none',
      '  PubkeyAuthentication no','  PasswordAuthentication no','  KbdInteractiveAuthentication no','  GSSAPIAuthentication no',
      '  HostbasedAuthentication no','  PreferredAuthentications none','  BatchMode yes','  NumberOfPasswordPrompts 0',
      '  ForwardAgent no','  ForwardX11 no','  ClearAllForwardings yes','  PermitLocalCommand no',
      '  ControlMaster no','  ControlPath none','  ControlPersist no','  EscapeChar none','  EnableEscapeCommandline no',
      '  RequestTTY no','  SessionType none','  ConnectionAttempts 1',`  ConnectTimeout ${Math.max(1,Math.ceil(timeoutMs/1000))}`,
      `  ProxyCommand ${command}`,`  KnownHostsCommand ${knownCommand}`,'',
    ].join('\n'),{mode:0o400,flag:'wx'});
    await chmod(publicDirectory,0o500);
    const profile=terminalFenceProfile({restrictDeviceIdentifiers:true,sshProtection:{agentRoot:ownedDirectory,
      protectedPaths:[ownedDirectory,path.join(hostHome,'.ssh')],readablePaths:[publicDirectory],
      readOnlyPaths:[publicDirectory,nodeExecutable],allowedSockets:[transport.socket]}})+
      `\n(allow file-write* (subpath ${JSON.stringify(outputDirectory)}))\n(allow file-read-metadata (subpath ${JSON.stringify(outputDirectory)}))\n(deny network-outbound)\n(allow network-outbound (remote unix-socket (literal ${JSON.stringify(transport.socket)})))`;
    const environment={PATH:'/usr/bin:/bin:/usr/sbin:/sbin',HOME:home,USERPROFILE:home,TMPDIR:home+'/',
      LANG:'C',LC_ALL:'C',TZ:'UTC',SHELL:'/bin/sh',ELECTRON_RUN_AS_NODE:'1',
      ENVARA_SSH_DIRECT_SOCKET:transport.socket,ENVARA_SSH_DIRECT_TOKEN:transport.token};
    if (!active()) throw fail('SSH_HOST_PROBE_REVOKED');
    // Capture a waiting child before exec, eliminating fast-exit PID ambiguity.
    child=spawn('/bin/sh',['-c','IFS= read -r ready; [ "$ready" = start ] || exit 1; exec "$@"','envara-probe',
      TERMINAL_FENCE_EXECUTABLE,'-p',profile,'/usr/bin/ssh','-F',config,'-n','-N','-T',alias],
      {cwd:home,env:environment,detached:true,stdio:['pipe','pipe','pipe']});
    exit=new Promise((resolve,reject)=>{child.once('error',()=>reject(fail('SSH_HOST_PROBE_FAILED')));child.once('close',(code,signal)=>resolve({code,signal}));});
    void exit.catch(()=>{});
    // Bound output, retaining neither server banners nor endpoint diagnostics.
    let outputBytes=0;
    const drain=chunk=>{outputBytes+=chunk.length;if(outputBytes>65536)controller.abort();};
    child.stdout.on('data',drain);child.stderr.on('data',drain);
    identity=await captureTerminalProcess(child.pid);
    const interrupted=new Promise((_,reject)=>{
      controller.signal.addEventListener('abort',()=>reject(fail(signal?.aborted?'SSH_HOST_PROBE_CANCELLED':'SSH_HOST_PROBE_REVOKED')),{once:true});
      deadlineTimer=setTimeout(()=>reject(fail('SSH_HOST_PROBE_TIMEOUT')),timeoutMs);
      revokeTimer=setInterval(()=>{if(!active())controller.abort();},50);revokeTimer.unref();
    });
    const completion=Promise.race([exit,interrupted]);
    if (!active()) controller.abort();
    else child.stdin.end('start\n');
    const completed=await completion;
    clearTimeout(deadlineTimer);clearInterval(revokeTimer);
    if (!active()) throw fail(signal?.aborted?'SSH_HOST_PROBE_CANCELLED':'SSH_HOST_PROBE_REVOKED');
    if (completed.code!==255 || completed.signal!==null || outputBytes>65536) throw fail('SSH_HOST_PROBE_FAILED');
    const info=await lstat(captureFile);
    if (!info.isFile()||info.isSymbolicLink()||info.nlink!==1||info.mode&0o077||info.size<1||info.size>32768||
        process.getuid&&info.uid!==process.getuid())throw fail('SSH_HOST_PROBE_FAILED');
    const file=await open(captureFile,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    let observation;
    try {const held=await file.stat();if(!sameFile(info,held)||held.size!==info.size)throw fail('SSH_HOST_PROBE_FAILED');
      const buffer=Buffer.alloc(32769);const {bytesRead}=await file.read(buffer,0,buffer.length,0);
      if(bytesRead!==info.size)throw fail('SSH_HOST_PROBE_FAILED');observation=JSON.parse(buffer.subarray(0,bytesRead).toString());
    } finally {await file.close();}
    if (!observation||Object.keys(observation).sort().join(',')!=='key,nonce,type,version'||observation.version!==1||observation.nonce!==nonce)
      throw fail('SSH_HOST_PROBE_FAILED');
    const key=parseSshPublicKey(`${observation.type} ${observation.key}`);
    result={hostKeys:[key],routeBinding,unverified:true};
  } catch(error) {
    // A transport can own a bound socket before its factory returns. Preserve
    // its cleanup capability even though assignment to transport never ran.
    if(typeof error?.sshCleanup==='function')partialTransportCleanup=error.sshCleanup;
    failure=fail(/^SSH_HOST_PROBE_(?:INVALID|CANCELLED|TIMEOUT|REVOKED)$/.test(error?.code??'')?error.code:'SSH_HOST_PROBE_FAILED');
  } finally {
    clearTimeout(deadlineTimer);clearInterval(revokeTimer);signal?.removeEventListener('abort',abort);
    try {await cleanup();}catch {cleanupPending=async()=>cleanup();}
  }
  if(cleanupPending){const error=fail('SSH_HOST_PROBE_CLEANUP_FAILED');error.cleanupRequired=true;error.sshCleanup=cleanupPending;throw error;}
  if(failure)throw failure;
  if(!active())throw fail(signal?.aborted?'SSH_HOST_PROBE_CANCELLED':'SSH_HOST_PROBE_REVOKED');
  return result;
}
