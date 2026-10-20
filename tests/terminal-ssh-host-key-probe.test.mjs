import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir,mkdtemp,readdir,realpath,rm,writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { probeSshHostKey } from '../electron/terminal-ssh-host-key-probe.mjs';
import { parseSshPublicKey } from '../electron/terminal-ssh-key.mjs';
const run=promisify(execFile),darwin=process.platform==='darwin';
const environment={PATH:'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',LANG:'C',LC_ALL:'C'};
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const wait=async predicate=>{const until=Date.now()+5000;while(Date.now()<until){if(await predicate())return;await delay(20);}throw new Error('Owned fixture deadline');};
let directory,root,hostHome,nodeExecutable,python,server,serverPort,serverKey,proxy,proxyPort;
let proxyMode='accept';const peers=new Set();
const stats={connections:0,active:0,authCallbacks:0,channels:0,proxyConnections:0,proxyAuthorized:0};
const credentials=randomBytes(24).toString('hex');
const target={host:'ssh-probe-fixture.invalid',port:1030,user:'not-sent-to-server'};
const source=String.raw`import json,socket,sys,threading,time,paramiko
key=paramiko.RSAKey.generate(2048)
lock=threading.Lock()
def emit(event,**values):
 with lock: print(json.dumps(dict(event=event,**values)),flush=True)
class Server(paramiko.ServerInterface):
 def check_auth_none(self,user):emit('auth');return paramiko.AUTH_SUCCESSFUL
 def check_auth_password(self,user,password):emit('auth');return paramiko.AUTH_SUCCESSFUL
 def check_auth_publickey(self,user,key):emit('auth');return paramiko.AUTH_SUCCESSFUL
 def check_auth_interactive(self,user,submethods):emit('auth');return paramiko.AUTH_SUCCESSFUL
 def check_channel_request(self,kind,chanid):emit('channel');return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(8)
emit('ready',port=listener.getsockname()[1],publicKey=key.get_name()+' '+key.get_base64())
def client(sock):
 emit('accepted')
 transport=paramiko.Transport(sock);transport.add_server_key(key)
 try:
  transport.start_server(server=Server())
  while transport.is_active():time.sleep(.02)
 except Exception:pass
 finally:transport.close();sock.close();emit('closed')
def stop():
 sys.stdin.buffer.read();listener.close()
threading.Thread(target=stop,daemon=True).start()
try:
 while True:
  sock,address=listener.accept();threading.Thread(target=client,args=(sock,),daemon=True).start()
except OSError:pass
`;
before(async context=>{
 if(!darwin)return;
 try{await run('python3',['-I','-c','import paramiko'],{env:environment,timeout:5000});}catch{context.skip('An existing Python Paramiko is required for this opt-in native fixture; nothing is downloaded.');return;}
 directory=await realpath(await mkdtemp('/private/tmp/evhk-'));root=path.join(directory,'probes');hostHome=path.join(directory,'home');
 await mkdir(root,{mode:0o700});await mkdir(hostHome,{mode:0o700});nodeExecutable=await realpath(process.execPath);
 python=path.join(directory,'server.py');await writeFile(python,source,{mode:0o600});
 server=spawn('python3',['-I',python],{env:{...environment,HOME:hostHome,TMPDIR:directory+'/'},cwd:directory,stdio:['pipe','pipe','pipe']});
 server.stderr.resume();let buffered='';server.stdout.on('data',chunk=>{buffered+=chunk;assert(buffered.length<65536);for(;;){const at=buffered.indexOf('\n');if(at<0)break;const line=buffered.slice(0,at);buffered=buffered.slice(at+1);const item=JSON.parse(line);
 if(item.event==='ready'){serverPort=item.port;serverKey=parseSshPublicKey(item.publicKey);}
 if(item.event==='accepted'){stats.connections++;stats.active++;}if(item.event==='closed')stats.active--;
 if(item.event==='auth')stats.authCallbacks++;if(item.event==='channel')stats.channels++;}});
 await wait(()=>serverPort);
 proxy=net.createServer({allowHalfOpen:true},socket=>{
  peers.add(socket);socket.on('error',()=>{});socket.once('close',()=>peers.delete(socket));stats.proxyConnections++;
  let buffer=Buffer.alloc(0);socket.on('data',function headers(chunk){buffer=Buffer.concat([buffer,chunk]);if(buffer.length>16384){socket.destroy();return;}const at=buffer.indexOf('\r\n\r\n');if(at<0)return;socket.pause();socket.off('data',headers);
   const text=buffer.subarray(0,at).toString('latin1');
   if(proxyMode==='refuse'||!text.startsWith('CONNECT ssh-probe-fixture.invalid:1030 HTTP/1.1\r\n')||!text.split('\r\n').includes('Proxy-Authorization: Basic '+Buffer.from('fixture:'+credentials).toString('base64'))){socket.end('HTTP/1.1 407 Refused\r\nContent-Length: 0\r\n\r\n');return;}
   stats.proxyAuthorized++;const upstream=net.connect({host:'127.0.0.1',port:serverPort,allowHalfOpen:true});peers.add(upstream);upstream.on('error',()=>socket.destroy());upstream.once('close',()=>peers.delete(upstream));socket.once('close',()=>upstream.destroy());
   upstream.once('connect',()=>{socket.write('HTTP/1.1 200 Connected\r\n\r\n');const tail=buffer.subarray(at+4);if(tail.length)upstream.write(tail);socket.pipe(upstream);upstream.pipe(socket);socket.resume();});
  });
 });
 await new Promise((resolve,reject)=>{proxy.once('error',reject);proxy.listen(0,'127.0.0.1',resolve);});proxyPort=proxy.address().port;
});
after(async context=>{
 for(const socket of peers)socket.destroy();if(proxy)await new Promise(resolve=>proxy.close(resolve));
 if(server){const exit=new Promise(resolve=>server.once('close',resolve));server.stdin.end();await Promise.race([exit,delay(3000)]);if(server.exitCode===null&&server.signalCode===null){server.kill('SIGTERM');await exit;}}
 if(directory)await rm(directory,{recursive:true,force:true});
 if(directory){assert.equal(stats.authCallbacks,0);assert.equal(stats.channels,0);}
 if(directory)context.diagnostic(JSON.stringify({schema:'envara.ssh-host-key-probe-native/v1',authCallbacks:stats.authCallbacks,channelRequests:stats.channels,proxyAuthorized:stats.proxyAuthorized,serverExited:server.exitCode!==null||server.signalCode!==null,remainingProxySockets:peers.size,ownedTemporaryRemoved:true}));
});
const options=extra=>({target,routeBinding:'synthetic-route-generation',root,hostHome,nodeExecutable,isActive:()=>true,timeoutMs:5000,...extra});
const ownedClean=async()=>{await wait(()=>stats.active===0);assert.equal(stats.authCallbacks,0);assert.equal(stats.channels,0);assert.deepEqual(await readdir(root),[]);};
// A connector is fixture-only here; production uses the shared main-process
// route-socket connector. These assertions ensure exact target authority.
const hostConnector=options=>{assert.equal(options.host,target.host);assert.equal(options.port,target.port);return net.connect({host:'127.0.0.1',port:serverPort,allowHalfOpen:true});};

test('native host observation captures public key before even permissive none authentication',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 const result=await probeSshHostKey(options({connector:hostConnector}));
 assert.deepEqual(result,{hostKeys:[serverKey],routeBinding:'synthetic-route-generation',unverified:true});
 await ownedClean();
});

test('native environment route uses authenticated CONNECT and returns the same untrusted key',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 const {openSshRouteSocket}=await import('../electron/terminal-ssh-route-socket.mjs');
 const result=await probeSshHostKey(options({connector:socketOptions=>openSshRouteSocket({target:socketOptions,routeContext:{route:{kind:'environment',profileId:'synthetic_environment'},proxyUrl:`http://fixture:${credentials}@127.0.0.1:${proxyPort}`,isActive:()=>true},signal:socketOptions.signal})}));
 assert.equal(result.hostKeys[0].fingerprint,serverKey.fingerprint);assert(stats.proxyAuthorized>0);await ownedClean();
});

test('route refusal cannot fall back to the reachable host connector',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 const before=stats.connections;proxyMode='refuse';
 const {openSshRouteSocket}=await import('../electron/terminal-ssh-route-socket.mjs');
 try{await assert.rejects(probeSshHostKey(options({connector:socketOptions=>openSshRouteSocket({target:socketOptions,routeContext:{route:{kind:'environment',profileId:'synthetic_environment'},proxyUrl:`http://fixture:${credentials}@127.0.0.1:${proxyPort}`,isActive:()=>true},signal:socketOptions.signal})})),{code:'SSH_HOST_PROBE_FAILED'});}finally{proxyMode='accept';}
 assert.equal(stats.connections,before);await ownedClean();
});

test('revoked and cancelled probes refuse before creating any connection',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 const before=stats.connections;const controller=new AbortController();controller.abort();
 await assert.rejects(probeSshHostKey(options({connector:hostConnector,signal:controller.signal})),{code:'SSH_HOST_PROBE_CANCELLED'});
 await assert.rejects(probeSshHostKey(options({connector:hostConnector,isActive:()=>false})),{code:'SSH_HOST_PROBE_REVOKED'});
 assert.equal(stats.connections,before);await ownedClean();
});

test('timeout and active cancellation close owned transports without authentication',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 const blackhole=net.createServer(socket=>{peers.add(socket);socket.on('error',()=>{});socket.once('close',()=>peers.delete(socket));});
 await new Promise(resolve=>blackhole.listen(0,'127.0.0.1',resolve));
 const connector=()=>net.connect({host:'127.0.0.1',port:blackhole.address().port});
 try{
  await assert.rejects(probeSshHostKey(options({connector,timeoutMs:200})),{code:'SSH_HOST_PROBE_TIMEOUT'});
  const controller=new AbortController();const pending=probeSshHostKey(options({connector,signal:controller.signal}));
  const timer=setTimeout(()=>controller.abort(),150);try{await assert.rejects(pending,{code:'SSH_HOST_PROBE_CANCELLED'});}finally{clearTimeout(timer);}
 }finally{for(const socket of peers)socket.destroy();await new Promise(resolve=>blackhole.close(resolve));}
 await ownedClean();
});


test('route-generation revocation interrupts an in-flight observation',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 let active=true;
 const blackhole=net.createServer(socket=>{peers.add(socket);socket.on('error',()=>{});socket.once('close',()=>peers.delete(socket));});
 await new Promise(resolve=>blackhole.listen(0,'127.0.0.1',resolve));
 const pending=probeSshHostKey(options({isActive:()=>active,connector:()=>net.connect({host:'127.0.0.1',port:blackhole.address().port})}));
 const timer=setTimeout(()=>{active=false;},150);
 try{await assert.rejects(pending,{code:'SSH_HOST_PROBE_REVOKED'});}finally{clearTimeout(timer);for(const socket of peers)socket.destroy();await new Promise(resolve=>blackhole.close(resolve));}
 await ownedClean();
});

test('invalid target or missing route binding cannot invoke a connector',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 let calls=0;const connector=()=>{calls++;throw new Error('must not connect');};
 await assert.rejects(probeSshHostKey(options({connector,target:{host:'bad host',port:22}})),{code:'SSH_HOST_PROBE_INVALID'});
 await assert.rejects(probeSshHostKey(options({connector,routeBinding:''})),{code:'SSH_HOST_PROBE_INVALID'});
 assert.equal(calls,0);await ownedClean();
});


test('partial transport initialization retains cleanup authority and directory until confirmed retry',{skip:!darwin},async context=>{
 if(!directory){context.skip('Paramiko unavailable');return;}
 let cleanupAttempts=0,created;
 const createTransport=async settings=>{
  created=settings.directory;await writeFile(path.join(created,'partial-owned-listener'),'owned synthetic resource',{mode:0o600});
  const error=new Error('synthetic partial initialization');
  error.sshCleanup=async()=>{if(++cleanupAttempts===1)throw new Error('synthetic cleanup unavailable');};
  throw error;
 };
 const error=await probeSshHostKey(options({connector:hostConnector,createTransport})).then(()=>{throw new Error('Must refuse');},value=>value);
 assert.equal(error.code,'SSH_HOST_PROBE_CLEANUP_FAILED');assert.equal(error.cleanupRequired,true);assert.equal(typeof error.sshCleanup,'function');
 assert.equal(cleanupAttempts,1);assert((await readdir(root)).includes(path.basename(created)));
 await error.sshCleanup();assert.equal(cleanupAttempts,2);await ownedClean();
});
