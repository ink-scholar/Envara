import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import unzipper from 'unzipper';
import { deflateRawSync } from 'node:zlib';
import { existsSync, renameSync, truncateSync, writeFileSync } from 'node:fs';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { extractApplicationUpdate } from '../electron/application-update-archive.mjs';

const table = Uint32Array.from({ length: 256 }, (_, n) => { for (let i=0;i<8;i++) n=n&1?0xedb88320^(n>>>1):n>>>1; return n>>>0; });
function crc(bytes) { let n=0xffffffff; for(const byte of bytes)n=table[(n^byte)&255]^(n>>>8);return(n^0xffffffff)>>>0; }
function zip(records) {
  const locals=[],central=[];let offset=0;
  for(const item of records) {
    const name=Buffer.isBuffer(item.name)?item.name:Buffer.from(item.name),localName=Buffer.from(item.localName??name);
    const content=Buffer.from(item.content??''),method=item.method??0,compressed=item.compressed??(method===8?deflateRawSync(content):content);
    const extra=item.extra??Buffer.alloc(0),size=item.size??content.length,checksum=item.crc??crc(content),flags=item.flags??0x800;
    const header=Buffer.alloc(30);header.writeUInt32LE(0x04034b50);header.writeUInt16LE(20,4);header.writeUInt16LE(flags,6);header.writeUInt16LE(method,8);
    header.writeUInt32LE(checksum,14);header.writeUInt32LE(compressed.length,18);header.writeUInt32LE(size,22);header.writeUInt16LE(localName.length,26);header.writeUInt16LE(extra.length,28);
    locals.push(header,localName,extra,compressed);
    const directory=Buffer.alloc(46);directory.writeUInt32LE(0x02014b50);directory.writeUInt16LE(((item.host??3)<<8)|20,4);directory.writeUInt16LE(20,6);
    directory.writeUInt16LE(flags,8);directory.writeUInt16LE(method,10);directory.writeUInt32LE(checksum,16);directory.writeUInt32LE(compressed.length,20);directory.writeUInt32LE(size,24);
    directory.writeUInt16LE(name.length,28);directory.writeUInt16LE(extra.length,30);directory.writeUInt32LE(((item.mode??0o100644)<<16)>>>0,38);directory.writeUInt32LE(offset,42);
    central.push(directory,name,extra);offset+=header.length+localName.length+extra.length+compressed.length;
  }
  const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(records.length,8);end.writeUInt16LE(records.length,10);
  end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);return Buffer.concat([...locals,directory,end]);
}
const file=(name,content='fixture')=>({name:`Envara.app/${name}`,content});
async function fixture(t,records,options={}) {
  const parent=await realpath(await mkdtemp(path.join(os.tmpdir(),'envara-update-archive-')));
  t.after(()=>rm(parent,{recursive:true,force:true}));await chmod(parent,0o700);
  const archivePath=path.join(parent,'update.zip'),destination=path.join(parent,'expanded'),bytes=Buffer.isBuffer(records)?records:zip(records);
  await writeFile(archivePath,bytes,{mode:0o600});await writeFile(path.join(parent,'unrelated.txt'),'keep');
  return {parent,archivePath,destination,bytes,options:{archivePath,destination,sha256:createHash('sha256').update(bytes).digest('hex'),...options}};
}
async function refuses(f) {
  await assert.rejects(extractApplicationUpdate(f.options),{code:'APPLICATION_UPDATE_ARCHIVE_INVALID'});
  await assert.rejects(lstat(f.destination),{code:'ENOENT'});
  assert.equal(await readFile(path.join(f.parent,'unrelated.txt'),'utf8'),'keep');
}

test('valid app resources and framework links extract privately, retaining executable bits without group/world write',async t=>{
  const f=await fixture(t,[{name:'Envara.app/',mode:0o040755},file('Contents/Info.plist','plist'),
    {...file('Contents/MacOS/Envara','native-fixture'),mode:0o100777,method:8},
    file('Contents/Resources/语言.txt','你好'),file('Contents/Frameworks/Fixture.framework/Versions/A/Fixture','binary'),
    file('Contents/Frameworks/Fixture.framework/Versions/A/Resources/name','resource'),
    {name:'Envara.app/Contents/Frameworks/Fixture.framework/Versions/Current',mode:0o120777,content:'A'},
    {name:'Envara.app/Contents/Frameworks/Fixture.framework/Fixture',mode:0o120777,content:'Versions/Current/Fixture'},
    {name:'Envara.app/Contents/Frameworks/Fixture.framework/Resources',mode:0o120777,content:'Versions/Current/Resources'},
    {name:'Envara.app/Contents/Resources/FrameworkResource',mode:0o120777,content:'../Frameworks/Fixture.framework/Resources/name'}]);
  const app=await extractApplicationUpdate(f.options);assert.equal(app,path.join(f.destination,'Envara.app'));
  assert.equal(await readFile(path.join(app,'Contents/Resources/FrameworkResource'),'utf8'),'resource');
  assert.equal(await readFile(path.join(app,'Contents/Resources/语言.txt'),'utf8'),'你好');
  assert.equal(await readlink(path.join(app,'Contents/Frameworks/Fixture.framework/Versions/Current')),'A');
  assert.equal((await lstat(path.join(app,'Contents/MacOS/Envara'))).mode&0o777,0o755);
  assert.equal((await lstat(f.destination)).mode&0o777,0o700);assert.deepEqual(await readdir(f.destination),['Envara.app']);
});

test('archive member paths reject traversal, platform aliases, invalid UTF-8, special files and alternate link metadata',async t=>{
  const cases=[
    [{name:'../escape'}],[{name:'/Envara.app/escape'}],[{name:'Other.app/file'}],[{name:'Envara.app/../escape'}],
    [{name:'Envara.app/./file'}],[{name:'Envara.app//file'}],[{name:'Envara.app/file/'}],[{name:'Envara.app\\file'}],
    [{name:'Envara.app/C:/file'}],[{name:'Envara.app/nu\0ll'}],[{name:Buffer.from('456e766172612e6170702fff','hex')}],
    [file('Case'),file('case')],[file('é'),file('e\u0301')],[file('same'),file('same')],
    [file('parent'),file('parent/child')],[file('Case/first'),file('case/second')],
    [{...file('fifo'),mode:0o010600}],[{...file('device'),mode:0o020600}],
    [{...file('hardlink'),extra:Buffer.from('0d000000','hex')}],[{...file('wrong-host'),host:0}],
    [{...file('local-mismatch'),localName:'Envara.app/other'}],
  ];
  for(const records of cases)await t.test(String(records[0].name),async inner=>refuses(await fixture(inner,records)));
});

test('symlinks reject outside targets, indirect escapes, cycles, dangling paths and descendants through a link',async t=>{
  const sym=(name,target)=>({name:`Envara.app/${name}`,mode:0o120777,content:target});
  const cases=[ [sym('escape','../outside')],[sym('escape','/tmp/outside')],[sym('escape','C:\\outside')],
    [sym('a','b'),sym('b','../../outside')],[sym('a','b'),sym('b','a')],[sym('a','missing')],
    [sym('a','a/child')],[sym('directory','real'),file('real/kept'),file('directory/child')],
    [sym('a','a/..')],[file('ordinary'),sym('alias','ordinary/child')],[sym('self','.')],
    [file('first/file'),file('second/file'),sym('first/link','../second'),sym('second/link','../first')],
  ];
  for(let index=0;index<cases.length;index++)await t.test(`link boundary ${index}`,async inner=>refuses(await fixture(inner,cases[index])));
});

test('size, entry count, CRC, compression, local headers and malformed archives fail with complete owned-stage cleanup',async t=>{
  const corrupt=zip([file('first','already-extracted'),{...file('second','corrupt'),crc:123}]);
  const bomb=zip([{...file('bomb',Buffer.alloc(256*1024,65)),method:8,size:1}]);
  const cases=[
    {bytes:corrupt},{bytes:bomb,options:{maxExpandedBytes:1024*1024}},
    {bytes:zip([file('one','12345'),file('two','67890')]),options:{maxExpandedBytes:9}},
    {bytes:zip([file('one'),file('two')]),options:{maxEntries:1}},
    {bytes:zip([{...file('file'),method:8,compressed:Buffer.from('invalid compressed stream')}])},
    {bytes:zip([{...file('encrypted'),flags:0x801}])},
    {bytes:corrupt.subarray(0,corrupt.length-2)},{bytes:Buffer.from('not a zip')},
    {bytes:zip([file('hash')]),options:{sha256:'0'.repeat(64)}},
  ];
  for(let index=0;index<cases.length;index++)await t.test(`invalid archive ${index}`,async inner=>refuses(await fixture(inner,cases[index].bytes,cases[index].options)));
});

test('archive and destination ownership rules preserve existing files and reject linked sources',async t=>{
  const f=await fixture(t,[file('file')]);
  await mkdir(f.destination,{mode:0o700});await writeFile(path.join(f.destination,'keep'),'untouched');
  await assert.rejects(extractApplicationUpdate(f.options),{code:'APPLICATION_UPDATE_ARCHIVE_INVALID'});
  assert.equal(await readFile(path.join(f.destination,'keep'),'utf8'),'untouched');
  await rm(f.destination,{recursive:true});
  const alias=path.join(f.parent,'alias.zip');await symlink(f.archivePath,alias);
  await refuses({...f,options:{...f.options,archivePath:alias}});await rm(alias);
  await link(f.archivePath,alias);await refuses(f);await rm(alias);
  await chmod(f.parent,0o755);await refuses(f);await chmod(f.parent,0o700);
});

test('cancellation leaves no extraction and exposes only a stable cancellation code',async t=>{
  const f=await fixture(t,[file('large',Buffer.alloc(8*1024*1024,65))]);
  const controller=new AbortController();const pending=extractApplicationUpdate({...f.options,signal:controller.signal});
  setTimeout(()=>controller.abort(),5);
  await assert.rejects(pending,{code:'APPLICATION_UPDATE_CANCELLED'});
  await assert.rejects(lstat(f.destination),{code:'ENOENT'});
  assert.equal(await readFile(path.join(f.parent,'unrelated.txt'),'utf8'),'keep');
});

test('source pathname replacement during verification is rejected even when replacement bytes have the same digest',async t=>{
  const f=await fixture(t,[file('large',Buffer.alloc(4*1024*1024,65))]);let swapped=false;
  const observer=setInterval(()=>{
    if(!swapped&&existsSync(f.destination)) {swapped=true;renameSync(f.archivePath,path.join(f.parent,'original.zip'));writeFileSync(f.archivePath,f.bytes,{mode:0o600});}
  },1);
  try {await refuses(f);assert.equal(swapped,true);}finally{clearInterval(observer);}
});

test('macOS ditto --norsrc app archives retain framework symlinks and resources', {skip:process.platform!=='darwin'},async t=>{
  const f=await fixture(t,[file('placeholder')]);
  const app=path.join(f.parent,'Envara.app'),framework=path.join(app,'Contents/Frameworks/Fixture.framework');
  await mkdir(path.join(framework,'Versions/A/Resources'),{recursive:true,mode:0o700});
  await writeFile(path.join(framework,'Versions/A/Resources/name'),'resource');
  await writeFile(path.join(framework,'Versions/A/Fixture'),'not-an-executable-fixture',{mode:0o755});
  await symlink('A',path.join(framework,'Versions/Current'));
  await symlink('Versions/Current/Fixture',path.join(framework,'Fixture'));
  await symlink('Versions/Current/Resources',path.join(framework,'Resources'));
  await rm(f.archivePath);await promisify(execFile)('/usr/bin/ditto',['-c','-k','--norsrc','--keepParent',app,f.archivePath]);
  f.options.sha256=createHash('sha256').update(await readFile(f.archivePath)).digest('hex');
  const result=await extractApplicationUpdate(f.options);
  assert.equal(await readFile(path.join(result,'Contents/Frameworks/Fixture.framework/Resources/name'),'utf8'),'resource');
  assert.equal(await readlink(path.join(result,'Contents/Frameworks/Fixture.framework/Versions/Current')),'A');
});

test('early expanded-byte refusal releases every owned ZIP read stream',async t=>{
  const f=await fixture(t,[{...file('bomb',Buffer.alloc(2*1024*1024,65)),size:1}]);
  const original=unzipper.Open.custom,streams=[];
  unzipper.Open.custom=function(source,options){const stream=source.stream;source.stream=(...args)=>{const result=stream(...args);streams.push(result);return result;};return original.call(this,source,options);};
  try {
    await refuses(f);await new Promise(resolve=>setTimeout(resolve,20));
    assert.ok(streams.length>0);
    assert.equal(streams.filter(stream=>!stream.destroyed).length,0);
  } finally {unzipper.Open.custom=original;for(const stream of streams)stream.destroy();}
});

test('implicit ancestor discovery preserves explicitly private directory permissions',async t=>{
  const f=await fixture(t,[{name:'Envara.app/',mode:0o040700},{name:'Envara.app/Contents/',mode:0o040700},file('Contents/file')]);
  const app=await extractApplicationUpdate(f.options);
  assert.equal((await lstat(app)).mode&0o777,0o700);assert.equal((await lstat(path.join(app,'Contents'))).mode&0o777,0o700);
});

test('bounded ZIP64 directory metadata is accepted and oversized declared counts fail before the library opens it',async t=>{
  const base=zip([file('Contents/resource','zip64-fixture')]),old=base.subarray(-22),offset=base.length-22;
  const record=Buffer.alloc(56);record.writeUInt32LE(0x06064b50);record.writeBigUInt64LE(44n,4);record.writeUInt16LE(45,12);record.writeUInt16LE(45,14);
  record.writeBigUInt64LE(1n,24);record.writeBigUInt64LE(1n,32);record.writeBigUInt64LE(BigInt(old.readUInt32LE(12)),40);record.writeBigUInt64LE(BigInt(old.readUInt32LE(16)),48);
  const locator=Buffer.alloc(20);locator.writeUInt32LE(0x07064b50);locator.writeBigUInt64LE(BigInt(offset),8);locator.writeUInt32LE(1,16);
  const end=Buffer.from(old);end.writeUInt16LE(0xffff,8);end.writeUInt16LE(0xffff,10);end.writeUInt32LE(0xffffffff,12);end.writeUInt32LE(0xffffffff,16);
  const valid=Buffer.concat([base.subarray(0,-22),record,locator,end]);
  const f=await fixture(t,valid),app=await extractApplicationUpdate(f.options);
  assert.equal(await readFile(path.join(app,'Contents/resource'),'utf8'),'zip64-fixture');
  const oversized=Buffer.from(valid);oversized.writeBigUInt64LE(100001n,offset+24);oversized.writeBigUInt64LE(100001n,offset+32);
  const denied=await fixture(t,oversized),original=unzipper.Open.custom;let calls=0;
  unzipper.Open.custom=(...args)=>{calls++;return original(...args);};
  try {await refuses(denied);assert.equal(calls,0);}finally{unzipper.Open.custom=original;}
});

test('implicit directories count toward the extraction entry limit before creating the app tree',async t=>{
  const f=await fixture(t,[file('one/two/three/four/file')],{maxEntries:4});await refuses(f);
});

test('cancellation during an entry stream closes its bounded source streams and removes the partial app',async t=>{
  const f=await fixture(t,[file('large',Buffer.alloc(2*1024*1024,65))]),controller=new AbortController();
  const original=unzipper.Open.custom,streams=[];let streamed=false;
  unzipper.Open.custom=function(source,options){
    const read=source.stream;source.stream=(...args)=>{const result=read(...args);streams.push(result);return result;};
    return original.call(this,source,options).then(archive=>{for(const entry of archive.files){const stream=entry.stream;entry.stream=()=>{
      const result=stream();streamed=true;setImmediate(()=>controller.abort());return result;
    };}return archive;});
  };
  try {
    await assert.rejects(extractApplicationUpdate({...f.options,signal:controller.signal}),{code:'APPLICATION_UPDATE_CANCELLED'});
    assert.equal(streamed,true);assert.equal(streams.filter(stream=>!stream.destroyed).length,0);
    await assert.rejects(lstat(f.destination),{code:'ENOENT'});
  }finally{unzipper.Open.custom=original;for(const stream of streams)stream.destroy();}
});

test('an underlying archive read failure rejects promptly and releases streams instead of hanging the parser', {timeout:3000},async t=>{
  const f=await fixture(t,[file('large',Buffer.alloc(2*1024*1024,65))]);
  const original=unzipper.Open.custom,streams=[];let truncated=false;
  unzipper.Open.custom=function(source,options){
    const read=source.stream;source.stream=(...args)=>{const result=read(...args);streams.push(result);return result;};
    return original.call(this,source,options).then(archive=>{for(const entry of archive.files){const stream=entry.stream;entry.stream=()=>{
      const result=stream();truncateSync(path.join(f.destination,'.verified-update.zip'),0);truncated=true;return result;
    };}return archive;});
  };
  try {await refuses(f);assert.equal(truncated,true);assert.equal(streams.filter(stream=>!stream.destroyed).length,0);}
  finally{unzipper.Open.custom=original;for(const stream of streams)stream.destroy();}
});

test('metadata source errors remain bounded, sanitized and fully cleaned up', {timeout:3000},async t=>{
  const f=await fixture(t,[file('resource')]),original=unzipper.Open.custom,streams=[];
  unzipper.Open.custom=function(source,options){const read=source.stream;source.stream=(...args)=>{
    const result=read(...args);streams.push(result);
    if(streams.length===1)queueMicrotask(()=>result.destroy(new Error('PRIVATE_ARCHIVE_READ_ERROR')));
    return result;
  };return original.call(this,source,options);};
  try {
    await assert.rejects(extractApplicationUpdate(f.options),error=>error.code==='APPLICATION_UPDATE_ARCHIVE_INVALID'&&!error.message.includes('PRIVATE_ARCHIVE_READ_ERROR'));
    assert.equal(streams.filter(stream=>!stream.closed).length,0);await assert.rejects(lstat(f.destination),{code:'ENOENT'});
  }finally{unzipper.Open.custom=original;for(const stream of streams)stream.destroy();}
});
