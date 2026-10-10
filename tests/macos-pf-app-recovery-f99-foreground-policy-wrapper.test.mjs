import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

const exec = promisify(execFile), native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
const payloadSHA = '77be8f3ca037950dc1715f0c6a02f55ac3811a3b6678799318c16683a7194ad5';

test('actual foreground helper refuses off-main before NSApp; failed foreground never calls Authorization; inert entries never initialize an app', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-f99-foreground-policy-inert-'));
  try {
    const executable = path.join(directory, 'inert');
    await writeFile(path.join(directory, 'recovery-app-f99-foreground-policy-wrapper-build.h'), `#define WRAPPER_SELF ${JSON.stringify(executable)}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_RECOVERY_SHA ${JSON.stringify(payloadSHA)}\n#define WRAPPER_ROOT_TARGET "/Library/PrivilegedHelperTools/io.envara.pf-recovery-f99-${payloadSHA}"\n#define WRAPPER_STAGE_PROGRAM "closed-inert-fixture-not-executed"\n`);
    const source = path.join(directory, 'inert.m');
    await writeFile(source, String.raw`
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <Security/Security.h>
#include <assert.h>
#include <pthread.h>
static unsigned created,copied;static OSStatus createError,copyError;
static OSStatus mockCreate(const AuthorizationRights*rights,const AuthorizationEnvironment*environment,AuthorizationFlags flags,AuthorizationRef*ref){assert(!rights&&environment==kAuthorizationEmptyEnvironment&&flags==0);created++;*ref=(AuthorizationRef)(uintptr_t)1;return createError;}
static OSStatus mockCopy(AuthorizationRef ref,const AuthorizationRights*rights,const AuthorizationEnvironment*environment,AuthorizationFlags flags,AuthorizationRights**authorized){assert(ref==(AuthorizationRef)(uintptr_t)1&&rights&&environment&&!authorized&&flags==(kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights));assert(rights->count==1&&!strcmp(rights->items[0].name,kAuthorizationRightExecute));assert(environment->count==1&&!strcmp(environment->items[0].name,kAuthorizationEnvironmentPrompt));copied++;return copyError;}
#define AuthorizationCreate mockCreate
#define AuthorizationCopyRights mockCopy
#define main wrapperEntry
#include "@SOURCE@"
#undef main
#undef AuthorizationCreate
#undef AuthorizationCopyRights
static void*worker(void*unused){(void)unused;assert(!NSThread.isMainThread&&!NSApp);assert(!activateOwnForeground());assert(!NSApp);return NULL;}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0&&NSThread.isMainThread&&!NSApp);pthread_t thread;assert(!pthread_create(&thread,NULL,worker,NULL));assert(!pthread_join(thread,NULL)&&!NSApp);
 AuthorizationRef ref=NULL;AuthorizationItem right={kAuthorizationRightExecute,0,NULL,0};AuthorizationRights rights={1,&right};char prompt[]="closed inert prompt";AuthorizationItem message={kAuthorizationEnvironmentPrompt,sizeof(prompt)-1,prompt,0};AuthorizationEnvironment environment={1,&message};
 assert(authorizationAfterForeground(false,&ref,&rights,&environment)==errAuthorizationInteractionNotAllowed&&!created&&!copied&&!ref&&!NSApp);
 assert(authorizationAfterForeground(true,&ref,&rights,&environment)==errAuthorizationSuccess&&created==1&&copied==1&&!NSApp);
 createError=errAuthorizationDenied;assert(authorizationAfterForeground(true,&ref,&rights,&environment)==createError&&created==2&&copied==1);createError=0;copyError=errAuthorizationCanceled;assert(authorizationAfterForeground(true,&ref,&rights,&environment)==copyError&&created==3&&copied==2);
 char*a[]={WRAPPER_SELF,"--plan",NULL};assert(wrapperEntry(2,a)==0&&!NSApp);char*b[]={WRAPPER_SELF,"--foreign",NULL};assert(wrapperEntry(2,b)==1&&!NSApp);char*c[]={WRAPPER_SELF,"--plan","extra",NULL};assert(wrapperEntry(3,c)==1&&!NSApp);assert(created==3&&copied==2);puts("foreground inert checks passed");return 0;
}}
`.replace('@SOURCE@', path.join(native, 'recovery-app-f99-foreground-policy-wrapper.m')));
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory, source, '-framework', 'Foundation', '-framework', 'Security', '-framework', 'AppKit', '-o', executable], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', executable], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', executable], { timeout: 15000 });
    const lines = (await exec(executable, [], { timeout: 10000 })).stdout.trim().split('\n');
    assert.equal(lines.pop(), 'foreground inert checks passed');
    const [plan, unknown, excess] = lines.map(line => JSON.parse(line));
    assert.equal(plan.ok, true);assert.equal(plan.localHardenedSelfVerified, true);
    assert.equal(unknown.reason, 'INVALID_FIXED_OPERATION');assert.equal(excess.reason, 'INVALID_FIXED_OPERATION');
    for (const output of [plan, unknown, excess]) for (const key of ['authorizationRequested', 'rootStageAttempted', 'rootStageCompleted', 'bootstrapRootTargetBound', 'cleanupConfirmed', 'cleanupPermitted', 'ready', 'protected', 'productionReady']) assert.equal(output[key], false, key);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('actual LSUIElement bundle already has Accessory policy; production helper accepts unchanged policy and verifies setter results without activation', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-f99-accessory-policy-inert-'));
  try {
    const app = path.join(directory, 'Own Accessory Policy Fixture.app');
    const macos = path.join(app, 'Contents/MacOS');
    const { mkdir } = await import('node:fs/promises');
    await mkdir(macos, { recursive: true });
    const executable = path.join(macos, 'inert');
    await writeFile(path.join(app, 'Contents/Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.own-accessory-policy-fixture</string><key>CFBundleExecutable</key><string>inert</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>\n');
    await writeFile(path.join(directory, 'recovery-app-f99-foreground-policy-wrapper-build.h'), `#define WRAPPER_SELF ${JSON.stringify(executable)}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_RECOVERY_SHA ${JSON.stringify(payloadSHA)}\n#define WRAPPER_ROOT_TARGET "/Library/PrivilegedHelperTools/io.envara.pf-recovery-f99-${payloadSHA}"\n#define WRAPPER_STAGE_PROGRAM "closed-inert-fixture-not-executed"\n`);
    const source = path.join(directory, 'inert.m');
    await writeFile(source, String.raw`
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <assert.h>
#define WRAPPER_INERT 1
#include "@SOURCE@"
@interface PolicyFixture:NSObject
@property(nonatomic)NSApplicationActivationPolicy policy;
@property(nonatomic)BOOL changeAllowed;
@property(nonatomic)unsigned setters;
@end
@implementation PolicyFixture
-(NSApplicationActivationPolicy)activationPolicy{return self.policy;}
-(BOOL)setActivationPolicy:(NSApplicationActivationPolicy)value{self.setters++;if(self.changeAllowed)self.policy=value;return NO;}
@end
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0&&NSThread.isMainThread&&!NSApp);clearOwnEnvironment();
 NSApplication*app=NSApplication.sharedApplication;assert(app&&app.activationPolicy==NSApplicationActivationPolicyAccessory);
 assert(![app setActivationPolicy:NSApplicationActivationPolicyAccessory]);assert(ensureOwnAccessoryPolicy(app));assert(app.activationPolicy==NSApplicationActivationPolicyAccessory);
 assert(!ensureOwnAccessoryPolicy(nil));
 PolicyFixture*fixture=[PolicyFixture new];fixture.policy=NSApplicationActivationPolicyAccessory;
 assert(ensureOwnAccessoryPolicy((NSApplication*)fixture)&&fixture.setters==0);
 fixture.policy=NSApplicationActivationPolicyProhibited;fixture.changeAllowed=NO;
 assert(!ensureOwnAccessoryPolicy((NSApplication*)fixture)&&fixture.setters==1&&fixture.policy==NSApplicationActivationPolicyProhibited);
 fixture.changeAllowed=YES;assert(ensureOwnAccessoryPolicy((NSApplication*)fixture)&&fixture.setters==2&&fixture.policy==NSApplicationActivationPolicyAccessory);
 assert(ensureOwnAccessoryPolicy((NSApplication*)fixture)&&fixture.setters==2);
 NSDictionary*result=@{@"alreadyAccessoryAccepted":@YES,@"unchangedSetterReturnedFalse":@YES,@"setterResultRechecked":@YES,@"finishLaunchingCalled":@NO,@"activationCalled":@NO,@"authorizationCalled":@NO,@"rootExecuted":@NO};
 NSData*d=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];fwrite(d.bytes,1,d.length,stdout);fputc('\n',stdout);return 0;
}}
`.replace('@SOURCE@', path.join(native, 'recovery-app-f99-foreground-policy-wrapper.m')));
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory, source, '-framework', 'Foundation', '-framework', 'Security', '-framework', 'AppKit', '-o', executable], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', app], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', app], { timeout: 15000 });
    const result = JSON.parse((await exec(executable, [], { timeout: 10000 })).stdout);
    for (const key of ['alreadyAccessoryAccepted', 'unchangedSetterReturnedFalse', 'setterResultRechecked']) assert.equal(result[key], true, key);
    for (const key of ['finishLaunchingCalled', 'activationCalled', 'authorizationCalled', 'rootExecuted']) assert.equal(result[key], false, key);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
