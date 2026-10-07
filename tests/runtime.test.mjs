import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { BrowserRuntime, buildLaunchConfig, isMacLocaleStartupHistory, macLocaleLauncherSource, parseProcessMetrics } from '../electron/runtime.mjs';

const profile = { id: 'environment-1', seed: 1729, platform: 'macos', width: 1440, height: 900, timezone: 'Asia/Shanghai', locale: 'zh-CN', startUrl: 'about:blank' };

async function fixture(t, options = {}) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'envara-runtime-test-'));
  t.after(() => fs.promises.rm(dir, { recursive: true, force: true }));
  const binaryPath = path.join(dir, 'browser');
  if (options.installed !== false) await fs.promises.writeFile(binaryPath, '#!/bin/sh\n', { mode: 0o755 });
  const page = { isClosed: () => false, bringToFront: async () => {}, screenshot: async () => Buffer.from('jpeg'), goto: async () => {} };
  const context = new EventEmitter();
  context.pages = () => [page];
  context.newPage = async () => page;
  context.close = async () => context.emit('close');
  let config;
  let launches = 0;
  let downloads = 0;
  const runtime = new BrowserRuntime({
    cacheDir: path.join(dir, 'cache'), browserVersion: '145.0.7632.109.2', collectMetrics: false,
    binaryInfo: () => ({ binaryPath, installed: fs.existsSync(binaryPath), version: '145.0.7632.109.2' }),
    ensureBinary: async () => { downloads++; await fs.promises.writeFile(binaryPath, '#!/bin/sh\n', { mode: 0o755 }); return binaryPath; },
    launchPersistentContext: async options => { launches++; config = options; return context; },
    ...options,
  });
  t.after(() => runtime.closeAll());
  return { runtime, context, page, dir, binaryPath, get config() { return config; }, get launches() { return launches; }, get downloads() { return downloads; } };
}

test('persistent launch uses stable native fingerprint flags and separate proxy credentials', () => {
  const proxy = { protocol: 'socks5', host: '::1', port: 1080, username: 'user', password: 'secret' };
  const config = buildLaunchConfig(profile, proxy, '/profiles/one', '145.0.7632.109.2');
  assert.equal(config.userDataDir, '/profiles/one');
  assert.equal(config.viewport, null);
  assert.equal(config.headless, false);
  assert.equal(config.timezone, 'Asia/Shanghai');
  assert.equal(config.locale, 'zh-CN');
  assert.ok(config.args.includes('--fingerprint=1729'));
  assert.ok(config.args.includes('--fingerprint-platform=macos'));
  assert.ok(config.args.includes('--accept-lang=zh-CN,zh'));
  assert.ok(!config.args.some(argument => argument.includes('secret')));
  assert.deepEqual(config.proxy, { server: 'socks5://[::1]:1080', username: 'user', password: 'secret' });
});

test('locale compatibility uses native accept-language flags for macOS baseline', () => {
  const config = buildLaunchConfig({ ...profile, locale: 'en-US' }, null, '/profiles/english', '145.0.7632.109.2');
  assert.ok(config.args.includes('--accept-lang=en-US,en'));
  assert.equal(config.locale, 'en-US');
  assert.ok(!config.args.some(argument => argument.includes('zh-CN')));
  assert.ok(config.args.every(argument => argument.startsWith('-')));
});

test('Cocoa native launcher preserves quoted executable paths and forwards every browser argument', async t => {
  if (process.platform === 'win32') return t.skip('POSIX launcher is macOS-only');
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'envara-launcher-test-'));
  t.after(() => fs.promises.rm(dir, { recursive: true, force: true }));
  const recorder = path.join(dir, "browser's $name; recorder.sh");
  const launcher = path.join(dir, 'launcher.sh');
  await fs.promises.writeFile(recorder, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o700 });
  await fs.promises.writeFile(launcher, macLocaleLauncherSource(recorder, 'en-US'), { mode: 0o700 });
  const { stdout } = await promisify(execFile)(launcher, ['--user-data-dir=/path with spaces', '--remote-debugging-pipe']);
  assert.deepEqual(stdout.trim().split('\n'), ['-AppleLanguages', '(en-US)', '--user-data-dir=/path with spaces', '--remote-debugging-pipe']);
});

test('locale startup cleanup matches only its generated single native navigation and preserves user history', () => {
  const entry = { url: 'http://(en-us)/', userTypedURL: '', transitionType: 'auto_toplevel' };
  const generated = { currentIndex: 0, entries: [entry] };
  assert.equal(isMacLocaleStartupHistory(generated, 'en-US'), true);
  assert.equal(isMacLocaleStartupHistory(generated, 'zh-CN'), false);
  assert.equal(isMacLocaleStartupHistory({ ...generated, entries: [{ ...entry, userTypedURL: entry.url }] }, 'en-US'), false);
  assert.equal(isMacLocaleStartupHistory({ ...generated, entries: [{ ...entry, transitionType: 'typed' }] }, 'en-US'), false);
  assert.equal(isMacLocaleStartupHistory({ currentIndex: 1, entries: [entry, { url: 'https://example.com' }] }, 'en-US'), false);
  assert.equal(isMacLocaleStartupHistory({ ...generated, entries: [{ ...entry, url: 'https://example.com/' }] }, 'en-US'), false);
});

test('starting without an installed engine never downloads or launches', async t => {
  const f = await fixture(t, { installed: false });
  await assert.rejects(f.runtime.start(profile, null, path.join(f.dir, 'profile')), /请先/);
  assert.equal(f.launches, 0);
  assert.equal(f.downloads, 0);
});

test('explicit installation is deduplicated and clears installing state', async t => {
  const f = await fixture(t, { installed: false });
  const first = f.runtime.install();
  const second = f.runtime.install();
  assert.equal(first, second);
  assert.equal(f.runtime.snapshot().installing, true);
  const installed = await first;
  assert.equal(installed.installing, false);
  assert.equal(f.downloads, 1);
  assert.equal(f.runtime.isInstalled(), true);
  assert.equal(f.runtime.snapshot().installing, false);
  assert.equal(f.runtime.snapshot().progress, null);
});

test('duplicate Start shares one browser, closing notifies once, preview contains real screenshot', async t => {
  const f = await fixture(t);
  let closed = 0;
  const profileDir = path.join(f.dir, 'profile');
  await Promise.all([f.runtime.start(profile, null, profileDir, () => closed++), f.runtime.start(profile, null, profileDir)]);
  assert.equal(f.launches, 1);
  assert.equal(await f.runtime.screenshot(profile.id), `data:image/jpeg;base64,${Buffer.from('jpeg').toString('base64')}`);
  assert.deepEqual(f.runtime.getMetrics(), { [profile.id]: { cpuPercent: null, memoryBytes: null } });
  await f.runtime.stop(profile.id);
  await f.runtime.stop(profile.id);
  assert.equal(closed, 1);
  assert.equal(await f.runtime.screenshot(profile.id), null);
});

test('installation failure reports the original error and can be retried', async t => {
  let attempts = 0;
  const f = await fixture(t, { installed: false, ensureBinary: async () => { attempts++; throw new Error('checksum mismatch'); } });
  await assert.rejects(f.runtime.install(), /checksum mismatch/);
  assert.equal(f.runtime.snapshot().installing, false);
  assert.equal(f.runtime.snapshot().error, 'checksum mismatch');
  await assert.rejects(f.runtime.install(), /checksum mismatch/);
  assert.equal(attempts, 2);
});

test('OS metrics include only profile browser and descendants, never a similarly prefixed profile', () => {
  const output = [
    '100 1 2.1 1000 /Applications/Chromium --user-data-dir=/profiles/one --other',
    '101 100 3.4 2000 /Applications/Chromium --type=renderer',
    '102 101 0.5 3000 /Applications/Chromium --type=utility',
    '200 1 99.9 5000 /Applications/Chromium --user-data-dir=/profiles/one-more --other',
    '201 200 88.8 6000 /Applications/Chromium --type=renderer',
  ].join('\n');
  assert.deepEqual(parseProcessMetrics(output, new Map([['one', { profileDir: '/profiles/one' }], ['missing', { profileDir: '/profiles/missing' }]])), {
    one: { cpuPercent: 6, memoryBytes: 6000 * 1024 },
    missing: { cpuPercent: null, memoryBytes: null },
  });
});
