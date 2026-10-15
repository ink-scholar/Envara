import https from 'node:https';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { lstat, open, realpath, rm } from 'node:fs/promises';
import { HttpsProxyAgent } from 'https-proxy-agent';

export const CLAUDE_RELEASE_BASE = 'https://downloads.claude.ai/claude-code-releases/';
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const MAX_BINARY = 512 * 1024 * 1024;
const failure = code => Object.assign(new Error(code), { code });
const abort = signal => { if (signal?.aborted) throw failure('CLAUDE_CODE_DOWNLOAD_CANCELLED'); };

function proxyAgent(proxyUrl, signal) {
  try {
    const proxy = new URL(proxyUrl);
    // The terminal already resolved this exact route to its managed listener or
    // owned bridge. Hostnames, remote proxies and implicit/system routes cannot
    // enter this download path. CONNECT delegates destination DNS to the proxy.
    if (proxy.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(proxy.hostname)
      || !proxy.port || proxy.pathname !== '/' || proxy.search || proxy.hash) throw new Error();
    const username = decodeURIComponent(proxy.username), password = decodeURIComponent(proxy.password);
    if (/[\0\r\n]/.test(username + password)) throw new Error();
    const headers = username || password ? () => ({ 'Proxy-Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}` }) : undefined;
    // The agent's debug URI contains no credentials; auth is a private callback.
    proxy.username = ''; proxy.password = '';
    return new HttpsProxyAgent(proxy, { signal, timeout: 30000, headers });
  } catch { throw failure('CLAUDE_CODE_DOWNLOAD_ROUTE_REQUIRED'); }
}

async function verifyMacSignature(filename, { signal }) {
  const requirement = '=anchor apple generic and identifier "com.anthropic.claude-code" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "Q6L2SF6YDW"';
  try {
    await promisify(execFile)('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', '-R', requirement, filename], { signal, timeout: 60000, maxBuffer: 16384 });
  } catch { abort(signal); throw failure('CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED'); }
}

/** Trusted native test seams only. No endpoint/TLS options are accepted by IPC. */
export function createClaudeNativeDownloader({ baseURL = CLAUDE_RELEASE_BASE, tlsOptions = {}, verifySignature = verifyMacSignature,
  deadlineMs = 10 * 60 * 1000 } = {}) {
  const base = new URL(baseURL);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || !base.pathname.endsWith('/')) throw failure('CLAUDE_CODE_DOWNLOAD_FAILED');
  return async function download({ destination, proxyUrl, signal, onProgress, platform = process.platform, arch = process.arch }) {
    // Dedicated terminals currently have native acceptance on macOS. Avoid
    // downloading an unverified executable/installer for another platform.
    if (platform !== 'darwin' || !['arm64', 'x64'].includes(arch)) throw failure('CLAUDE_CODE_PLATFORM_UNSUPPORTED');
    abort(signal);
    const controller = new AbortController();
    const cancelled = () => controller.abort(failure('CLAUDE_CODE_DOWNLOAD_CANCELLED'));
    signal?.addEventListener('abort', cancelled, { once: true });
    const timeout = setTimeout(() => controller.abort(failure('CLAUDE_CODE_DOWNLOAD_TIMEOUT')), deadlineMs);
    let agent, file, owned, complete = false;
    const report = update => { try { onProgress?.(update); } catch { /* UI listeners never change installation authority. */ } };
    const check = () => { if (controller.signal.aborted) throw controller.signal.reason; };
    const responseFor = url => new Promise((resolve, reject) => {
      check();
      // https.request does not follow redirects. All responses must be 200;
      // a CDN migration needs an explicit reviewed allowlist change.
      const request = https.request(url, { method: 'GET', agent, ...tlsOptions, rejectUnauthorized: true,
        signal: controller.signal, headers: { Accept: '*/*', 'Accept-Encoding': 'identity', 'User-Agent': 'Envara (Claude native installer)' } }, response => {
        if (response.statusCode !== 200 || (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity')) {
          response.destroy(); reject(failure('CLAUDE_CODE_DOWNLOAD_FAILED')); return;
        }
        resolve(response);
      });
      request.setTimeout(60000, () => controller.abort(failure('CLAUDE_CODE_DOWNLOAD_TIMEOUT')));
      request.once('error', () => reject(controller.signal.aborted ? controller.signal.reason : failure('CLAUDE_CODE_DOWNLOAD_FAILED')));
      request.end();
    });
    const metadata = async (relative, limit) => {
      const response = await responseFor(new URL(relative, base));
      if (Number(response.headers['content-length']) > limit) { response.destroy(); throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED'); }
      const chunks = []; let length = 0;
      for await (const chunk of response) {
        check(); length += chunk.length;
        if (length > limit) { response.destroy(); throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED'); }
        chunks.push(chunk);
      }
      return Buffer.concat(chunks).toString('utf8');
    };
    try {
      agent = proxyAgent(proxyUrl, controller.signal);
      if (typeof destination !== 'string' || !path.isAbsolute(destination) || /[\0\r\n]/.test(destination)) throw failure('CLAUDE_CODE_DOWNLOAD_FAILED');
      const parent = path.dirname(destination), info = await lstat(parent);
      if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o022 || await realpath(parent) !== parent) throw failure('CLAUDE_CODE_DOWNLOAD_FAILED');
      report({ phase: 'metadata' });
      const version = (await metadata('latest', 256)).trim();
      if (version.length > 80 || !VERSION.test(version)) throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
      let manifest;
      try { manifest = JSON.parse(await metadata(`${version}/manifest.json`, 128 * 1024)); }
      catch (error) { if (error.code?.startsWith('CLAUDE_CODE_')) throw error; throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED'); }
      const target = `${platform}-${arch}`, entry = manifest?.platforms?.[target];
      if (manifest?.version !== version || entry?.binary !== 'claude' || !/^[a-f0-9]{64}$/.test(entry?.checksum)
        || !Number.isSafeInteger(entry?.size) || entry.size <= 0 || entry.size > MAX_BINARY) throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
      check();
      file = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      owned = await file.stat();
      const response = await responseFor(new URL(`${version}/${target}/claude`, base));
      if (response.headers['content-length'] !== undefined && (!/^\d+$/.test(response.headers['content-length']) || Number(response.headers['content-length']) !== entry.size)) {
        response.destroy(); throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
      }
      const hash = createHash('sha256'); let receivedBytes = 0, lastProgress = 0;
      report({ phase: 'downloading', version, receivedBytes, totalBytes: entry.size });
      for await (const chunk of response) {
        check(); receivedBytes += chunk.length;
        if (receivedBytes > entry.size) { response.destroy(); throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED'); }
        hash.update(chunk);
        let offset = 0;
        while (offset < chunk.length) { const { bytesWritten } = await file.write(chunk, offset, chunk.length - offset); offset += bytesWritten; }
        if (Date.now() - lastProgress >= 250 || receivedBytes === entry.size) { lastProgress = Date.now(); report({ phase: 'downloading', version, receivedBytes, totalBytes: entry.size }); }
      }
      check();
      if (receivedBytes !== entry.size || hash.digest('hex') !== entry.checksum) throw failure('CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
      await file.sync(); await file.close(); file = null;
      report({ phase: 'verifying', version, receivedBytes, totalBytes: entry.size });
      await verifySignature(destination, { signal: controller.signal }); check();
      complete = true;
      return { version, checksum: entry.checksum, size: entry.size };
    } catch (error) {
      if (controller.signal.aborted) throw controller.signal.reason;
      if (error.code?.startsWith('CLAUDE_CODE_')) throw error;
      throw failure('CLAUDE_CODE_DOWNLOAD_FAILED');
    } finally {
      clearTimeout(timeout); signal?.removeEventListener('abort', cancelled);
      controller.abort(); agent?.destroy(); await file?.close();
      if (!complete && owned) {
        const current = await lstat(destination).catch(() => null);
        if (current?.isFile() && current.dev === owned.dev && current.ino === owned.ino) await rm(destination);
      }
    }
  };
}

export const downloadClaudeNative = createClaudeNativeDownloader();
