// Self-contained client copied into one dedicated terminal's private runtime.
// Its revocable broker owns the HOME and native helper authority. The client
// supplies no paths, account data, commands or host credentials.
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const failure = (code = 'CLAUDE_KEYCHAIN_UNAVAILABLE') => Object.assign(new Error('Claude 登录凭据存储暂不可用，请检查钥匙串后重试。'), { code });
const codes = new Set(['INVALID_ARGUMENT', 'UNSAFE_PATH', 'BUSY', 'MISSING', 'LOCKED', 'UNAVAILABLE',
  'EXISTING_SELECTION', 'PREPARATION_FAILED', 'HOST_CHANGED', 'HOST_CHECK_FAILED', 'CLEANUP_FAILED',
  'RESOURCE_INVALID', 'TIMEOUT', 'PROTOCOL_ERROR'].map(value => `CLAUDE_KEYCHAIN_${value}`));
const stages = new Set(['arguments', 'lock', 'scoped-query', 'host-query', 'stage', 'select', 'publish', 'verify', 'host-verify', 'cleanup']);
function diagnostic(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'stage') || !Object.hasOwn(value, 'osStatus') || !stages.has(value.stage)
    || !(value.osStatus === null || Number.isSafeInteger(value.osStatus) && value.osStatus >= -2147483648 && value.osStatus <= 2147483647)) return null;
  return { stage: value.stage, osStatus: value.osStatus };
}

export async function prepareClaudeCredentials({ environment = process.env, timeoutMs = 40000 } = {}) {
  const socketPath = environment.ENVARA_BROWSER_SOCKET, token = environment.ENVARA_BROWSER_TOKEN;
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || /[\0\r\n]/.test(socketPath)
    || Buffer.byteLength(socketPath) > 100 || typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 40000) throw failure();
  return new Promise((resolve, reject) => {
    let request, settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) { request?.destroy(); reject(error); } else resolve(result);
    };
    const timer = setTimeout(() => finish(failure('CLAUDE_KEYCHAIN_TIMEOUT')), timeoutMs);
    try {
      request = http.request({ socketPath, method: 'POST', path: '/credentials/prepare',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'content-length': 2 }, agent: false }, response => {
        let bytes = 0; const chunks = [];
        response.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 1024) { finish(failure('CLAUDE_KEYCHAIN_PROTOCOL_ERROR')); response.destroy(); }
          else chunks.push(chunk);
        });
        response.on('error', () => finish(failure()));
        response.on('aborted', () => finish(failure()));
        response.on('end', () => {
          if (settled) return;
          let value;
          try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return finish(failure('CLAUDE_KEYCHAIN_PROTOCOL_ERROR')); }
          if (response.statusCode === 200 && value?.ready === true && Object.keys(value).length === 1)
            return finish(null, { ready: true });
          if (response.statusCode === 503 && value?.error === 'credential-preparation-failed' && codes.has(value.code)
            && Object.keys(value).every(key => ['error', 'code', 'keychainDiagnostic'].includes(key))) {
            const detail = Object.hasOwn(value, 'keychainDiagnostic') ? diagnostic(value.keychainDiagnostic) : null;
            if (Object.hasOwn(value, 'keychainDiagnostic') && !detail) return finish(failure('CLAUDE_KEYCHAIN_PROTOCOL_ERROR'));
            const error = failure(value.code);
            if (detail) error.keychainDiagnostic = detail;
            return finish(error);
          }
          finish(failure());
        });
      });
      request.on('error', () => finish(failure()));
      request.end('{}');
    } catch { finish(failure()); }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw failure('CLAUDE_KEYCHAIN_INVALID_ARGUMENT');
    await prepareClaudeCredentials();
  } catch (error) {
    const code = codes.has(error?.code) ? error.code : 'CLAUDE_KEYCHAIN_UNAVAILABLE';
    const message = code === 'CLAUDE_KEYCHAIN_LOCKED'
      ? '登录钥匙串已锁定，请在 macOS“钥匙串访问”中解锁后重新运行 claude。'
      : code === 'CLAUDE_KEYCHAIN_MISSING'
        ? '未找到可用的系统登录钥匙串，请在 macOS“钥匙串访问”中检查后重试。'
        : 'Claude 登录凭据存储暂不可用，请检查境舱终端状态后重试。';
    const detail = diagnostic(error?.keychainDiagnostic);
    const suffix = detail ? ` [${detail.stage}; osStatus=${detail.osStatus ?? 'unknown'}]` : '';
    process.stderr.write(`envara: ${message} (${code})${suffix}\n`);
    process.exitCode = 78;
  }
}
