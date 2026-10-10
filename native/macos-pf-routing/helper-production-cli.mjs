import { fileURLToPath } from 'node:url';
import { NativeApplicationCommands, APP_NATIVE_PROTOCOL } from './helper-production-native.mjs';

const methods = new Set(['status', 'plan', 'register', 'retire', 'prepareTicket', 'inspectTicket', 'stageTicket', 'stop']);
export async function serveNativeApplicationHelper({ commands = new NativeApplicationCommands(), input = process.stdin, output = process.stdout, maxBytes = 8192 } = {}) {
  let buffer = Buffer.alloc(0), lost = false;
  const end = () => { lost = true; buffer = Buffer.alloc(0); input.destroy?.(); commands.shutdown(); };
  const inputEnd = () => commands.shutdown();
  output.on('error', end);
  output.on('close', end);
  input.on('error', end);
  input.on('end', inputEnd);
  const dispatch = async bytes => {
    if (lost) return;
    let request;
    try {
      request = JSON.parse(bytes.toString('utf8'));
      if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).some(key => !['id', 'method', 'params'].includes(key)) ||
          typeof request.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(request.id) || !methods.has(request.method) ||
          !request.params || typeof request.params !== 'object' || Array.isArray(request.params)) throw new Error();
      if (request.method === 'status' && Object.keys(request.params).length) throw new Error();
      const result = await commands[request.method](request.params);
      if (!lost) output.write(`${JSON.stringify({ protocol: APP_NATIVE_PROTOCOL, id: request.id, ok: true, result })}\n`);
    } catch {
      if (!lost) output.write(`${JSON.stringify({ protocol: APP_NATIVE_PROTOCOL, id: typeof request?.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(request.id) ? request.id : null,
        ok: false, error: { code: 'APPLICATION_NATIVE_REFUSED', message: 'Native application operation did not complete' } })}\n`);
    }
  };
  try {
    for await (const chunk of input) {
      if (lost) break; buffer = Buffer.concat([buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]); if (buffer.length > 2 * maxBytes) { end(); break; }
      let at; while (!lost && (at = buffer.indexOf(10)) >= 0) { const line = buffer.subarray(0, at); buffer = buffer.subarray(at + 1);
        if (line.length > maxBytes) { end(); break; } if (line.length) await dispatch(line); }
      if (buffer.length > maxBytes) end();
    }
    if (!lost && buffer.length) await dispatch(buffer);
  } finally { output.removeListener('error', end); output.removeListener('close', end); input.removeListener('error', end); input.removeListener('end', inputEnd); const result = commands.shutdown(); if (result.cleanupRequired) process.exitCode = 1; }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  // No argv enables controlled root mutation. The installed authenticated
  // native entry must construct that session directly after OS authorization.
  if (process.argv.length !== 3 || process.argv[2] !== '--rpc') process.exitCode = 2;
  else await serveNativeApplicationHelper();
}
