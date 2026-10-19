// Private helper executed only by a main-owned, fenced OpenSSH process.
// No credential is stored in this file, its arguments, or its environment.
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export async function runSshAskpass({ socket, token, output = process.stdout, connect = net.createConnection,
  timeoutMs = 15000, promptKind = '' } = {}) {
  if (typeof socket !== 'string' || !path.isAbsolute(socket) || path.normalize(socket) !== socket
    || /[\x00-\x1f\x7f]/.test(socket) || Buffer.byteLength(socket) > 100
    || typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || promptKind) return 1;
  return new Promise(resolve => {
    let channel, settled = false, received = Buffer.alloc(0);
    const finish = code => {
      if (settled) return;
      settled = true; clearTimeout(timer); received.fill(0); channel?.destroy(); resolve(code);
    };
    const timer = setTimeout(() => finish(1), Math.min(15000, Math.max(100, timeoutMs)));
    try {
      channel = connect({ path: socket });
      channel.once('connect', () => channel.write(`${JSON.stringify({ version: 1, token })}\n`));
      channel.on('data', chunk => {
        if (settled) return;
        const previous = received;
        received = Buffer.concat([previous, chunk]); previous.fill(0);
        if (received.length > 4097) finish(1);
      });
      channel.once('end', () => {
        if (settled) return;
        if (received.length < 2 || received.at(-1) !== 10 || received.subarray(0, -1).includes(10)
          || received.includes(0) || received.includes(13)) return finish(1);
        // OpenSSH owns this stdout pipe. Never send the value to the terminal.
        try { output.write(received, error => finish(error ? 1 : 0)); } catch { finish(1); }
      });
      channel.once('error', () => finish(1));
      channel.once('close', () => { if (!channel.readableEnded) finish(1); });
    } catch { finish(1); }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runSshAskpass({ socket: process.env.ENVARA_SSH_ASKPASS_SOCKET,
    token: process.env.ENVARA_SSH_ASKPASS_TOKEN, promptKind: process.env.SSH_ASKPASS_PROMPT ?? '' });
}
