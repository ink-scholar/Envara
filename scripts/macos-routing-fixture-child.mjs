import net from 'node:net';

// Owned test process. No credentials, user files, DNS or application state.
if (!process.send) throw new Error('The fixture requires its private parent IPC.');
process.send({ type: 'waiting', pid: process.pid });
process.on('message', request => {
  if (request?.type === 'exit') { process.disconnect(); return; }
  if (request?.type !== 'tcp' || typeof request.payload !== 'string') return;
  const payload = Buffer.from(request.payload, 'hex');
  const socket = net.createConnection({ host: '198.51.100.42', port: 40443, allowHalfOpen: true });
  const received = []; let settled = false; let captureWitnessObserved = false;
  const done = success => {
    if (settled) return; settled = true; clearTimeout(timer); socket.destroy();
    process.send({ type: 'tcp-result', passed: success, receivedBytes: Buffer.concat(received).length, captureWitnessObserved });
  };
  const timer = setTimeout(() => done(false), 8000);
  socket.once('connect', () => request.halfCloseAfterCapture === true ? socket.write(payload.subarray(0, 1024)) : request.halfClose === true ? socket.end(payload) : socket.write(payload));
  socket.on('data', bytes => {
    received.push(bytes);
    const result = Buffer.concat(received);
    if (request.halfCloseAfterCapture === true && !captureWitnessObserved && result.length >= 1024) {
      if (!result.subarray(0, 1024).equals(payload.subarray(0, 1024))) return done(false);
      captureWitnessObserved = true; socket.end(payload.subarray(1024));
    }
    if (request.halfClose !== true && request.halfCloseAfterCapture !== true && result.length >= payload.length) done(result.equals(payload));
  });
  socket.once('end', () => done(Buffer.concat(received).equals(payload)));
  socket.once('error', () => done(false));
  socket.once('close', () => done(false));
});
