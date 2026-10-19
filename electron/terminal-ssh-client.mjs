// Copied into the protected terminal runtime. Keep this client standalone and
// limited to Node builtins; passwords belong exclusively to the main process.
import net from 'node:net';
import path from 'node:path';

const MAX_LINE = 128 * 1024;
const MAX_DATA = 48 * 1024;
const MAX_BUFFER = 1024 * 1024;
const FAILURE = 'Envara: SSH connection failed.\n';
const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
const ERROR_CODE = /^SSH_[A-Z_]{1,64}$/;
const size = value => Number.isInteger(value) && value >= 1 && value <= 1000;
const exactKeys = (value, keys) => Object.keys(value).every(key => keys.includes(key))
  && keys.every(key => Object.hasOwn(value, key));

function decodeData(value) {
  if (typeof value !== 'string' || value.length > MAX_DATA / 3 * 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}

/** Forward a single SSH invocation to the session's fenced Unix socket. The
 * socket path is an already-issued capability, never an arbitrary host URL. */
export async function runPasswordSshClient({ socket: socketPath, argv, tty = false, cols = 80, rows = 24,
  input = process.stdin, output = process.stdout, errorOutput = process.stderr,
  signals = process, connect = net.createConnection } = {}) {
  const report = () => {
    if (!errorOutput?.write || errorOutput.destroyed || errorOutput.writableEnded || errorOutput.errored) return;
    let pending = true, failed = false, observedError = false, closed = false;
    const release = () => {
      if (pending || failed && !observedError && !closed) return;
      errorOutput.off?.('error', onError);
      errorOutput.off?.('close', onClose);
    };
    const onError = () => { observedError = true; release(); };
    const onClose = () => { closed = true; release(); };
    try {
      // A broken stderr can emit its error after the write callback. Keep a
      // temporary listener until that event, including an asynchronous destroy.
      errorOutput.on?.('error', onError);
      errorOutput.on?.('close', onClose);
      errorOutput.write(FAILURE, error => {
        pending = false;
        failed = Boolean(error || errorOutput.errored);
        release();
      });
    } catch { pending = false; release(); }
  };
  let start;
  try {
    if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || socketPath !== path.normalize(socketPath)
      || socketPath.length > 4096 || /[\x00-\x1f\x7f]/.test(socketPath)
      || !Array.isArray(argv) || argv.length < 1 || argv.length > 512
      || argv.some(value => typeof value !== 'string' || value.includes('\0'))
      || argv.reduce((total, value) => total + Buffer.byteLength(value), 0) > 64 * 1024
      || typeof tty !== 'boolean' || !size(cols) || !size(rows) || typeof connect !== 'function'
      || !input?.on || !input?.off || !input?.pause || !input?.resume
      || input.destroyed && !input.readableEnded
      || [output, errorOutput].some(stream => !stream?.on || !stream?.off || !stream?.write || stream.destroyed || stream.writableEnded)
      || !signals?.on || !signals?.off || tty && input.isTTY && typeof input.setRawMode !== 'function') throw new Error();
    start = `${JSON.stringify({ type: 'start', version: 1, argv, tty, cols, rows })}\n`;
    if (Buffer.byteLength(start) > MAX_LINE) throw new Error();
  } catch {
    report();
    return 255;
  }

  return new Promise(resolve => {
    let wire, timer, settled = false, connected = false, ready = false, remoteEnded = false;
    let incoming = Buffer.alloc(0), pendingInput = Buffer.alloc(0), inputOffset = 0;
    let inputEnded = Boolean(input.readableEnded), eofSent = false, wireBlocked = false;
    let rawChanged = false, originalRaw = Boolean(input.isRaw), exitCode = null;
    let outputBytes = 0, outputWrites = 0, outputBlocked = null;
    const outputStreams = [...new Set([output, errorOutput])];
    const pendingWrites = new Map(outputStreams.map(stream => [stream, 0]));
    const failedWrites = new Set(), observedErrors = new Set(), closedOutputs = new Set();
    const signalHandlers = new Map();

    const bufferedBytes = () => incoming.length + pendingInput.length - inputOffset
      + outputBytes + (wire?.writableLength || 0);
    const releaseOutputErrors = stream => {
      if (pendingWrites.get(stream)) return;
      // Writable emits a failed write's error after invoking its callback.
      // Its destroy hook may be asynchronous, so wait for the actual event.
      if ((failedWrites.has(stream) || stream.errored) && !observedErrors.has(stream) && !closedOutputs.has(stream)) return;
      stream.off('error', onStreamError);
      stream.off('close', onOutputClose);
    };
    const cleanup = () => {
      clearTimeout(timer);
      input.off('data', onInput);
      input.off('end', onInputEnd);
      input.off('error', onStreamError);
      input.off('close', onInputClose);
      try { input.pause(); } catch { /* Restoration must continue. */ }
      if (rawChanged) {
        try { input.setRawMode(originalRaw); } catch { /* The terminal may already be closed. */ }
      }
      for (const stream of outputStreams) {
        releaseOutputErrors(stream);
        stream.off('drain', onOutputDrain);
      }
      for (const [signal, handler] of signalHandlers) signals.off(signal, handler);
      wire?.off('data', onWireData);
      wire?.off('drain', onWireDrain);
      wire?.off('connect', onConnect);
      // Keep this owned socket's error listener while destroy completes.
      wire?.destroy();
      incoming = Buffer.alloc(0);
      pendingInput = Buffer.alloc(0);
    };
    const finish = code => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(code);
    };
    const fail = () => {
      if (settled) return;
      if (connected && !wire.destroyed && !wire.writableEnded && (wire.writableLength || 0) < MAX_BUFFER - 32) {
        try { wire.write('{"type":"cancel"}\n'); } catch { /* Disconnect also cancels. */ }
      }
      report();
      finish(255);
    };
    const complete = () => {
      if (exitCode !== null && outputWrites === 0) finish(exitCode);
    };
    const send = frame => {
      if (settled || !connected || wire.destroyed || wire.writableEnded) return false;
      const line = typeof frame === 'string' ? frame : `${JSON.stringify(frame)}\n`;
      if (Buffer.byteLength(line) > MAX_LINE || bufferedBytes() + Buffer.byteLength(line) > MAX_BUFFER) {
        fail();
        return false;
      }
      try {
        if (!wire.write(line)) {
          wireBlocked = true;
          input.pause();
        }
        return true;
      } catch { fail(); return false; }
    };
    const pumpInput = () => {
      if (settled || !ready || exitCode !== null) return;
      while (!wireBlocked && inputOffset < pendingInput.length) {
        const bytes = pendingInput.subarray(inputOffset, inputOffset + MAX_DATA);
        inputOffset += bytes.length;
        if (!send({ type: 'stdin', data: bytes.toString('base64') })) return;
      }
      if (inputOffset === pendingInput.length) {
        pendingInput = Buffer.alloc(0);
        inputOffset = 0;
      }
      if (wireBlocked) return;
      if (inputEnded) {
        if (!eofSent) { eofSent = true; send({ type: 'eof' }); }
      } else input.resume();
    };
    function onInput(chunk) {
      if (settled || exitCode !== null) return;
      try {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (bufferedBytes() + bytes.length > MAX_BUFFER) return fail();
        pendingInput = inputOffset < pendingInput.length
          ? Buffer.concat([pendingInput.subarray(inputOffset), bytes]) : bytes;
        inputOffset = 0;
        input.pause();
        pumpInput();
      } catch { fail(); }
    }
    function onInputEnd() { inputEnded = true; pumpInput(); }
    function onInputClose() { if (!inputEnded && !input.readableEnded) fail(); }
    function onStreamError() {
      if (pendingWrites.has(this)) observedErrors.add(this);
      fail();
      if (settled && pendingWrites.has(this)) releaseOutputErrors(this);
    }
    function onOutputClose() {
      closedOutputs.add(this);
      if (!settled) fail();
      releaseOutputErrors(this);
    }
    function onWireDrain() { wireBlocked = false; pumpInput(); }
    function onOutputDrain() {
      outputBlocked = null;
      consume();
      if (!settled && !outputBlocked) wire.resume();
    }
    const writeOutput = (stream, bytes) => {
      if (bufferedBytes() + bytes.length > MAX_BUFFER) return fail();
      outputBytes += bytes.length;
      outputWrites++;
      pendingWrites.set(stream, pendingWrites.get(stream) + 1);
      let accepted;
      try {
        accepted = stream.write(bytes, error => {
          outputBytes -= bytes.length;
          outputWrites--;
          pendingWrites.set(stream, pendingWrites.get(stream) - 1);
          if (error) { failedWrites.add(stream); fail(); }
          else complete();
          if (settled) releaseOutputErrors(stream);
        });
      } catch {
        outputBytes -= bytes.length;
        outputWrites--;
        pendingWrites.set(stream, pendingWrites.get(stream) - 1);
        return fail();
      }
      if (!accepted && !settled) {
        outputBlocked = stream;
        stream.once('drain', onOutputDrain);
        wire.pause();
      }
    };
    const handleFrame = frame => {
      if (!frame || typeof frame !== 'object' || Array.isArray(frame) || typeof frame.type !== 'string' || exitCode !== null) return fail();
      if (frame.type === 'error') {
        if (!exactKeys(frame, ['type', 'code']) || typeof frame.code !== 'string' || !ERROR_CODE.test(frame.code)) return fail();
        return fail();
      }
      if (frame.type === 'ready') {
        if (ready || !exactKeys(frame, ['type'])) return fail();
        ready = true;
        clearTimeout(timer);
        if (tty && input.isTTY) {
          rawChanged = true;
          try { input.setRawMode(true); } catch { return fail(); }
        }
        pumpInput();
        return;
      }
      if (!ready) return fail();
      if (frame.type === 'stdout' || frame.type === 'stderr') {
        if (!exactKeys(frame, ['type', 'data'])) return fail();
        const bytes = decodeData(frame.data);
        if (!bytes) return fail();
        // Empty frames carry no data. Do not create zero-byte Writable queue
        // entries whose callbacks would escape the byte-based buffer limit.
        if (bytes.length === 0) return;
        return writeOutput(frame.type === 'stdout' ? output : errorOutput, bytes);
      }
      if (frame.type === 'exit') {
        const keys = Object.hasOwn(frame, 'signal') ? ['type', 'code', 'signal'] : ['type', 'code'];
        if (!exactKeys(frame, keys) || !Number.isInteger(frame.code) || frame.code < 0 || frame.code > 255
          || Object.hasOwn(frame, 'signal') && (typeof frame.signal !== 'string' || !/^SIG[A-Z0-9]{1,20}$/.test(frame.signal))
          || incoming.length) return fail();
        exitCode = frame.code;
        input.pause();
        complete();
        return;
      }
      fail();
    };
    function consume() {
      while (!settled && !outputBlocked) {
        const newline = incoming.indexOf(10);
        if (newline < 0) {
          if (incoming.length >= MAX_LINE || remoteEnded && exitCode === null) fail();
          return;
        }
        if (newline + 1 > MAX_LINE) return fail();
        const line = incoming.subarray(0, newline);
        incoming = incoming.subarray(newline + 1);
        try {
          const text = line.toString('utf8');
          if (!line.equals(Buffer.from(text))) return fail();
          handleFrame(JSON.parse(text));
        } catch { return fail(); }
      }
    }
    function onWireData(chunk) {
      if (settled) return;
      if (bufferedBytes() + chunk.length > MAX_BUFFER || exitCode !== null) return fail();
      incoming = Buffer.concat([incoming, chunk]);
      consume();
    }
    function onConnect() {
      connected = true;
      send(start);
    }
    function onWireEnd() {
      remoteEnded = true;
      if (!settled && !outputBlocked) consume();
    }
    const onResize = () => {
      if (!ready || !tty || settled || exitCode !== null) return;
      const nextCols = output.columns ?? input.columns ?? cols;
      const nextRows = output.rows ?? input.rows ?? rows;
      if (size(nextCols) && size(nextRows)) send({ type: 'resize', cols: nextCols, rows: nextRows });
    };
    try {
      input.pause();
      input.on('data', onInput);
      input.on('end', onInputEnd);
      input.on('error', onStreamError);
      input.on('close', onInputClose);
      for (const stream of outputStreams) {
        stream.on('error', onStreamError);
        stream.on('close', onOutputClose);
      }
      for (const signal of SIGNALS) {
        const handler = () => { if (ready && exitCode === null) send({ type: 'signal', signal }); else fail(); };
        signalHandlers.set(signal, handler);
        signals.on(signal, handler);
      }
      signalHandlers.set('SIGWINCH', onResize);
      signals.on('SIGWINCH', onResize);
      wire = connect({ path: socketPath });
      wire.on('error', fail);
      wire.on('connect', onConnect);
      wire.on('data', onWireData);
      wire.on('drain', onWireDrain);
      wire.on('end', onWireEnd);
      wire.on('close', onWireEnd);
      timer = setTimeout(fail, 15_000);
    } catch { fail(); }
  });
}
