// Bounded framing only. This module never resolves names or opens sockets.
export const notionSOCKSError = code => Object.assign(new Error(code), { code })
export class NotionSOCKSReader {
  constructor(socket, { signal, maxBuffered = 65536 } = {}) {
    this.socket = socket; this.buffer = Buffer.alloc(0); this.pending = null; this.failure = null; this.ended = false
    this.onData = bytes => {
      if (this.buffer.length + bytes.length > maxBuffered) { this.fail(notionSOCKSError('FRAME_LIMIT')); socket.destroy(); return }
      this.buffer = Buffer.concat([this.buffer, bytes]); this.flush()
    }
    this.onEnd = () => { this.ended = true; this.flush() }
    this.onClose = () => this.fail(notionSOCKSError('SOCKET_CLOSED'))
    this.onError = () => this.fail(notionSOCKSError('SOCKET_FAILED'))
    this.onAbort = () => { this.fail(notionSOCKSError('REVOKED')); socket.destroy() }
    this.signal = signal
    socket.on('data', this.onData); socket.on('end', this.onEnd); socket.on('close', this.onClose); socket.on('error', this.onError)
    if (signal?.aborted) this.onAbort(); else signal?.addEventListener('abort', this.onAbort, { once: true })
  }
  fail(error) { this.failure ??= error; if (this.pending) { const pending = this.pending; this.pending = null; clearTimeout(pending.timer); pending.reject(this.failure) } }
  flush() {
    if (!this.pending) return
    if (this.buffer.length >= this.pending.length) {
      const pending = this.pending; this.pending = null; clearTimeout(pending.timer)
      const bytes = Buffer.from(this.buffer.subarray(0, pending.length)); this.buffer = this.buffer.subarray(pending.length); pending.resolve(bytes)
    } else if (this.ended) this.fail(notionSOCKSError('FRAME_EOF'))
  }
  read(length, timeoutMs) {
    if (!Number.isInteger(length) || length < 1 || length > 4096 || this.pending) return Promise.reject(notionSOCKSError('FRAME_ARGUMENT'))
    if (this.failure) return Promise.reject(this.failure)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(notionSOCKSError('FRAME_TIMEOUT')), timeoutMs)
      this.pending = { length, resolve, reject, timer }; this.flush()
    })
  }
  release() {
    this.socket.pause()
    this.socket.off('data', this.onData); this.socket.off('end', this.onEnd); this.socket.off('close', this.onClose); this.socket.off('error', this.onError)
    this.signal?.removeEventListener('abort', this.onAbort)
    if (this.pending) this.fail(notionSOCKSError('READER_RELEASED'))
    if (this.buffer.length) this.socket.unshift(this.buffer)
    this.buffer = Buffer.alloc(0)
  }
}
