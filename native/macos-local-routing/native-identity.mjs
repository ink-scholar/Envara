import { spawn } from 'node:child_process'
import path from 'node:path'

export function createNativeInspector(executable) {
  if (!path.isAbsolute(executable)) throw new Error('absolute native verifier path required')
  const rejected = code => Object.assign(new Error('native verification rejected'), { code })
  function invoke(args, socket = null) {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, { stdio: ['ignore', 'pipe', 'pipe', ...(socket ? [socket] : [])], env: { PATH: '/usr/bin:/bin' } })
      let output = ''; let overflow = false
      const timer = setTimeout(() => { child.kill(); reject(rejected('NATIVE_VERIFIER_TIMEOUT')) }, 5000)
      child.stdout.on('data', bytes => { output += bytes; if (output.length > 16384) { overflow = true; child.kill() } })
      child.stderr.resume()
      child.once('error', () => { clearTimeout(timer); reject(rejected('NATIVE_VERIFIER_UNAVAILABLE')) })
      child.once('close', code => {
        clearTimeout(timer)
        try {
          const result = JSON.parse(output)
          if (code !== 0 || overflow || result.verified !== true) {
            const reason = !overflow && /^[A-Z][A-Z0-9_]{1,95}$/.test(result.reason ?? '') ? result.reason : 'NATIVE_VERIFIER_REJECTED'
            reject(rejected(reason)); return
          }
          resolve(result)
        } catch { reject(rejected('NATIVE_VERIFIER_INVALID_OUTPUT')) }
      })
    })
  }
  return Object.freeze({
    identity: async pid => {
      if (!Number.isInteger(pid) || pid < 2 || pid > 0x7fffffff) return Promise.reject(new Error('invalid PID'))
      const result = await invoke(['identity', String(pid)])
      if (result.pid !== pid || (result.alive !== true && result.alive !== false) ||
          (result.alive === false && result.reason !== 'not-found') ||
          (result.alive === true && (!Number.isInteger(result.uid) || !/^\d+:\d{6}$/.test(result.birth ?? '') || !path.isAbsolute(result.path ?? '')))) throw new Error('invalid native process evidence')
      return result
    },
    peer: socket => invoke(['peer'], socket),
  })
}
