// Private persistent JSON-lines RPC; default status/setup never activate NE.
import readline from 'node:readline'
import { MacOSLocalRoutingAdapter } from './controller.mjs'
const argument = name => process.argv.find(value => value.startsWith(`${name}=`))?.slice(name.length + 1)
const adapter = new MacOSLocalRoutingAdapter({ peerVerifierPath: argument('--peer-verifier'), bundledAppPath: argument('--bundled-app') })
const allowed = new Set(['status', 'setup', 'prepareRoute', 'launch', 'stop', 'revoke', 'shutdown'])
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of input) {
  let request
  try {
    if (Buffer.byteLength(line) > 64 * 1024) throw new Error('request size')
    request = JSON.parse(line)
    if (request.protocol !== 'envara.application-routing' || request.version !== 1 || typeof request.id !== 'string' || !allowed.has(request.method)) throw new Error('request envelope')
    const result = await adapter[request.method](request.params ?? {})
    process.stdout.write(`${JSON.stringify({ protocol: request.protocol, version: 1, id: request.id, result: result ?? { closed: true } })}\n`)
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ protocol: 'envara.application-routing', version: 1, id: request?.id ?? null, error: { code: /^APPLICATION_[A-Z_]+$/.test(error.code ?? '') ? error.code : 'APPLICATION_ROUTING_PROTOCOL_ERROR', message: 'Mac routing operation did not complete' } })}\n`)
  }
}
try { await adapter.shutdown() } catch { process.stderr.write('Selected processes remain; capture shutdown was refused.\n'); process.exitCode = 1 }
