// The staged copy supports read-only inspection. System mutation is permitted
// only from the approved root-owned installation and its pinned Node runtime.
// The executable wrapper supplies no inherited env or caller-selected module.
import { fileURLToPath } from 'node:url';
import { MacOSPFController, dispatchPFRequest, PF_HELPER_PROTOCOL, PF_HELPER_VERSION } from './controller.mjs';

// Only fixed diagnostic values cross the root RPC boundary. This projection
// deliberately excludes Error.message/stack/cause and all native private data.
const failureStages = new Set(['register', 'inspect', 'lock', 'baseline', 'registry-lock', 'root-hook', 'group', 'group-allocation',
  'context', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
const nativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn',
  'front-handshake', 'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const nativeReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const operationReasons = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED', 'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED', 'NATIVE_NOTION_SUPPORTED_ARGUMENT_REFUSED', 'NATIVE_NOTION_SUPPORTED_PLIST_REFUSED', 'NATIVE_NOTION_SUPPORTED_VERSION_REFUSED', 'NATIVE_NOTION_SUPPORTED_SIGNATURE_REFUSED', 'NATIVE_NOTION_PLAN_ARGUMENT_REFUSED', 'NATIVE_NOTION_PLAN_REGISTRY_REFUSED', 'NATIVE_NOTION_PLAN_CONTEXT_REFUSED', 'NATIVE_NOTION_PLAN_REQUEST_REFUSED', 'NATIVE_NOTION_PLAN_SEALED_REFUSED', 'NATIVE_NOTION_PLAN_SUPPORTED_REFUSED', 'NATIVE_NOTION_PLAN_DIGEST_REFUSED', 'NATIVE_NOTION_PLAN_CDHASH_REFUSED', 'NATIVE_NOTION_PLAN_REQUIREMENT_REFUSED', 'NATIVE_NOTION_PLAN_DATA_REFUSED', 'NATIVE_NOTION_PLAN_ALLOCATION_REFUSED', 'NATIVE_NOTION_DATA_ARGUMENT_REFUSED', 'NATIVE_NOTION_DATA_ENTRY_REFUSED', 'NATIVE_NOTION_DATA_ANCESTOR_REFUSED', 'NATIVE_NOTION_DATA_LEAF_REFUSED', 'NATIVE_NOTION_DATA_DENY_REFUSED', 'NATIVE_NOTION_STAGE_ARGUMENT_REFUSED', 'NATIVE_NOTION_STAGE_AUTHORITY_REFUSED', 'NATIVE_NOTION_STAGE_ENTRY_REFUSED', 'NATIVE_NOTION_STAGE_SESSION_REFUSED', 'NATIVE_NOTION_STAGE_ORIGINAL_RUNNING_REFUSED', 'NATIVE_NOTION_STAGE_ACCOUNT_REFUSED', 'NATIVE_NOTION_STAGE_ENVIRONMENT_REFUSED', 'NATIVE_NOTION_STAGE_DATA_REFUSED', 'NATIVE_NOTION_STAGE_RECHECK_REFUSED', 'NATIVE_NOTION_STAGE_SPAWN_REFUSED', 'NATIVE_NOTION_STAGE_STOPPED_REFUSED', 'NATIVE_NOTION_STAGE_CHILD_REFUSED']);
const diagnosticCodes = new Set(['APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_NOT_READY', 'APPLICATION_PROXY_UNAVAILABLE',
  'APPLICATION_ROUTING_PROTOCOL_ERROR', 'APPLICATION_APP_CONTEXT_REFUSED', 'APPLICATION_APP_IDENTITY_REFUSED', 'APPLICATION_APP_NATIVE_REFUSED',
  'APPLICATION_APP_STAGE_UNCONFIRMED', 'APPLICATION_APP_TRANSPORT_UNCONFIRMED', 'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_STOP_TIMEOUT', 'APPLICATION_APP_RELEASE_TIMEOUT',
  'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED', 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const exactDiagnostic = (value, required, optional = []) => value && typeof value === 'object' && !Array.isArray(value) &&
  required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...required, ...optional].includes(key));
const nativeDiagnostic = value => exactDiagnostic(value, ['stage', 'reason', 'error']) && nativeStages.has(value.stage) &&
  (value.stage === 'register' ? nativeReasons.has(value.reason) : operationReasons.has(value.reason)) &&
  Number.isInteger(value.error) && value.error > 0 && value.error <= 1024 ? { stage: value.stage, reason: value.reason, error: value.error } : null;
const failureDiagnostic = value => exactDiagnostic(value, ['stage', 'code'], ['native']) && failureStages.has(value.stage) && diagnosticCodes.has(value.code) &&
  (!Object.hasOwn(value, 'native') || nativeDiagnostic(value.native)) ? { stage: value.stage, code: value.code,
    ...(Object.hasOwn(value, 'native') ? { native: nativeDiagnostic(value.native) } : {}) } : null;
export function projectPFHelperError(error) {
  const result = { code: /^APPLICATION_[A-Z_]+$/.test(error?.code ?? '') ? error.code : 'APPLICATION_ROUTING_PROTOCOL_ERROR',
    message: 'Mac application routing operation did not complete' };
  const native = nativeDiagnostic(error?.nativeFailure);
  if (native) result.nativeFailure = native;
  if (failureStages.has(error?.failureStage)) result.failureStage = error.failureStage;
  for (const key of ['initialFailure', 'cleanupFailure']) {
    const failure = failureDiagnostic(error?.[key]);
    if (failure) result[key] = failure;
  }
  return result;
}

export async function servePFHelper({ controller = new MacOSPFController(), input = process.stdin, output = process.stdout, maxBytes = 65536,
  signalSource = input === process.stdin ? process : null } = {}) {
  let buffer = Buffer.alloc(0), overLimit = false, closed = false, channelLost = false;
  const endChannel = () => { channelLost = true; closed = true; input.destroy?.(); };
  const reply = value => { if (!channelLost) try { output.write(`${JSON.stringify(value)}\n`); } catch { endChannel(); } };
  output.on?.('error', endChannel);
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) signalSource?.on(signal, endChannel);
  const dispatch = async bytes => {
    let request;
    try {
      if (bytes.length < 2 || bytes.length > maxBytes) throw new Error();
      request = JSON.parse(bytes.toString('utf8'));
      const result = await dispatchPFRequest(controller, request);
      reply({ protocol: PF_HELPER_PROTOCOL, version: PF_HELPER_VERSION, ok: true, id: request.id, result: result ?? {} });
    } catch (error) {
      reply({ protocol: PF_HELPER_PROTOCOL, version: PF_HELPER_VERSION, ok: false,
        id: typeof request?.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(request.id) ? request.id : null,
        error: projectPFHelperError(error) });
    }
  };
  try {
    for await (const chunk of input) {
      if (closed) break;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      // A malicious stream without newlines must not grow an unbounded buffer.
      if (buffer.length + bytes.length > maxBytes * 2) { overLimit = true; break; }
      buffer = Buffer.concat([buffer, bytes]);
      let newline;
      while ((newline = buffer.indexOf(10)) >= 0) {
        const line = buffer.subarray(0, newline); buffer = buffer.subarray(newline + 1);
        if (line.length > maxBytes) { overLimit = true; break; }
        if (line.length) await dispatch(line);
        if (controller.closed) { closed = true; break; }
      }
      if (buffer.length > maxBytes || overLimit) { overLimit = true; break; }
    }
    if (!overLimit && buffer.length && !closed) await dispatch(buffer);
    if (overLimit) reply({ protocol: PF_HELPER_PROTOCOL, version: PF_HELPER_VERSION, ok: false, id: null,
      error: { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR', message: 'Mac application routing request refused' } });
  } catch {
    channelLost = true;
  } finally {
    const result = await controller.shutdown().catch(() => ({ cleanupRequired: true }));
    // No raw errors, private endpoint credentials, usernames, user paths or
    // node passwords are printed to stderr during faults or recovery.
    if (result.cleanupRequired) process.exitCode = 1;
    output.removeListener?.('error', endChannel);
    for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) signalSource?.removeListener(signal, endChannel);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const controlled = process.argv.length === 5 && process.argv[2] === '--controlled-experiment' && process.argv[3] === '--caller-uid' && /^[1-9][0-9]{0,9}$/.test(process.argv[4]);
  if (!controlled && (process.argv.length !== 3 || !['--rpc', '--plan'].includes(process.argv[2]))) {
    process.stderr.write('Use the fixed helper RPC or read-only plan operation.\n'); process.exitCode = 2;
  } else if (process.argv[2] === '--plan') {
    const controller = new MacOSPFController();
    process.stdout.write(`${JSON.stringify(await controller.plan())}\n`); await controller.shutdown();
  } else if (controlled) {
    // Only the separately approved native Security authorizer starts this
    // fixed installed entry as root and derives UID from /dev/console. The
    // value is a bootstrap argument, never an RPC parameter or inherited env.
    const controller = new MacOSPFController({ identity: { uid: process.getuid?.() ?? -1, euid: process.geteuid?.() ?? -1,
      callerUID: Number(process.argv[4]), controlledSession: true } });
    await servePFHelper({ controller });
  } else await servePFHelper();
}
