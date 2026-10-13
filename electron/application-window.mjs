import { execFile } from 'node:child_process';

const REGISTRY_OBJECTS = '/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/';
const KEEPER = '/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native';
const failed = (code, message) => Object.assign(new Error(message), { code });

/** The running managed instance of one registration in a `ps -axo
 * pid=,ppid=,uid=,comm=` listing: the main executable of its sealed copy,
 * started by the root keeper and running as this user. Helpers, other
 * registrations, an unrelated parent or another user never match, and more
 * than one match is no answer. */
export function managedApplicationProcess(listing, { registrationId, uid }) {
  if (typeof listing !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(registrationId ?? '') || !Number.isSafeInteger(uid)) return null;
  const rows = listing.split('\n').map(line => /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\/.+?)\s*$/.exec(line)).filter(Boolean)
    .map(([, pid, ppid, owner, command]) => ({ pid: Number(pid), ppid: Number(ppid), uid: Number(owner), command }));
  const keepers = new Set(rows.filter(row => row.uid === 0 && row.command === KEEPER).map(row => row.pid));
  const prefix = `${REGISTRY_OBJECTS}${registrationId}/`;
  const matches = rows.filter(row => row.uid === uid && keepers.has(row.ppid) && row.command.startsWith(prefix) &&
    /\.app\/Contents\/MacOS\/[^/]+$/.test(row.command) && !row.command.slice(prefix.length).includes('/Contents/Frameworks/'));
  return matches.length === 1 ? matches[0].pid : null;
}

/* A reopen Apple Event addressed to one process id is what a Dock click sends.
 * Addressed by pid it can only reach that running instance: if the instance is
 * gone the event fails, and nothing is ever launched outside the environment,
 * unlike opening the bundle or its identifier would. */
const REOPEN = `ObjC.import('AppKit');
function run(argv) {
  const pid = Number(argv[0]);
  const target = $.NSAppleEventDescriptor.descriptorWithProcessIdentifier(pid);
  const event = $.NSAppleEventDescriptor.appleEventWithEventClassEventIDTargetDescriptorReturnIDTransactionID(0x61657674, 0x72617070, target, -1, 0);
  const error = $();
  event.sendEventWithOptionsTimeoutError(0x43, 60, error);
  const code = error.isNil() ? 0 : Number(error.code);
  const running = $.NSRunningApplication.runningApplicationWithProcessIdentifier(pid);
  if (code === 0 && !running.isNil()) running.activateWithOptions(3);
  return String(code);
}`;

export async function showManagedApplicationWindow({ registrationId, uid = process.getuid?.(), run = execFile } = {}) {
  const command = (file, args) => new Promise((resolve, reject) => run(file, args, { timeout: 65000, env: { PATH: '/usr/bin:/bin' } },
    (error, stdout) => error && !stdout ? reject(error) : resolve(String(stdout ?? '').trim())));
  const pid = managedApplicationProcess(await command('/bin/ps', ['-axo', 'pid=,ppid=,uid=,comm=']).catch(() => ''), { registrationId, uid });
  if (!pid) throw failed('APPLICATION_WINDOW_UNAVAILABLE', '软件没有在境舱中运行。');
  const code = Number(await command('/usr/bin/osascript', ['-l', 'JavaScript', '-e', REOPEN, String(pid)]).catch(() => 'NaN'));
  // errAEEventNotPermitted / errAEEventWouldRequireUserConsent: macOS consent.
  if (code === -1743 || code === -1744) throw failed('APPLICATION_WINDOW_NOT_PERMITTED', 'macOS 未允许境舱控制这个软件。请在“系统设置 › 隐私与安全性 › 自动化”中允许，或点程序坞里的图标。');
  if (code !== 0) throw failed('APPLICATION_WINDOW_UNAVAILABLE', '软件没有在境舱中运行。');
  return { shown: true };
}
