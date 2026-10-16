const browserActiveStates = new Set(['starting', 'running', 'stopping', 'closing']);

// Exporting browser data is independent of another consumer in its environment.
export function browserExportActive(profile, pending = {}) {
  return browserActiveStates.has(profile?.status) || Boolean(profile?.id &&
    (pending[`startProfile:${profile.id}`] || pending[`stopProfile:${profile.id}`]));
}

// The ref is updated before React renders the disabled buttons. All dismissal
// paths (close icon, Escape and backdrop) use this same in-flight reservation.
export function environmentTransferModalPending(modal, pending) {
  const has = key => typeof pending?.has === 'function' ? pending.has(key) : Boolean(pending?.[key]);
  if (modal?.type === 'exportData' && modal.profile?.id) return has(`exportEnvironment:${modal.profile.id}`);
  if (['importMapping', 'importPassword'].includes(modal?.type) && modal.session?.importId) return has(`importProfiles:${modal.session.importId}`);
  return false;
}

// Read only the validated IPC manifest scope, never infer it from a filename.
export function importedDataLabel(scope) {
  return { browser: '浏览器', terminal: '终端', application: '附加软件', environment: '环境' }[scope ?? 'environment'] ?? '导入数据';
}
