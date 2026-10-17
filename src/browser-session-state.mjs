export function browserSessionControls(profile, runtime, { pending = {}, busy = false } = {}) {
  const running = profile?.status === 'running';
  const starting = profile?.status === 'starting' || Boolean(pending[`startProfile:${profile?.id}`]);
  const supported = Boolean(runtime) && runtime.supported !== false;
  const installing = Boolean(runtime?.installing || pending[`installEngine:${runtime?.id}`]);
  const action = running ? 'focus' : runtime?.installed ? 'start' : 'install';
  const label = running ? '打开' : starting ? '启动中…' : !supported ? '不可用'
    : installing ? '安装中…' : runtime.installed ? '启动' : '安装内核';
  return {
    running,
    starting,
    active: running || starting,
    action,
    label,
    detailLabel: { '打开': '打开浏览器', '启动': '启动浏览器', '安装内核': '安装浏览器内核' }[label] || label,
    primaryDisabled: Boolean(busy || starting || !running && (installing || !supported)),
    // Startup is serialized in the backend; Stop does not cancel preparation.
    stopDisabled: Boolean(busy || starting || !running),
  };
}
