export const NEW_CLAUDE_ACCOUNT = '__new__';

export function claudeAccountLabel(account, t) {
  return account.default && account.name === '默认' ? t('默认档案') : account.name;
}

export function reconcileClaudeAccountChoice(items, accountId) {
  if (accountId === NEW_CLAUDE_ACCOUNT || items.some(account => account.id === accountId)) return accountId;
  return items.find(account => account.default)?.id ?? items[0]?.id ?? NEW_CLAUDE_ACCOUNT;
}

const downloadErrors = {
  CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE: '本机未找到可用的 Claude 原生安装，请选择下载独立安装。',
  CLAUDE_CODE_INSTALLATION_INVALID: '境舱的 Claude 安装无效，请检查其本地安装后重试；未改用本机版本。',
  CLAUDE_CODE_INSTALLATION_CLEANUP_FAILED: 'Claude 安装临时文件清理未完成，请重试关闭会话。',
  CLAUDE_CODE_DOWNLOAD_ROUTE_REQUIRED: 'Claude 下载需要此境舱可用的代理线路。',
  CLAUDE_CODE_DOWNLOAD_FAILED: 'Claude 下载失败，请检查网络后重试。',
  CLAUDE_CODE_DOWNLOAD_TIMEOUT: 'Claude 下载超时，请重试。',
  CLAUDE_CODE_DOWNLOAD_CANCELLED: 'Claude 下载已取消。',
  CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED: 'Claude 下载大小或校验值不一致，请重试。',
  CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED: '无法验证 Claude 官方程序签名，请重试。',
  CLAUDE_CODE_PLATFORM_UNSUPPORTED: '当前平台尚不支持 Claude 专用安装。',
};

export const claudeErrorMessage = (message, code) => downloadErrors[code] ?? downloadErrors[message] ?? message;

export function validClaudeInstallationChoice(installation, profileId, source) {
  return Boolean(profileId && installation.profileId === profileId && installation.status === 'ready'
    && (installation.installed || source === 'download' || source === 'local'));
}

export function claudeInstallationOptions(installation, profileId, source) {
  if (!validClaudeInstallationChoice(installation, profileId, source)) throw new Error('无法读取 Claude 安装状态，请重试。');
  return installation.installed ? {} : { claudeInstallSource: source };
}

export function validClaudeAccountChoice(accounts, profileId, choice) {
  if (!profileId || accounts.profileId !== profileId || accounts.status !== 'ready') return false;
  return choice.accountId === NEW_CLAUDE_ACCOUNT
    ? Boolean(choice.accountName?.trim())
    : accounts.items.some(account => account.id === choice.accountId);
}

export function claudeSessionForRequest(profiles, profileId, requestId) {
  if (!profileId || !requestId) return null;
  return profiles.find(profile => profile.profileId === profileId)?.sessions?.find(session => session.requestId === requestId && session.kind === 'claude-code') ?? null;
}

export function claudeInstallPresentation(installation) {
  const label = { metadata: '准备安装 Claude…', downloading: '下载 Claude…', verifying: '验证安装包…', installing: '安装 Claude…' }[installation?.phase];
  if (!label) return null;
  const received = Number(installation.receivedBytes), total = Number(installation.totalBytes);
  const percent = installation.phase === 'downloading' && Number.isFinite(received) && received >= 0 && Number.isFinite(total) && total > 0
    ? Math.max(0, Math.min(100, Math.floor(received / total * 100))) : null;
  return { label, percent };
}
