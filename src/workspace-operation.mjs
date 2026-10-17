/** A refresh failure is not evidence that an already successful action failed. */
export function workspaceOperationWarning(result) {
  if (result?.warnings?.some(item => item?.code === 'ENVIRONMENT_APPLICATION_CLEANUP_INCOMPLETE'))
    return '环境已删除，但部分附加软件绑定或应用数据未清理完成。请到「附加软件」检查并清理。';
  return null;
}

export async function completeWorkspaceOperation({ execute, acceptSnapshot, refresh }) {
  const result = await execute();
  if (acceptSnapshot(result) || result?.canceled || result?.needsPassword || result?.needsProxyMapping) {
    return { result, refreshFailed: false };
  }
  try {
    await refresh();
    return { result, refreshFailed: false };
  } catch {
    return { result, refreshFailed: true };
  }
}
