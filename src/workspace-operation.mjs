/** A refresh failure is not evidence that an already successful action failed. */
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
