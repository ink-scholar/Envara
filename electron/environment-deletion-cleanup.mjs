/** The profile is already deleted. Report remaining owned data without asking
 * the renderer to retry the irreversible profile deletion. */
export async function finishEnvironmentDeletion({ method, args, result, applications, eraseData, releaseImport }) {
  const ids = method === 'deleteProfile' ? [args.id] : method === 'bulkProfiles' && args.action === 'delete'
    ? [...new Set((result?.actionResult?.results ?? result?.results ?? []).filter(item => item.ok).map(item => item.id))] : [];
  if (!ids.length) return result;
  const incomplete = new Set();
  let bindings = [];
  if (applications) {
    try { bindings = (await applications.snapshot()).applications; }
    catch { for (const id of ids) incomplete.add(id); }
  }
  for (const id of ids) {
    for (const binding of bindings.filter(item => item.profileId === id)) {
      try { await applications.deleteApplication({ id: binding.id }); }
      catch { incomplete.add(id); }
    }
    // A binding that could not be retired may still own a process. Keep its
    // data until the user can resolve that state from Attached applications.
    if (incomplete.has(id)) continue;
    try { await eraseData(id); releaseImport(id); }
    catch { incomplete.add(id); }
  }
  if (!incomplete.size) return result;
  return { ...result, warnings: [...(result?.warnings ?? []), ...[...incomplete].map(profileId => ({
    code: 'ENVIRONMENT_APPLICATION_CLEANUP_INCOMPLETE', profileId,
  }))] };
}
