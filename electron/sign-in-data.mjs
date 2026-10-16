import path from 'node:path';
import { readFile, writeFile, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { pfAttachEnvironmentId, pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';

const MAX_NAMES = 256;
const registrationOf = application => { try { return pfApplicationRegistrationId(application.path); } catch { return null; } };
const environmentOf = profileId => { try { return pfAttachEnvironmentId(profileId); } catch { return null; } };

/** The application data list shown to the user: one row per environment and
 * application that has data on disk, or that is attached there now. Names of
 * applications that were removed come from the remembered index; nothing here
 * reads the data itself beyond its size. */
export function signInDataRows({ applications = [], profiles = [], names = {}, inventory = [], running = new Set() } = {}) {
  const profilesByEnvironment = new Map(profiles.map(profile => [environmentOf(profile.id), profile]).filter(([id]) => id));
  const bindings = new Map();
  for (const application of applications) {
    const registrationId = registrationOf(application), environmentId = environmentOf(application.profileId);
    if (registrationId && environmentId) bindings.set(`${environmentId}:${registrationId}`, application);
  }
  const rows = new Map();
  for (const item of inventory) {
    if (item.dataScope !== 'environment' || item.hasDataDirectory !== true) continue;
    const id = `${item.environmentId}:${item.registrationId}`;
    rows.set(id, { id, environmentId: item.environmentId, registrationId: item.registrationId,
      dataScope: 'environment', hasDataDirectory: true, bytes: item.bytes, modifiedAt: item.modifiedAt ?? null });
  }
  for (const [id, application] of bindings) if (!rows.has(id)) {
    const [environmentId, registrationId] = id.split(':');
    rows.set(id, { id, environmentId, registrationId, dataScope: 'unavailable', hasDataDirectory: false, bytes: 0, modifiedAt: null });
  }
  return [...rows.values()].map(row => {
    const binding = bindings.get(row.id), profile = profilesByEnvironment.get(row.environmentId), remembered = names[row.registrationId];
    return { ...row, environment: profile ? { id: profile.id, name: profile.name } : null,
      application: binding ? { name: binding.name, path: binding.path, bindingId: binding.id }
        : remembered ? { name: remembered.name, path: remembered.path, bindingId: null } : null,
      running: running.has(row.id) };
  }).filter(row => row.hasDataDirectory || row.application?.bindingId)
    .sort((a, b) => (a.environment?.name ?? '￿').localeCompare(b.environment?.name ?? '￿') || (a.application?.name ?? '').localeCompare(b.application?.name ?? ''));
}

/** Remembers each attached application's name by its registration, so its
 * sign-in data can still be named after the application is removed. */
export class SignInDataNames {
  constructor({ dataDir }) { this.file = path.join(dataDir, 'attached-application-names.json'); this.cache = null; this.queue = Promise.resolve(); }
  async read() {
    if (this.cache) return this.cache;
    try { const value = JSON.parse(await readFile(this.file, 'utf8')); this.cache = value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
    catch { this.cache = {}; }
    return this.cache;
  }
  remember(applications = []) {
    const task = this.queue.then(async () => {
      const names = { ...await this.read() };
      let changed = false;
      for (const application of applications) {
        const registrationId = registrationOf(application);
        if (!registrationId || typeof application.name !== 'string') continue;
        const entry = { name: application.name.slice(0, 100), path: application.path };
        if (names[registrationId]?.name !== entry.name || names[registrationId]?.path !== entry.path) { names[registrationId] = entry; changed = true; }
      }
      const keys = Object.keys(names);
      if (keys.length > MAX_NAMES) for (const key of keys.slice(0, keys.length - MAX_NAMES)) { delete names[key]; changed = true; }
      if (changed) {
        const temporary = `${this.file}.${randomUUID()}.tmp`;
        try {
          await writeFile(temporary, `${JSON.stringify(names)}\n`, { mode: 0o600, flag: 'wx' });
          await rename(temporary, this.file);
        } finally { await rm(temporary, { force: true }); }
      }
      this.cache = names;
      return names;
    });
    this.queue = task.catch(() => {});
    return task;
  }
}

/** Data stays occupied until both the process and its route are confirmed clean. */
export function signInDataInUse(application) {
  return !!application && (['starting', 'running', 'stopping'].includes(application.status) ||
    !!application.sessionId || !!application.routeId || application.cleanupUncertain === true);
}

/** The environment and registration a live attachment occupies. */
export function runningSignInDataId(application) {
  const registrationId = application && registrationOf(application), environmentId = application && environmentOf(application.profileId);
  return registrationId && environmentId ? `${environmentId}:${registrationId}` : null;
}
