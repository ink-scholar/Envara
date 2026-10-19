import { TERMINAL_METHODS } from './terminal-controller.mjs';
import { terminalViewSnapshot } from './terminal-view.mjs';
import { environmentMutationProfile } from './environment-import-lifecycle.mjs';

const bootstrapReads = new Set(['snapshot', 'terminalSnapshot']);
const terminalProfileMethods = new Set(['chooseWorkspaceDirectory', 'pickTerminalDirectory', 'setTerminalLinkBrowser',
  'openTerminal', 'openTerminalWindow', 'listClaudeAccounts', 'createClaudeAccount', 'renameClaudeAccount', 'deleteClaudeAccount', 'claudeInstallationStatus',
  'listTerminalSshConnections', 'prepareTerminalSshIdentity', 'saveTerminalSshConnection', 'removeTerminalSshConnection']);
const terminalSessionMethods = new Set(['duplicateTerminal', 'writeTerminal', 'resizeTerminal', 'closeTerminal']);

async function assertTerminalScope(source, request, terminal) {
  if (request.method === 'terminalSnapshot') request.args = { ...request.args, id: source.profileId };
  if (terminalProfileMethods.has(request.method) && request.args?.id !== source.profileId) throw new Error('此窗口仅操作当前环境。');
  if (terminalSessionMethods.has(request.method)) {
    const current = await terminal.snapshot({ id: source.profileId });
    if (!current.profiles?.some(profile => profile.sessions?.some(session => session.sessionId === request.args?.sessionId)))
      throw new Error('该会话不属于此终端窗口。');
  }
}

/** Register once before opening a window. Startup reads may wait; actions never
 * queue behind initialization. Recheck authority after every asynchronous gate.
 */
export function registerDesktopIPC({ ipcMain, views, startup, lifecycle, services, transferLock,
  handleCall, fullWorkspaceSnapshot, onReady = () => {} }) {
  ipcMain.handle('envara:call', async (event, request) => {
    try {
      const source = views.get(event.sender);
      const sourceEpoch = lifecycle().requestEpoch;
      const assertSource = () => {
        if (!source || source !== views.get(event.sender) || source.window.isDestroyed() || event.sender.isDestroyed() || event.senderFrame !== event.sender.mainFrame)
          throw new Error('不允许的请求来源');
        const { quitting, requestEpoch } = lifecycle();
        if (quitting || sourceEpoch !== requestEpoch) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' });
      };
      assertSource();
      if (!request || typeof request.method !== 'string') throw new Error('无效请求');
      if (source.kind === 'terminal' && !TERMINAL_METHODS.has(request.method) && !['snapshot', 'openTerminalWindow'].includes(request.method))
        throw new Error('此窗口仅支持终端操作。');

      const dispatch = async () => {
        assertSource();
        if (source.kind === 'terminal') await assertTerminalScope(source, request, services().terminal);
        assertSource();
        startup.assertReady();
        const value = await fullWorkspaceSnapshot(await transferLock.mutate(request.method, request.args,
          () => { assertSource(); startup.assertReady(); return handleCall(request.method, request.args, source.window); },
          environmentMutationProfile(request.method, request.args, services())));
        assertSource();
        return { ok: true, value: source.kind === 'terminal' ? terminalViewSnapshot(value) : value };
      };
      if (bootstrapReads.has(request.method)) return await startup.read(dispatch);
      startup.assertReady();
      return await dispatch();
    } catch (error) { return { ok: false, error: { message: error.message, code: error.code || 'ACTION_FAILED' } }; }
  });
  onReady();
}
