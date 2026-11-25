/** Engines Envara withholds on a platform even when the sidecar reports
 * support, because the pinned upstream runtime has a known blocking defect.
 *
 * BrowseForge Chromium v0.1.6-alpha.0 for windows-x64 ships no side-by-side
 * assembly manifest for chrome.exe (it cannot start: "side-by-side
 * configuration is incorrect"), and with that manifest supplied it still
 * reports the host timezone and Intl locale instead of the environment's.
 * Remove the hold only after an upstream runtime fixing both is pinned and
 * accepted on Windows. */
export const WINDOWS_BROWSEFORGE_CHROMIUM_HOLD = 'BrowseForge Chromium 暂不支持 Windows：其运行时缺少启动组件，且无法应用环境时区。请改用 CloakBrowser 或 Camoufox。';

export function enginePlatformHold(id, platform = process.platform) {
  return platform === 'win32' && id === 'browseforge-chromium' ? WINDOWS_BROWSEFORGE_CHROMIUM_HOLD : null;
}

/** Return a runtime descriptor as unsupported when it is held on this platform. */
export function withPlatformHold(descriptor, platform = process.platform) {
  const hold = enginePlatformHold(descriptor?.id, platform);
  return hold ? { ...descriptor, platform_supported: false, unsupported_reason: hold } : descriptor;
}
