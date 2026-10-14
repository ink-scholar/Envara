import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFileCallback);
const root = fileURLToPath(new URL('../', import.meta.url));
export const LINK_ROUTER_BUNDLE_ID = 'io.envara.link-router';
export const LINK_ROUTER_APP = 'EnvaraLinkRouter.app';

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>EnvaraLinkRouter</string>
<key>CFBundleIdentifier</key><string>${LINK_ROUTER_BUNDLE_ID}</string>
<key>CFBundleName</key><string>Envara Link Router</string>
<key>CFBundleDisplayName</key><string>Envara Link Router</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>CFBundleURLTypes</key><array><dict>
<key>CFBundleURLName</key><string>Web links</string>
<key>CFBundleTypeRole</key><string>Viewer</string>
<key>CFBundleURLSchemes</key><array><string>http</string><string>https</string></array>
</dict></array>
</dict></plist>
`;

/** Builds the dockless web-link router. It installs and registers nothing here;
 *  the application does that, with the user's confirmation, when they ask for
 *  links to leave through an environment. */
export async function buildMacOSLinkRouter() {
  if (process.platform !== 'darwin') throw new Error('Build the macOS link router on macOS.');
  const output = path.join(root, 'build/app-routing/macos-link-router');
  const source = path.join(root, 'native/macos-link-router/main.swift');
  await fs.mkdir(path.dirname(output), { recursive: true });
  const stage = await fs.mkdtemp(path.join(root, 'build/app-routing', '.link-router-'));
  const backup = `${output}.previous-${randomUUID()}`;
  let movedOld = false;
  try {
    await fs.chmod(stage, 0o700);
    const app = path.join(stage, LINK_ROUTER_APP), macos = path.join(app, 'Contents/MacOS');
    await fs.mkdir(macos, { recursive: true });
    await fs.writeFile(path.join(app, 'Contents/Info.plist'), infoPlist, { mode: 0o644 });
    await execute('/usr/bin/swiftc', ['-O', '-whole-module-optimization', '-o', path.join(macos, 'EnvaraLinkRouter'), source], { timeout: 240000, maxBuffer: 16 * 1024 * 1024 });
    /* Ad-hoc, like the rest of Envara's local build: LaunchServices accepts it,
     * and the user is not asked to buy a signing identity for a prototype. */
    await execute('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 60000 });
    await execute('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 30000 });
    const { stdout } = await execute(path.join(macos, 'EnvaraLinkRouter'), ['--status'], { timeout: 20000 });
    const status = JSON.parse(stdout || '{}');
    if (status.router !== LINK_ROUTER_BUNDLE_ID) throw new Error('The built link router reports an unexpected identity.');
    try { await fs.rename(output, backup); movedOld = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.rename(path.join(stage, LINK_ROUTER_APP), output);
    await fs.writeFile(path.join(path.dirname(output), 'macos-link-router.json'),
      `${JSON.stringify({ schema: 'envara.macos-link-router', version: 1, application: LINK_ROUTER_APP, bundleIdentifier: LINK_ROUTER_BUNDLE_ID }, null, 2)}\n`);
    await fs.rm(backup, { recursive: true, force: true });
    return { application: output };
  } catch (error) {
    if (movedOld) { await fs.rm(output, { recursive: true, force: true }).catch(() => {}); await fs.rename(backup, output).catch(() => {}); }
    throw error;
  } finally { await fs.rm(stage, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await buildMacOSLinkRouter().then(result => console.log(`link router: ${result.application}`)).catch(error => { console.error(error.message); process.exitCode = 1; });
