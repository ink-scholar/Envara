import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runMacOSAppProxyFixtureMatrix } from './macos-app-proxy-fixture-matrix.mjs';
import { validateAcceptanceBuild, createAcceptanceRPCTransport, acceptanceFailureReason } from './macos-app-proxy-acceptance-transport.mjs';

// Default: read-only plan. Every system or fixture operation has its own flag.
// No result from this tool can create a production routing acceptance receipt.
const root = fileURLToPath(new URL('../', import.meta.url));
export function parseAcceptanceArguments(args) {
  if (!Array.isArray(args) || args.length > 1 || args.some(value => !['--setup-profiles', '--activate-extension', '--run-fixtures'].includes(value))) {
    throw Object.assign(new Error('Invalid owned fixture arguments'), { code: 'ACCEPTANCE_ARGUMENT_INVALID' });
  }
  return args[0] === '--run-fixtures' ? 'runFixtures' : args[0] === '--setup-profiles' ? 'setupProfiles' : args[0] === '--activate-extension' ? 'activateExtension' : 'status';
}
async function writeReport(directory, report) {
  await fs.mkdir(directory, { recursive: true });
  const operationName = report.operation === 'runOwnedAppProxyFixtures' ? 'native-fixtures' : report.operation === 'status' ? 'plan' : report.operation === 'activateExtension' ? 'activation' : 'setup-profiles';
  const filename = path.join(directory, `app-proxy-acceptance-${operationName}.json`);
  try { const existing = await fs.lstat(filename); if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1) throw new Error('unsafe report'); }
  catch (error) { if (error.code !== 'ENOENT') throw Object.assign(new Error('Report refused'), { code: 'ACCEPTANCE_REPORT_FAILED' }); }
  const temporary = path.join(directory, `.app-proxy-${randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    if (operationName === 'native-fixtures') {
      const archive = path.join(directory, `app-proxy-acceptance-native-fixtures-${new Date().toISOString().replaceAll(':', '-')}-${randomUUID()}.json`);
      await fs.copyFile(temporary, archive, constants.COPYFILE_EXCL); await fs.chmod(archive, 0o600);
    }
    await fs.rename(temporary, filename);
  } catch { await fs.unlink(temporary).catch(() => {}); throw Object.assign(new Error('Report failed'), { code: 'ACCEPTANCE_REPORT_FAILED' }); }
}

export async function runAcceptanceCLI({ args = [], projectRoot = root, loadBuild = validateAcceptanceBuild,
  makeCall = createAcceptanceRPCTransport, runMatrix = runMacOSAppProxyFixtureMatrix,
  saveReport = writeReport, platform = process.platform, osRelease = os.release(),
} = {}) {
  const operation = parseAcceptanceArguments(args);
  const build = await loadBuild(path.join(projectRoot, 'build/acceptance-app-routing/macos'));
  const call = makeCall({ helperPath: build.helperPath, identifiers: build.identifiers });
  let report;
  if (operation === 'runFixtures') {
    report = await runMatrix({ call, identifiers: build.identifiers });
    report.helperMaximumTeardownGraceMs = call.maximumTeardownGraceMs;
    report.maximumMatrixSecondsIncludingUnconfirmedHelperTeardown = report.maximumMatrixSeconds + (call.maximumTeardownGraceMs ?? 0) / 1000;
  } else {
    const result = await call(operation, operation === 'activateExtension' ? { activate: true } : {});
    report = {
      schemaVersion: 1, recordedAt: new Date().toISOString(), operation,
      acceptanceOnly: true, productionReady: false, productionReceiptAllowed: false,
      authorized: result.authorized === true, extensionEnabled: result.extensionEnabled === true,
      runtimeNamespace: build.runtimeNamespace, profilePath: result.profilePath,
      requiresUserApproval: result.requiresUserApproval === true,
      changesVPNOrTUN: false, launchesNotion: false, fixtureProcessesStarted: false,
      nativeChecks: { tcp: false, halfClose: false, udp: false, dnsPerRealm: false, sameHostnameCache: false,
        childProcesses: false, firstPacket: false, guardCrash: false, providerCrash: false, unaffectedApplications: false },
      transport: result.transport,
      requiredFixtureMatrix: ['two simultaneous exact-path realms', 'same system hostname and warm cache',
        'parent, child and detached helper', 'TCP half-close', 'UDP proxy and block', 'first packet',
        'upstream failure and rebind', 'whole guardian and provider crash', 'unbound existing and new connections'],
    };
  }
  report.platform = platform; report.osRelease = osRelease;
  report.build = { runtimeNamespace: build.runtimeNamespace, ...build.identifiers, signed: build.signed,
    signingMode: build.signingMode, bytesVerified: build.bytesVerified, appleAuthorizationVerifiedByBuildInspection: false,
    helperSHA256: build.helperSHA256, provider: build.provider, fixtures: build.fixtures };
  if (call.mutationBlocked) report.helperExitUncertaintyBlocksFurtherMutations = true;
  await saveReport(path.join(projectRoot, 'test-artifacts/mac-routing'), report);
  return { report, exitCode: report.error || (operation === 'runFixtures' && report.testedFixtureSubsetPassed !== true) ? 2 : 0 };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await runAcceptanceCLI({ args: process.argv.slice(2) });
    console.log(JSON.stringify(result.report, null, 2)); process.exitCode = result.exitCode;
  } catch (error) { console.error(acceptanceFailureReason(error)); process.exitCode = 1; }
}
