#!/usr/bin/env node
/* Fetches the EasyPrivacy files the browser's tracker blocking uses, at one
 * pinned commit of https://github.com/easylist/easylist, and stores them byte
 * for byte next to the sidecar code that embeds them, with their hashes.
 *
 *   node scripts/update-tracker-list.mjs              # refetch the pinned commit
 *   node scripts/update-tracker-list.mjs --commit SHA # move to another commit
 *
 * The files are never edited: the sidecar parses the rule subset it supports
 * and skips the rest, so every active rule can be compared with upstream.
 * curl honours HTTPS_PROXY / https_proxy when GitHub needs a proxy. */
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = path.join(ROOT, 'third_party', 'browseforge', 'internal', 'browser', 'trackerlists', 'easyprivacy');
const PINNED_COMMIT = '93c1d90410ad8611bdcc80f44db520991b2a701f';
/* Third-party tracking hosts and their exceptions. Generic URL patterns,
 * site-specific first-party rules and CNAME lists are left out: the browser
 * blocks third-party requests only. */
export const EASYPRIVACY_FILES = Object.freeze([
  'easyprivacy/easyprivacy_trackingservers.txt',
  'easyprivacy/easyprivacy_trackingservers_general.txt',
  'easyprivacy/easyprivacy_trackingservers_thirdparty.txt',
  'easyprivacy/easyprivacy_trackingservers_international.txt',
  'easyprivacy/easyprivacy_trackingservers_admiral.txt',
  'easyprivacy/easyprivacy_trackingservers_mining.txt',
  'easyprivacy/easyprivacy_trackingservers_notifications.txt',
  'easyprivacy/easyprivacy_thirdparty.txt',
  'easyprivacy/easyprivacy_thirdparty_international.txt',
  'easyprivacy/easyprivacy_allowlist.txt',
  'easyprivacy/easyprivacy_allowlist_international.txt',
]);
const LICENCE = 'Unless otherwise noted, the contents of the EasyList repository (https://github.com/easylist) is dual licensed under the GNU General Public License version 3 of the License, or (at your option) any later version, and Creative Commons Attribution-ShareAlike 3.0 Unported, or (at your option) any later version. You may use and/or modify the files as permitted by either licence; if required, "The EasyList authors (https://easylist.to/)" should be attributed as the source of the material.';

const argument = name => { const index = process.argv.indexOf(name); return index > 0 ? process.argv[index + 1] : null; };
const commit = argument('--commit') ?? PINNED_COMMIT;
if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error('--commit must be a full 40-character commit hash.');

const staging = `${OUTPUT}.staging-${process.pid}`;
await rm(staging, { recursive: true, force: true });
await mkdir(staging, { recursive: true });
try {
  const files = [];
  for (const upstream of EASYPRIVACY_FILES) {
    const name = path.basename(upstream), target = path.join(staging, name);
    await execFile('/usr/bin/curl', ['-sSfL', '--max-time', '90', '-o', target, `https://raw.githubusercontent.com/easylist/easylist/${commit}/${upstream}`], { maxBuffer: 1024 * 1024 });
    const bytes = await readFile(target);
    if (!bytes.length || !bytes.toString('utf8').includes('||')) throw new Error(`${upstream} is empty or not a filter list.`);
    files.push({ upstream, name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  const provenance = { schema: 'envara.tracker-list', version: 1, list: 'EasyPrivacy', source: 'https://github.com/easylist/easylist', commit, files,
    licence: LICENCE, licenceSource: 'https://easylist.to/pages/licence.html', attribution: 'The EasyList authors (https://easylist.to/)' };
  await writeFile(path.join(staging, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  await writeFile(path.join(staging, 'NOTICE.md'), `# EasyPrivacy (bundled, unmodified)

These files are taken byte for byte from ${provenance.source} at commit \`${commit}\`; \`provenance.json\` lists each file's SHA-256.

Attribution: ${provenance.attribution}.

Licence (${provenance.licenceSource}):

> ${LICENCE}

Envara distributes them unmodified, under Creative Commons Attribution-ShareAlike 3.0 Unported (https://creativecommons.org/licenses/by-sa/3.0/) or, at the recipient's option, the GNU General Public License version 3 or later (https://www.gnu.org/licenses/gpl-3.0.html).
`);
  await rm(OUTPUT, { recursive: true, force: true });
  await rename(staging, OUTPUT);
  console.log(`EasyPrivacy ${commit.slice(0, 7)}: ${files.length} files, ${files.reduce((sum, file) => sum + file.bytes, 0)} bytes -> ${path.relative(ROOT, OUTPUT)}`);
} catch (error) {
  await rm(staging, { recursive: true, force: true });
  throw error;
}
