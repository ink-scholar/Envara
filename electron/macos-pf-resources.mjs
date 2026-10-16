import path from 'node:path';
import { PF_NOTION_TRIAL_CARRIER } from './macos-pf-notion-trial.mjs';

/** Release builds reuse the complete pinned authorization carrier. Keeping a
 * second copy beside it added ~199 MB and allowed the two copies to drift.
 * Development keeps the ordinary build output; neither path activates it.
 */
export function bundledPFRoutingPaths(resourcesRoot, { packaged = true } = {}) {
  const authorizerPath = path.join(resourcesRoot, PF_NOTION_TRIAL_CARRIER);
  const directory = packaged ? path.dirname(authorizerPath) : path.join(resourcesRoot, 'app-routing/macos-pf');
  return { directory, helperPath: path.join(directory, 'EnvaraPFHelper'),
    installerPath: path.join(directory, 'EnvaraPFInstall'), authorizerPath };
}
