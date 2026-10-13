import path from 'node:path';

const validPath = value => typeof value === 'string' && path.isAbsolute(value) && value.length <= 4096 && !/[\0\r\n]/.test(value);

/** The system's own icon for an application bundle, as a small PNG data URL.
 * Only a bundle that the local catalog listed or a saved binding holds is
 * rendered, so the renderer can never use icons to probe arbitrary paths.
 * Icons are cached per path, rendered a few at a time, and a missing or
 * unreadable icon is null, never an error. */
export function createApplicationIcons({ render, isKnown, concurrency = 4, maximum = 512 } = {}) {
  if (typeof render !== 'function' || typeof isKnown !== 'function' || !Number.isSafeInteger(concurrency) || concurrency < 1 ||
      !Number.isSafeInteger(maximum) || maximum < 1) throw new TypeError('Invalid application icon options');
  const cache = new Map(), waiting = [];
  let running = 0;
  const next = () => {
    while (running < concurrency && waiting.length) {
      const { target, resolve } = waiting.shift(); running++;
      Promise.resolve().then(() => render(target)).then(value => typeof value === 'string' && value.startsWith('data:image/png;base64,') ? value : null, () => null)
        .then(value => { running--; resolve(value); next(); });
    }
  };
  return async function applicationIcon({ path: target } = {}) {
    if (!validPath(target) || !(await isKnown(target))) return { icon: null };
    if (!cache.has(target)) {
      if (cache.size >= maximum) cache.delete(cache.keys().next().value);
      cache.set(target, new Promise(resolve => { waiting.push({ target, resolve }); next(); }));
    }
    return { icon: await cache.get(target) };
  };
}

/** Electron's renderer for a bundle icon. A Quick Look thumbnail is the full
 * resolution icon; the file icon is the fallback. getFileIcon's 'large' size
 * aborts the process on macOS, so only 'normal' is ever requested. */
export function electronApplicationIcon({ app, nativeImage, size = 96 }) {
  return async target => {
    let image = null;
    try { image = await nativeImage.createThumbnailFromPath(target, { width: 128, height: 128 }); } catch { image = null; }
    if (!image || image.isEmpty()) image = await app.getFileIcon(target, { size: 'normal' });
    return image && !image.isEmpty() ? image.resize({ width: size, height: size, quality: 'best' }).toDataURL() : null;
  };
}
