/** Pages limited to some platforms. Elsewhere they are hidden rather than
 * leading to an unsupported page; an unknown platform (the browser preview)
 * shows everything. */
export const PAGE_PLATFORMS = Object.freeze({ ssh: Object.freeze(['darwin']) });

export function pageAvailable(page, platform) {
  const platforms = PAGE_PLATFORMS[page];
  return !platforms || !platform || platforms.includes(platform);
}
