/**
 * Vendored-path filtering.
 *
 * External scanners (notably trufflehog's filesystem mode) walk everything on
 * disk, including third-party dependencies and caches. A secret or lint hit in
 * node_modules/.venv/vendor is not the user's code to fix and can't be rotated
 * by them, so it's noise. This module drops findings located inside clearly
 * third-party or cache directories.
 *
 * The list is deliberately CONSERVATIVE: it excludes only directories that are
 * unambiguously not the user's own source. Ambiguous dirs that can legitimately
 * hold user code or real secrets (env, bin, dist, build, out) are intentionally
 * NOT filtered — for a security tool, hiding a real finding is worse than a
 * little noise.
 */

/** Directory names whose contents are third-party or generated caches. */
export const VENDORED_DIRS = new Set([
  'node_modules',
  '.venv',
  'venv',
  'vendor',
  'site-packages',
  'bower_components',
  '__pycache__',
  '.git',
  '.cache',
  '.clipeus-cache',
  '.pytest_cache',
  '.mypy_cache',
  '.tox',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.gradle',
  '.terraform',
  '.serverless',
  '.nyc_output',
]);

/**
 * Whether a file path lies inside a vendored/generated directory.
 * Handles both absolute and relative paths, and both path separators.
 * @param {string} file
 * @returns {boolean}
 */
export function isVendoredPath(file) {
  if (!file) return false;
  const segments = String(file).replace(/\\/g, '/').split('/');
  return segments.some((s) => VENDORED_DIRS.has(s));
}

/**
 * Partition findings into those to keep and those dropped for living inside a
 * vendored directory.
 * @param {object[]} findings
 * @returns {{kept: object[], filtered: object[]}}
 */
export function filterVendoredFindings(findings) {
  const kept = [];
  const filtered = [];
  for (const f of findings || []) {
    if (isVendoredPath(f?.file)) filtered.push(f);
    else kept.push(f);
  }
  return { kept, filtered };
}
