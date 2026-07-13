/**
 * Read-only recursive filesystem walker.
 *
 * Shared by project detection, the standalone checkers, and the taint tracker.
 * Skips well-known dependency/build/VCS directories, avoids symlink cycles, and
 * never throws on permission errors (the offending entry is simply skipped).
 */

import fs from 'node:fs';
import path from 'node:path';
import { log } from './logger.js';

/** Directory names that are never worth scanning. */
export const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage',
  '.nyc_output', '.venv', 'venv', 'env', '__pycache__', '.next', '.nuxt',
  '.svelte-kit', 'vendor', 'target', 'bin', 'obj', '.gradle', '.idea',
  '.vscode', '.patronus-cache', '.terraform', '.serverless', '.cache',
  'bower_components', '.pytest_cache', '.mypy_cache', '.tox', 'site-packages',
]);

/**
 * Walk a directory tree, returning absolute file paths.
 *
 * @param {string} root
 * @param {Object} [opts]
 * @param {Set<string>|string[]} [opts.ignoreDirs] Extra dir names to skip.
 * @param {string[]} [opts.extensions] If set, only files with these extensions
 *        (lowercase, with dot, e.g. ['.js', '.ts']) are returned.
 * @param {number} [opts.maxDepth=Infinity]
 * @param {number} [opts.maxFiles=50000] Safety cap to bound huge repos.
 * @param {(name:string)=>boolean} [opts.nameFilter] Optional basename filter.
 * @returns {string[]}
 */
export function walk(root, opts = {}) {
  const {
    ignoreDirs,
    extensions,
    maxDepth = Infinity,
    maxFiles = 50_000,
    nameFilter,
  } = opts;

  const ignored = new Set(DEFAULT_IGNORED_DIRS);
  if (ignoreDirs) {
    for (const d of ignoreDirs) ignored.add(d);
  }
  const extSet = extensions ? new Set(extensions.map((e) => e.toLowerCase())) : null;

  const results = [];
  const visited = new Set();

  /** @param {string} dir @param {number} depth */
  function recurse(dir, depth) {
    if (results.length >= maxFiles) return;
    let real;
    try {
      real = fs.realpathSync(dir);
    } catch {
      return;
    }
    if (visited.has(real)) return; // symlink cycle guard
    visited.add(real);

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      log.debug(`walk: cannot read ${dir} (${err.code || err.message})`);
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      const full = path.join(dir, entry.name);

      let isDir = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        try {
          const st = fs.statSync(full);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch {
          continue; // broken symlink
        }
      }

      if (isDir) {
        if (ignored.has(entry.name)) continue;
        if (depth < maxDepth) recurse(full, depth + 1);
      } else if (isFile) {
        if (nameFilter && !nameFilter(entry.name)) continue;
        if (extSet) {
          const ext = path.extname(entry.name).toLowerCase();
          if (!extSet.has(ext)) continue;
        }
        results.push(full);
      }
    }
  }

  try {
    const st = fs.statSync(root);
    if (st.isFile()) return [root];
  } catch {
    return [];
  }

  recurse(root, 0);
  return results;
}

/**
 * List only the immediate entries of a directory (names). Never throws.
 * @param {string} dir
 * @returns {{ files: string[], dirs: string[] }}
 */
export function listTopLevel(dir) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const files = [];
    const dirs = [];
    for (const e of entries) {
      if (e.isDirectory()) dirs.push(e.name);
      else if (e.isFile()) files.push(e.name);
      else if (e.isSymbolicLink()) {
        try {
          const st = fs.statSync(path.join(dir, e.name));
          (st.isDirectory() ? dirs : files).push(e.name);
        } catch {
          /* skip broken symlink */
        }
      }
    }
    return { files, dirs };
  } catch {
    return { files: [], dirs: [] };
  }
}
