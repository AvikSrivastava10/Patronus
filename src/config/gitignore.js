/**
 * .gitignore management.
 *
 * Keeps Clipeus's own generated artifacts (scan reports, cache) out of the
 * user's version control, so a scan never leaves committable clutter behind.
 * Deliberately does NOT ignore clipeus.config.json or a baseline file — those
 * are meant to be committed and shared with a team.
 *
 * Idempotent, additive, and never throws.
 */

import fs from 'node:fs';
import path from 'node:path';

const BEGIN = '# >>> clipeus >>>';
const END = '# <<< clipeus <<<';

/** Generated artifacts Clipeus may drop in a project that should not be committed. */
export const CLIPEUS_GITIGNORE_ENTRIES = Object.freeze([
  'clipeus-report.*',
  'clipeus.sarif',
  '.clipeus-cache/',
]);

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Ensure the project's .gitignore contains the given Clipeus entries. Only the
 * entries not already present anywhere in the file are appended, inside a marked
 * block. Re-running is a no-op once everything is present.
 *
 * @param {string} root  Project root.
 * @param {string[]} [entries]
 * @returns {{changed:boolean, created:boolean, added:string[], path:string, error?:string}}
 */
export function ensureGitignore(root, entries = CLIPEUS_GITIGNORE_ENTRIES) {
  const file = path.join(root, '.gitignore');

  let existing = '';
  let created = false;
  try {
    existing = fs.readFileSync(file, 'utf8');
  } catch {
    created = true; // no .gitignore yet — we'll create one
  }

  const isPresent = (entry) => new RegExp(`^\\s*${escapeRe(entry)}\\s*$`, 'm').test(existing);
  const added = entries.filter((e) => !isPresent(e));
  if (added.length === 0) {
    return { changed: false, created: false, added: [], path: file };
  }

  const block = [BEGIN, '# Clipeus security-scan generated files', ...added, END].join('\n');
  const needsNewline = existing && !existing.endsWith('\n');
  const body = existing ? `${existing}${needsNewline ? '\n' : ''}\n${block}\n` : `${block}\n`;

  try {
    fs.writeFileSync(file, body, 'utf8');
    return { changed: true, created, added, path: file };
  } catch (err) {
    return { changed: false, created: false, added: [], path: file, error: err.message };
  }
}
