/**
 * Inline suppression comments (ESLint-style, for any language).
 *
 * Directives (recognized in //, #, /* *​/, <!-- -->, --, ; comments):
 *   clipeus-disable                 suppress every finding in the file
 *   clipeus-disable-file            same as above
 *   clipeus-disable-line   [ids]    suppress findings on this line
 *   clipeus-disable-next-line [ids] suppress findings on the following line
 *
 * `[ids]` is an optional comma/space-separated list of rule ids, categories, or
 * tool ids. With no ids, all findings at that scope are suppressed. This lets a
 * developer acknowledge a finding at the exact spot, with a reason, rather than
 * only via a project-wide .clipeusignore.
 *
 * Read-only: only reads the referenced source files. Never throws.
 */

import fs from 'node:fs';
import path from 'node:path';
import { log } from '../core/logger.js';

const DIRECTIVE_RE =
  /clipeus-disable(-next-line|-line|-file)?(?:[ \t:]+([^\r\n*]*?))?(?:\s*(?:\*\/|-->|$))/i;

/** Parse "[ids]" text into a lowercase Set, or null meaning "all". */
function parseIds(text) {
  if (!text) return null;
  const ids = text
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return ids.length ? new Set(ids) : null;
}

/** Does a directive id set match a finding? (null = matches all). */
function idsMatch(idSet, finding) {
  if (!idSet) return true;
  return (
    idSet.has(String(finding.ruleId).toLowerCase()) ||
    idSet.has(String(finding.category).toLowerCase()) ||
    idSet.has(String(finding.tool).toLowerCase())
  );
}

/**
 * Parse directives from a file's lines.
 * @returns {{ fileWide: (Set|null)|false, byLine: Map<number, (Set|null)> }}
 *   fileWide === false means "no file-wide directive"; otherwise it's the id set
 *   (or null for all). byLine maps 1-based line -> id set (or null).
 */
function parseDirectives(lines) {
  let fileWide = false;
  const byLine = new Map();

  const mergeLine = (lineNo, idSet) => {
    if (byLine.has(lineNo)) {
      const existing = byLine.get(lineNo);
      // If either is "all" (null), the merged scope is "all".
      if (existing === null || idSet === null) byLine.set(lineNo, null);
      else byLine.set(lineNo, new Set([...existing, ...idSet]));
    } else {
      byLine.set(lineNo, idSet);
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DIRECTIVE_RE);
    if (!m) continue;
    const kind = (m[1] || '').toLowerCase();
    const idSet = parseIds(m[2]);

    if (kind === '-file' || kind === '') {
      // "clipeus-disable" (no suffix) and "-file" are file-wide.
      fileWide = fileWide === false ? idSet : mergeSets(fileWide, idSet);
    } else if (kind === '-line') {
      mergeLine(i + 1, idSet);
    } else if (kind === '-next-line') {
      mergeLine(i + 2, idSet);
    }
  }
  return { fileWide, byLine };
}

function mergeSets(a, b) {
  if (a === null || b === null) return null;
  return new Set([...a, ...b]);
}

/**
 * Filter findings using inline directives found in their source files.
 * @param {object[]} findings
 * @param {string} root  scan root (findings' file paths are relative to it)
 * @returns {{ kept: object[], suppressed: object[] }}
 */
export function applyInlineSuppressions(findings, root) {
  if (!findings.length) return { kept: findings, suppressed: [] };

  // Group by file to read each file at most once.
  const byFile = new Map();
  for (const f of findings) {
    if (!f.file) continue;
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  const directivesCache = new Map();
  const getDirectives = (relFile) => {
    if (directivesCache.has(relFile)) return directivesCache.get(relFile);
    let parsed = { fileWide: false, byLine: new Map() };
    try {
      const abs = path.isAbsolute(relFile) ? relFile : path.join(root, relFile);
      const text = fs.readFileSync(abs, 'utf8');
      if (text.includes('clipeus-disable')) {
        parsed = parseDirectives(text.split(/\r?\n/));
      }
    } catch (err) {
      log.debug(`inline-suppress: cannot read ${relFile} (${err.message})`);
    }
    directivesCache.set(relFile, parsed);
    return parsed;
  };

  const kept = [];
  const suppressed = [];
  for (const f of findings) {
    if (!f.file) {
      kept.push(f);
      continue;
    }
    const { fileWide, byLine } = getDirectives(f.file);
    let drop = false;
    if (fileWide !== false && idsMatch(fileWide, f)) {
      drop = true;
    } else if (f.line != null && byLine.has(f.line) && idsMatch(byLine.get(f.line), f)) {
      drop = true;
    }
    (drop ? suppressed : kept).push(f);
  }

  return { kept, suppressed };
}
