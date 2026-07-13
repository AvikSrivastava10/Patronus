/**
 * .patronusignore parsing + suppression.
 *
 * Syntax is gitignore-like, with three suppression dimensions:
 *   - path globs (default):      src/legacy/**, *.min.js, /vendor/
 *   - rule ids:                  rule:semgrep.xxx   or   rule:patronus.jwt.*
 *   - categories:                category:secrets
 *
 * Lines starting with `#` are comments; blank lines are ignored. Path patterns
 * support gitignore semantics including `!` negation with last-match-wins.
 */

import fs from 'node:fs';
import path from 'node:path';
import { normalizePath } from '../core/finding.js';

const IGNORE_FILENAME = '.patronusignore';

/** Convert a single glob segment string into a regex body (path-aware). */
function globToRegexBody(pattern) {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        out += '.*';
        i++;
        if (pattern[i + 1] === '/') i++; // consume the slash after **
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return out;
}

/** Compile a path pattern into { negated, test(path) }. */
function compilePathPattern(raw) {
  let negated = false;
  let pattern = raw;

  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  }
  let anchored = false;
  if (pattern.startsWith('/')) {
    anchored = true;
    pattern = pattern.slice(1);
  }
  if (pattern.endsWith('/')) {
    pattern = pattern.slice(0, -1);
  }

  const hasSlash = pattern.includes('/');
  const body = globToRegexBody(pattern);
  const prefix = anchored || hasSlash ? '^' : '(^|/)';
  // Trailing group lets a matched directory also match everything beneath it.
  const regex = new RegExp(`${prefix}${body}(/.*)?$`);

  return { negated, test: (p) => regex.test(p) };
}

/** Simpler glob (only `*`) for rule id matching. */
function compileRulePattern(raw) {
  const body = raw
    .split('*')
    .map((s) => s.replace(/[\\^$.|+()[\]{}?]/g, (m) => `\\${m}`))
    .join('.*');
  return new RegExp(`^${body}$`, 'i');
}

/**
 * Parse ignore lines into a structured suppression matcher.
 * @param {string[]} lines
 * @returns {SuppressionSet}
 */
export function parseIgnoreLines(lines) {
  const pathPatterns = [];
  const ruleMatchers = [];
  const categories = new Set();

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '').trim();
    if (!line || line.startsWith('#')) continue;

    if (line.toLowerCase().startsWith('rule:')) {
      const val = line.slice('rule:'.length).trim();
      if (val) ruleMatchers.push(compileRulePattern(val));
      continue;
    }
    if (line.toLowerCase().startsWith('category:')) {
      const val = line.slice('category:'.length).trim().toLowerCase();
      if (val) categories.add(val);
      continue;
    }
    // Optional explicit path: prefix.
    const pathVal = line.toLowerCase().startsWith('path:')
      ? line.slice('path:'.length).trim()
      : line;
    if (pathVal) pathPatterns.push(compilePathPattern(pathVal));
  }

  return new SuppressionSet(pathPatterns, ruleMatchers, categories);
}

/** Encapsulates suppression logic across the three dimensions. */
export class SuppressionSet {
  constructor(pathPatterns = [], ruleMatchers = [], categories = new Set()) {
    this.pathPatterns = pathPatterns;
    this.ruleMatchers = ruleMatchers;
    this.categories = categories;
  }

  get isEmpty() {
    return (
      this.pathPatterns.length === 0 &&
      this.ruleMatchers.length === 0 &&
      this.categories.size === 0
    );
  }

  /** Path suppression using last-match-wins negation semantics. */
  matchesPath(file) {
    if (!file) return false;
    const p = normalizePath(file);
    let ignored = false;
    for (const pat of this.pathPatterns) {
      if (pat.test(p)) ignored = !pat.negated;
    }
    return ignored;
  }

  matchesRule(ruleId) {
    if (!ruleId) return false;
    return this.ruleMatchers.some((r) => r.test(ruleId));
  }

  matchesCategory(category) {
    if (!category) return false;
    return this.categories.has(String(category).toLowerCase());
  }

  /** True when a finding should be suppressed by any dimension. */
  shouldSuppress(finding) {
    return (
      this.matchesCategory(finding.category) ||
      this.matchesRule(finding.ruleId) ||
      this.matchesPath(finding.file)
    );
  }

  /** Partition findings into kept vs suppressed. */
  apply(findings) {
    if (this.isEmpty) return { kept: findings, suppressed: [] };
    const kept = [];
    const suppressed = [];
    for (const f of findings) {
      (this.shouldSuppress(f) ? suppressed : kept).push(f);
    }
    return { kept, suppressed };
  }
}

/**
 * Load .patronusignore from `cwd` (if present) and merge with any extra
 * patterns from config. Never throws.
 * @param {string} cwd
 * @param {string[]} extraPatterns
 * @returns {SuppressionSet}
 */
export function loadSuppressions(cwd = process.cwd(), extraPatterns = []) {
  let lines = [];
  const file = path.join(cwd, IGNORE_FILENAME);
  try {
    if (fs.existsSync(file)) {
      lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    }
  } catch {
    lines = [];
  }
  if (Array.isArray(extraPatterns) && extraPatterns.length) {
    lines = lines.concat(extraPatterns);
  }
  return parseIgnoreLines(lines);
}

export { IGNORE_FILENAME };
