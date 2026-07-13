/**
 * Unified finding schema.
 *
 * Every finding from every source (external tool adapters, custom Semgrep
 * rules, standalone checkers, taint tracker) MUST pass through `createFinding`
 * before reaching dedup / reporting. This guarantees a single stable shape.
 *
 * @typedef {Object} Finding
 * @property {string}  tool              Producer id (see constants.TOOL).
 * @property {string}  ruleId            Tool/rule-specific identifier.
 * @property {('critical'|'high'|'medium'|'low')} severity
 * @property {string}  category          Internal taxonomy (see constants.CATEGORY).
 * @property {string}  file              Path relative to scan root (POSIX separators).
 * @property {number|null} line          1-based line, or null if not line-scoped.
 * @property {number|null} [endLine]     Optional end line.
 * @property {number|null} [column]      Optional column.
 * @property {string}  message           Human-readable explanation of the risk.
 * @property {('high'|'medium'|'low')} confidence
 * @property {boolean} aiCodegenRelevant Maps to an AI-codegen antipattern.
 * @property {string}  [remediation]     Optional guidance on how to fix.
 * @property {string[]} [references]     Optional links (CWE, docs).
 * @property {string}  [toolVersion]     Optional producing tool version.
 * @property {object}  [raw]             Optional raw tool payload (for --verbose).
 * @property {string[]} [agreedTools]    Populated by dedup: tools that concur.
 * @property {string}  [fingerprint]     Populated by dedup: stable dedup key.
 */

import {
  SEVERITY,
  SEVERITY_ORDER,
  CONFIDENCE,
  CATEGORY,
  CATEGORY_VALUES,
} from '../constants.js';

/** Normalize an arbitrary value to POSIX-style relative-ish path text. */
export function normalizePath(file) {
  if (!file || typeof file !== 'string') return '';
  return file.replace(/\\/g, '/').replace(/^\.\//, '');
}

function coerceSeverity(value) {
  if (typeof value === 'string' && SEVERITY[value.toLowerCase()]) {
    return value.toLowerCase();
  }
  return SEVERITY.medium;
}

function coerceConfidence(value) {
  if (typeof value === 'string' && CONFIDENCE[value.toLowerCase()]) {
    return value.toLowerCase();
  }
  return CONFIDENCE.high;
}

function coerceCategory(value) {
  if (typeof value === 'string' && CATEGORY_VALUES.includes(value)) {
    return value;
  }
  return CATEGORY.other;
}

function coerceLine(value) {
  const n = Number(value);
  if (Number.isFinite(n) && n > 0) return Math.floor(n);
  return null;
}

/**
 * Build a validated, fully-shaped Finding. Unknown/invalid enum values are
 * coerced to safe defaults rather than throwing, so a single malformed tool
 * record can never crash normalization.
 *
 * @param {Partial<Finding>} input
 * @returns {Finding}
 */
export function createFinding(input = {}) {
  const finding = {
    tool: String(input.tool ?? 'unknown'),
    ruleId: String(input.ruleId ?? 'unknown'),
    severity: coerceSeverity(input.severity),
    category: coerceCategory(input.category),
    file: normalizePath(input.file),
    line: coerceLine(input.line),
    message: String(input.message ?? '').trim() || 'Security finding (no message provided).',
    confidence: coerceConfidence(input.confidence),
    aiCodegenRelevant: Boolean(input.aiCodegenRelevant),
  };

  if (input.endLine != null) finding.endLine = coerceLine(input.endLine);
  if (input.column != null) {
    const c = Number(input.column);
    finding.column = Number.isFinite(c) && c >= 0 ? Math.floor(c) : null;
  }
  if (input.remediation) finding.remediation = String(input.remediation);
  if (Array.isArray(input.references) && input.references.length) {
    finding.references = input.references.map(String);
  }
  if (input.toolVersion) finding.toolVersion = String(input.toolVersion);
  if (input.raw !== undefined) finding.raw = input.raw;
  if (Array.isArray(input.agreedTools) && input.agreedTools.length) {
    finding.agreedTools = [...new Set(input.agreedTools.map(String))];
  }

  return finding;
}

/** Compare two severities. Returns >0 if a is more severe than b. */
export function compareSeverity(a, b) {
  return (SEVERITY_ORDER[a] ?? 0) - (SEVERITY_ORDER[b] ?? 0);
}

/** True when `severity` meets or exceeds the `threshold` severity. */
export function meetsSeverityThreshold(severity, threshold) {
  return (SEVERITY_ORDER[severity] ?? 0) >= (SEVERITY_ORDER[threshold] ?? Infinity);
}

/**
 * Stable fingerprint for dedup.
 *
 * For line-scoped findings, same file + line + category collapses across tools
 * (tool and rule id are excluded so overlapping findings from different tools
 * merge). For line-less findings (e.g. dependency CVEs, which share
 * file=package.json + category=dependency-cve), the rule id is included so
 * distinct advisories stay distinct instead of collapsing into one entry.
 */
export function fingerprintFinding(finding) {
  if (finding.line != null) {
    return [finding.file || '?', finding.line, finding.category].join('::');
  }
  return [finding.file || '?', '*', finding.category, finding.ruleId || '?'].join('::');
}
