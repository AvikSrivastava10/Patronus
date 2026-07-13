/**
 * Deduplication + sorting of findings.
 *
 * Multiple tools frequently flag the same issue (e.g. Semgrep and ESLint both
 * catching an `eval` on the same line). We merge entries that share a
 * fingerprint, keep the highest-confidence/severity representative, and record
 * which tools agreed so the report can show corroboration.
 */

import {
  fingerprintFinding,
  compareSeverity,
} from './finding.js';
import { SEVERITY_ORDER, CONFIDENCE_ORDER } from '../constants.js';

/** Rank a finding for "which is the best representative of a group". */
function rank(f) {
  return (CONFIDENCE_ORDER[f.confidence] ?? 0) * 10 + (SEVERITY_ORDER[f.severity] ?? 0);
}

/**
 * Merge duplicate findings.
 * @param {object[]} findings
 * @returns {{ findings: object[], duplicatesRemoved: number }}
 */
export function deduplicate(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = fingerprintFinding(f);
    const bucket = groups.get(key);
    if (bucket) bucket.push(f);
    else groups.set(key, [f]);
  }

  const merged = [];
  let duplicatesRemoved = 0;

  for (const group of groups.values()) {
    if (group.length === 1) {
      merged.push(group[0]);
      continue;
    }
    duplicatesRemoved += group.length - 1;

    // Best representative: highest confidence, then severity.
    let best = group[0];
    let highestSeverity = group[0].severity;
    const tools = new Set();
    const references = new Set();

    for (const f of group) {
      tools.add(f.tool);
      if (Array.isArray(f.agreedTools)) f.agreedTools.forEach((t) => tools.add(t));
      if (Array.isArray(f.references)) f.references.forEach((r) => references.add(r));
      if (rank(f) > rank(best)) best = f;
      if (compareSeverity(f.severity, highestSeverity) > 0) highestSeverity = f.severity;
    }

    const representative = {
      ...best,
      // Escalate to the most severe opinion in the group.
      severity: highestSeverity,
      agreedTools: [...tools].sort(),
    };
    if (references.size) representative.references = [...references];
    merged.push(representative);
  }

  return { findings: merged, duplicatesRemoved };
}

/**
 * Deterministic sort for reporting: severity desc, confidence desc, then file,
 * then line, then tool.
 * @param {object[]} findings
 * @returns {object[]} a new sorted array
 */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const sev = (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
    if (sev !== 0) return sev;
    const conf = (CONFIDENCE_ORDER[b.confidence] ?? 0) - (CONFIDENCE_ORDER[a.confidence] ?? 0);
    if (conf !== 0) return conf;
    const file = (a.file || '').localeCompare(b.file || '');
    if (file !== 0) return file;
    const line = (a.line ?? 0) - (b.line ?? 0);
    if (line !== 0) return line;
    return (a.tool || '').localeCompare(b.tool || '');
  });
}

/**
 * Summary counts for the reporting layer + exit code logic.
 * @param {object[]} findings
 */
export function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  let aiCodegen = 0;

  for (const f of findings) {
    if (bySeverity[f.severity] != null) bySeverity[f.severity] += 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    if (f.aiCodegenRelevant) aiCodegen += 1;
  }

  return { total: findings.length, bySeverity, byCategory, aiCodegen };
}
