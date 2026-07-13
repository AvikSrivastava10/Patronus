/**
 * Baseline support.
 *
 * A baseline records the fingerprints of findings that already exist in a
 * codebase so subsequent scans can report only *new* findings. This is what
 * makes Clipeus adoptable on a large legacy project: accept the current state
 * once, then gate CI on regressions only.
 *
 * Fingerprints intentionally exclude the line number so they survive unrelated
 * edits that shift lines around; they key on tool + rule + category + file +
 * message, which stays stable for "the same issue".
 */

import fs from 'node:fs';
import crypto from 'node:crypto';
import { VERSION, PRODUCT } from '../version.js';
import { log } from '../core/logger.js';

/**
 * Stable, line-independent fingerprint for a finding.
 * @param {object} finding
 * @returns {string} sha1 hex
 */
export function baselineFingerprint(finding) {
  const key = [
    finding.tool || '',
    finding.ruleId || '',
    finding.category || '',
    finding.file || '',
    (finding.message || '').trim(),
  ].join('\u0000');
  return crypto.createHash('sha1').update(key).digest('hex');
}

/**
 * Load a baseline file. Never throws.
 * @param {string} file
 * @returns {{ fingerprints: Set<string> }|null} null if missing/unreadable.
 */
export function loadBaseline(file) {
  try {
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const list = Array.isArray(parsed?.fingerprints) ? parsed.fingerprints : [];
    return { fingerprints: new Set(list.map(String)) };
  } catch (err) {
    log.warn(`Could not read baseline ${file} (${err.message}); treating all findings as new.`);
    return null;
  }
}

/**
 * Write a baseline file from the given findings. This is Clipeus's own output
 * (explicitly requested via --update-baseline), analogous to --output.
 * @param {string} file
 * @param {object[]} findings
 * @returns {number} count of fingerprints written
 */
export function writeBaseline(file, findings) {
  const fingerprints = [...new Set(findings.map(baselineFingerprint))].sort();
  const payload = {
    tool: PRODUCT.toLowerCase(),
    version: VERSION,
    createdAt: new Date().toISOString(),
    count: fingerprints.length,
    fingerprints,
  };
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return fingerprints.length;
}

/**
 * Partition findings into new (not in baseline) and known (in baseline).
 * @param {object[]} findings
 * @param {Set<string>} baselineSet
 * @returns {{ newFindings: object[], knownFindings: object[] }}
 */
export function partitionByBaseline(findings, baselineSet) {
  const newFindings = [];
  const knownFindings = [];
  for (const f of findings) {
    if (baselineSet.has(baselineFingerprint(f))) knownFindings.push(f);
    else newFindings.push(f);
  }
  return { newFindings, knownFindings };
}
