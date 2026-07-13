/**
 * JSON reporter.
 *
 * Emits a structured report object whose `findings` field is the full unified
 * schema array. The wrapper adds scan metadata (detection summary, per-tool
 * status, counts) that CI systems and dashboards typically need. When
 * `verbose` is false, per-finding `raw` payloads are stripped to keep output
 * lean.
 */

import { VERSION, PRODUCT } from '../version.js';

/**
 * @param {object} scan  Result from runScan().
 * @param {object} [opts]
 * @param {boolean} [opts.verbose]
 * @returns {string} pretty-printed JSON
 */
export function render(scan, opts = {}) {
  const verbose = Boolean(opts.verbose);

  const findings = scan.findings.map((f) => {
    if (verbose) return f;
    const { raw, ...rest } = f;
    return rest;
  });

  const report = {
    tool: PRODUCT.toLowerCase(),
    version: VERSION,
    schemaVersion: 1,
    scannedAt: new Date(scan.finishedAt ?? Date.now()).toISOString(),
    durationMs: scan.durationMs,
    target: scan.target,
    root: scan.root,
    failOn: scan.threshold,
    failed: scan.failed,
    detection: {
      stacks: Object.entries(scan.detection.stacks)
        .filter(([, v]) => v)
        .map(([k]) => k),
      languages: scan.detection.languages,
      nodeConstraint: scan.detection.meta?.nodeConstraint || undefined,
    },
    summary: scan.summary,
    suppressedCount: scan.suppressedCount,
    duplicatesRemoved: scan.duplicatesRemoved,
    minConfidence: scan.minConfidence || undefined,
    minConfidenceFiltered: scan.minConfidenceFiltered || undefined,
    baseline: scan.baseline || undefined,
    tools: scan.toolResults.map((t) => ({
      id: t.id,
      status: t.status,
      findings: Array.isArray(t.findings) ? t.findings.length : 0,
      reason: t.reason || undefined,
      version: t.version || undefined,
      durationMs: t.durationMs,
    })),
    findings,
  };

  return JSON.stringify(report, null, 2);
}
