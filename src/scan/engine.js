/**
 * Scan engine.
 *
 * The orchestrator that ties detection, tool adapters, internal checkers, the
 * taint engine, suppression, dedup, and summarization together.
 *
 * Guarantees:
 *   - runs every applicable analyzer in parallel (Promise.allSettled) so one
 *     tool's failure never blocks the others;
 *   - is strictly read-only against the user's project: all intermediate tool
 *     output goes to an OS temp directory that is removed afterwards;
 *   - always produces a normalized, deduplicated, sorted finding set plus a
 *     per-analyzer status list.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_ADAPTERS } from '../adapters/index.js';
import { runAdapter, STATUS } from '../adapters/base.js';
import { ALL_CHECKERS } from '../checkers/index.js';
import { TAINT_ANALYZERS } from '../taint/index.js';
import { detectProject } from '../detectors/detect.js';
import { loadConfig } from '../config/config.js';
import { loadSuppressions } from '../config/clipeusignore.js';
import { applyInlineSuppressions } from '../config/inline-suppress.js';
import { loadBaseline, writeBaseline, partitionByBaseline } from '../config/baseline.js';
import { deduplicate, sortFindings, summarize } from '../core/dedup.js';
import { filterVendoredFindings } from '../core/vendored.js';
import { meetsSeverityThreshold } from '../core/finding.js';
import { CONFIDENCE_ORDER } from '../constants.js';
import { log } from '../core/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_DIR = path.resolve(__dirname, '..', 'rules');

/** All internal analyzers (Phase 3 checkers + Phase 4 taint). */
const INTERNAL_ANALYZERS = [...ALL_CHECKERS, ...TAINT_ANALYZERS];

/** Every selectable unit id (for --only/--skip validation + help). */
export function allSelectableIds() {
  return [
    ...ALL_ADAPTERS.map((a) => a.id),
    ...INTERNAL_ANALYZERS.map((c) => c.id),
  ];
}

function toSet(value) {
  if (!value) return new Set();
  if (value instanceof Set) return value;
  if (Array.isArray(value)) return new Set(value);
  return new Set(String(value).split(',').map((s) => s.trim()).filter(Boolean));
}

/**
 * Determine which tool adapters and internal checkers to run.
 */
export function selectAnalyzers({ detection, config, only, skip }) {
  const knownAdapterIds = new Set(ALL_ADAPTERS.map((a) => a.id));
  const knownCheckerIds = new Set(INTERNAL_ANALYZERS.map((c) => c.id));
  const allKnown = new Set([...knownAdapterIds, ...knownCheckerIds]);

  const onlySet = toSet(only);
  const skipSet = toSet(skip);

  let toolSet;
  let checkerSet;

  if (onlySet.size) {
    // --only overrides detection: run exactly the named, known units.
    toolSet = new Set([...knownAdapterIds].filter((id) => onlySet.has(id)));
    checkerSet = new Set([...knownCheckerIds].filter((id) => onlySet.has(id)));
    for (const id of onlySet) {
      if (!allKnown.has(id)) log.warn(`--only: unknown tool/check "${id}" (ignored)`);
    }
  } else {
    const configEnabled = toSet(config?.tools?.enabled);
    toolSet = configEnabled.size
      ? new Set([...configEnabled].filter((id) => knownAdapterIds.has(id)))
      : new Set(detection.enabledTools);
    // Each internal analyzer decides whether it applies to the detected stack.
    checkerSet = new Set(
      INTERNAL_ANALYZERS.filter(
        (a) => typeof a.appliesTo !== 'function' || a.appliesTo(detection),
      ).map((a) => a.id),
    );
  }

  // Remove disabled (config) + skipped (CLI).
  const removals = new Set([...toSet(config?.tools?.disabled), ...skipSet]);
  for (const id of removals) {
    toolSet.delete(id);
    checkerSet.delete(id);
  }
  for (const id of skipSet) {
    if (!allKnown.has(id)) log.warn(`--skip: unknown tool/check "${id}" (ignored)`);
  }

  return { toolSet, checkerSet };
}

/** Wrap an internal analyzer run so it conforms to the adapter result shape and never throws. */
async function runInternal(analyzer, ctx) {
  const started = Date.now();
  const base = {
    id: analyzer.id,
    displayName: analyzer.displayName,
    status: STATUS.ok,
    findings: [],
    reason: null,
    version: null,
    durationMs: 0,
    installHint: null,
    rawExitCode: null,
  };
  try {
    const r = (await analyzer.run(ctx)) || {};
    return {
      ...base,
      status: r.status ?? STATUS.ok,
      findings: Array.isArray(r.findings) ? r.findings : [],
      reason: r.reason ?? null,
      version: r.version ?? null,
      durationMs: r.durationMs ?? Date.now() - started,
    };
  } catch (err) {
    log.debug(`internal analyzer ${analyzer.id} crashed: ${err.stack || err.message}`);
    return { ...base, status: STATUS.error, reason: err.message, durationMs: Date.now() - started };
  }
}

/**
 * Run a full scan.
 *
 * @param {Object} options
 * @param {string} [options.path='.']   Target path relative to cwd (or absolute).
 * @param {string} [options.failOn]     Threshold override.
 * @param {string|string[]} [options.only]
 * @param {string|string[]} [options.skip]
 * @param {boolean} [options.verbose]
 * @param {Object}  [options.hooks]     { onStart(task), onResult(result) }
 * @returns {Promise<object>} scan result
 */
export async function runScan(options = {}) {
  const startedAt = Date.now();
  const cwd = process.cwd();
  const targetArg = options.path || '.';
  const root = path.resolve(cwd, targetArg);

  const { config } = loadConfig(root);
  const detection = detectProject(root);
  const suppressions = loadSuppressions(root, config.ignore);

  const { toolSet, checkerSet } = selectAnalyzers({
    detection,
    config,
    only: options.only,
    skip: options.skip,
  });

  // Read-only guarantee: intermediate tool output lives in an OS temp dir.
  let tmpDir;
  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-'));
  } catch {
    tmpDir = path.join(os.tmpdir(), `clipeus-${Date.now()}`);
    try { fs.mkdirSync(tmpDir, { recursive: true }); } catch { /* best effort */ }
  }

  const ctx = {
    root,
    target: '.',
    config,
    detection,
    tmpDir,
    rulesDir: RULES_DIR,
    verbose: Boolean(options.verbose),
    offline: Boolean(options.offline),
  };

  // Build the task list.
  const tasks = [];
  for (const adapter of ALL_ADAPTERS) {
    if (toolSet.has(adapter.id)) {
      tasks.push({
        id: adapter.id,
        displayName: adapter.displayName,
        kind: 'tool',
        run: () => runAdapter(adapter, ctx),
      });
    }
  }
  for (const analyzer of INTERNAL_ANALYZERS) {
    if (checkerSet.has(analyzer.id)) {
      tasks.push({
        id: analyzer.id,
        displayName: analyzer.displayName,
        kind: 'checker',
        run: () => runInternal(analyzer, ctx),
      });
    }
  }

  const hooks = options.hooks || {};
  if (typeof hooks.onPlan === 'function') {
    try {
      hooks.onPlan(tasks.map((t) => ({ id: t.id, displayName: t.displayName, kind: t.kind })));
    } catch { /* ignore hook errors */ }
  }
  const runOne = async (task) => {
    if (typeof hooks.onStart === 'function') {
      try { hooks.onStart(task); } catch { /* ignore hook errors */ }
    }
    const result = await task.run();
    result.kind = task.kind;
    if (typeof hooks.onResult === 'function') {
      try { hooks.onResult(result); } catch { /* ignore hook errors */ }
    }
    return result;
  };

  const settled = await Promise.allSettled(tasks.map((t) => runOne(t)));
  const toolResults = settled.map((s, i) => {
    if (s.status === 'fulfilled') return s.value;
    // Should not happen (runOne never throws), but degrade gracefully.
    return {
      id: tasks[i].id,
      displayName: tasks[i].displayName,
      status: STATUS.error,
      findings: [],
      reason: s.reason?.message || String(s.reason),
      kind: tasks[i].kind,
      durationMs: 0,
    };
  });

  // Cleanup temp dir (read-only guarantee: leave the user's project untouched).
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch { /* best effort */ }

  // ---- Post-processing pipeline ----
  // 1) collect raw findings from every analyzer
  const rawFindings = [];
  for (const r of toolResults) {
    if (Array.isArray(r.findings)) rawFindings.push(...r.findings);
  }
  // 1b) drop findings inside third-party/vendored dirs (node_modules, .venv, …).
  //     A secret or lint hit in a dependency isn't the user's code to fix.
  const { kept: afterVendor, filtered: vendoredFindings } = filterVendoredFindings(rawFindings);
  // 2) project-wide suppressions (.clipeusignore + config.ignore)
  const { kept: afterIgnore, suppressed: ignoreSuppressed } = suppressions.apply(afterVendor);
  // 3) inline comment suppressions (clipeus-disable directives in source)
  const { kept: afterInline, suppressed: inlineSuppressed } = applyInlineSuppressions(afterIgnore, root);
  // 4) deduplicate across tools
  const { findings: deduped, duplicatesRemoved } = deduplicate(afterInline);

  // 5) optional minimum-confidence filter (reduce heuristic noise)
  let current = deduped;
  let minConfidenceFiltered = 0;
  const minConfidence = options.minConfidence ? String(options.minConfidence).toLowerCase() : null;
  if (minConfidence && CONFIDENCE_ORDER[minConfidence]) {
    const before = current.length;
    current = current.filter((f) => (CONFIDENCE_ORDER[f.confidence] ?? 0) >= CONFIDENCE_ORDER[minConfidence]);
    minConfidenceFiltered = before - current.length;
  }
  current = sortFindings(current);

  // 6) optional baseline: report only findings not already recorded
  let baseline = null;
  let reported = current;
  if (options.baselineFile) {
    if (options.updateBaseline) {
      let recorded = 0;
      let error = null;
      try {
        recorded = writeBaseline(options.baselineFile, current);
      } catch (err) {
        error = err.message;
        log.error(`Could not write baseline ${options.baselineFile}: ${err.message}`);
      }
      baseline = { file: options.baselineFile, updated: true, recorded, error };
      reported = current;
    } else {
      const loaded = loadBaseline(options.baselineFile);
      if (loaded) {
        const { newFindings, knownFindings } = partitionByBaseline(current, loaded.fingerprints);
        reported = sortFindings(newFindings);
        baseline = { file: options.baselineFile, new: newFindings.length, known: knownFindings.length };
      } else {
        baseline = { file: options.baselineFile, new: current.length, known: 0, missing: true };
      }
    }
  }

  const findings = reported;
  const summary = summarize(findings);
  const threshold = (options.failOn || config.failOn || 'critical').toLowerCase();
  // A baseline-update run records state and never fails the build.
  const failed = baseline?.updated
    ? false
    : findings.some((f) => meetsSeverityThreshold(f.severity, threshold));

  return {
    root,
    target: targetArg,
    detection,
    config,
    toolResults,
    findings,
    suppressedCount: ignoreSuppressed.length + inlineSuppressed.length,
    inlineSuppressedCount: inlineSuppressed.length,
    vendoredFilteredCount: vendoredFindings.length,
    duplicatesRemoved,
    minConfidence,
    minConfidenceFiltered,
    baseline,
    summary,
    threshold,
    failed,
    startedAt,
    finishedAt: Date.now(),
    durationMs: Date.now() - startedAt,
  };
}
