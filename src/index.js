/**
 * Programmatic API for Clipeus.
 *
 * Lets other tools embed Clipeus (e.g. custom CI scripts) without shelling out
 * to the CLI. The CLI in bin/clipeus.js is a thin wrapper over these exports.
 */

export { runScan, selectAnalyzers, allSelectableIds } from './scan/engine.js';
export { renderReport, FORMATS } from './report/index.js';
export { detectProject } from './detectors/detect.js';
export { loadConfig, getDefaultConfig } from './config/config.js';
export { loadSuppressions } from './config/clipeusignore.js';
export { applyInlineSuppressions } from './config/inline-suppress.js';
export {
  baselineFingerprint,
  loadBaseline,
  writeBaseline,
  partitionByBaseline,
} from './config/baseline.js';
export {
  createFinding,
  fingerprintFinding,
  meetsSeverityThreshold,
  normalizePath,
  compareSeverity,
} from './core/finding.js';
export { deduplicate, sortFindings, summarize } from './core/dedup.js';
export { ALL_ADAPTERS, ADAPTERS, getAdapter } from './adapters/index.js';
export { enableHook, disableHook, hookStatus } from './hooks/git-hook.js';
export { VERSION, PRODUCT } from './version.js';
export * as constants from './constants.js';
