/**
 * ESLint adapter (MIT), configured with security plugins.
 *
 * Unlike the other adapters, ESLint (and the security plugins) are bundled as
 * Patronus dependencies and executed through ESLint's Node API using a
 * self-contained flat config. This guarantees the security rules actually run,
 * regardless of the target project's own ESLint setup. It is strictly
 * lint-only: no --fix, no file writes.
 *
 * `normalize()` operates on the standard ESLint results array (identical shape
 * to `eslint --format json`), so it is unit-testable with fixtures.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { STATUS } from './base.js';
import { log } from '../core/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = path.join(__dirname, 'eslint.config.js');

/** Per-rule mapping onto the unified schema. */
const RULE_META = {
  'security/detect-eval-with-expression': { category: CATEGORY.injection, severity: SEVERITY.high, confidence: CONFIDENCE.medium },
  'security/detect-child-process': { category: CATEGORY.injection, severity: SEVERITY.high, confidence: CONFIDENCE.medium },
  'security/detect-non-literal-require': { category: CATEGORY.injection, severity: SEVERITY.medium, confidence: CONFIDENCE.low },
  'security/detect-non-literal-fs-filename': { category: CATEGORY.pathTraversal, severity: SEVERITY.medium, confidence: CONFIDENCE.low },
  'security/detect-non-literal-regexp': { category: CATEGORY.other, severity: SEVERITY.low, confidence: CONFIDENCE.low },
  'security/detect-unsafe-regex': { category: CATEGORY.other, severity: SEVERITY.medium, confidence: CONFIDENCE.medium },
  'security/detect-buffer-noassert': { category: CATEGORY.other, severity: SEVERITY.medium, confidence: CONFIDENCE.medium },
  'security/detect-object-injection': { category: CATEGORY.injection, severity: SEVERITY.low, confidence: CONFIDENCE.low },
  'security/detect-possible-timing-attacks': { category: CATEGORY.insecureCrypto, severity: SEVERITY.low, confidence: CONFIDENCE.low },
  'security/detect-pseudoRandomBytes': { category: CATEGORY.insecureCrypto, severity: SEVERITY.medium, confidence: CONFIDENCE.medium },
  'security/detect-disable-mustache-escape': { category: CATEGORY.injection, severity: SEVERITY.medium, confidence: CONFIDENCE.medium },
  'security/detect-no-csrf-before-method-override': { category: CATEGORY.insecureConfig, severity: SEVERITY.medium, confidence: CONFIDENCE.medium },
  'security/detect-new-buffer': { category: CATEGORY.other, severity: SEVERITY.low, confidence: CONFIDENCE.medium },
  'security/detect-bidi-characters': { category: CATEGORY.other, severity: SEVERITY.medium, confidence: CONFIDENCE.high },
  'no-unsanitized/method': { category: CATEGORY.injection, severity: SEVERITY.high, confidence: CONFIDENCE.medium },
  'no-unsanitized/property': { category: CATEGORY.injection, severity: SEVERITY.high, confidence: CONFIDENCE.medium },
};

function metaFor(ruleId) {
  return (
    RULE_META[ruleId] || {
      category: CATEGORY.other,
      severity: SEVERITY.medium,
      confidence: CONFIDENCE.medium,
    }
  );
}

const adapter = {
  id: TOOL.eslint,
  displayName: 'ESLint (security)',
  command: 'eslint',
  license: 'MIT',
  homepage: 'https://eslint.org',
  install: {
    recommended: 'bundled with Patronus (no separate install required)',
  },

  /**
   * Fully custom runner using the ESLint Node API. Never throws.
   */
  async runCustom(ctx) {
    let ESLint;
    let version = null;
    try {
      const mod = await import('eslint');
      ESLint = mod.ESLint;
      version = ESLint?.version ?? null;
    } catch (err) {
      return { status: STATUS.skipped, findings: [], reason: `eslint not resolvable: ${err.message}` };
    }
    if (!ESLint) {
      return { status: STATUS.skipped, findings: [], reason: 'ESLint API unavailable' };
    }

    try {
      const eslint = new ESLint({
        cwd: ctx.root,
        overrideConfigFile: CONFIG_PATH,
        errorOnUnmatchedPattern: false,
      });

      const patterns = [
        '**/*.js', '**/*.jsx', '**/*.mjs', '**/*.cjs',
        '**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts',
      ];
      const results = await eslint.lintFiles(patterns);
      const findings = adapter.normalize(results, { ...ctx, root: ctx.root, version });
      return { status: STATUS.ok, findings, version };
    } catch (err) {
      log.debug(`eslint runCustom error: ${err.stack || err.message}`);
      return { status: STATUS.error, findings: [], reason: err.message, version };
    }
  },

  /**
   * @param {Array} results  ESLint results array (per-file objects).
   * @param {object} ctx
   * @returns {object[]}
   */
  normalize(results, ctx = {}) {
    if (!Array.isArray(results)) return [];
    const root = ctx.root || process.cwd();
    const findings = [];

    for (const fileResult of results) {
      const messages = Array.isArray(fileResult.messages) ? fileResult.messages : [];
      const relFile = path.isAbsolute(fileResult.filePath || '')
        ? path.relative(root, fileResult.filePath)
        : fileResult.filePath;

      for (const msg of messages) {
        // Skip parse/config errors: not security findings, avoid noise.
        if (!msg.ruleId || msg.fatal) continue;
        // Only surface rules from our bundled security plugins.
        if (!msg.ruleId.startsWith('security/') && !msg.ruleId.startsWith('no-unsanitized/')) {
          continue;
        }
        const meta = metaFor(msg.ruleId);
        findings.push(
          createFinding({
            tool: TOOL.eslint,
            ruleId: msg.ruleId,
            severity: meta.severity,
            category: meta.category,
            file: relFile,
            line: msg.line ?? null,
            column: msg.column ?? null,
            endLine: msg.endLine ?? undefined,
            message: msg.message,
            confidence: meta.confidence,
            aiCodegenRelevant: false,
            toolVersion: ctx.version || undefined,
          }),
        );
      }
    }
    return findings;
  },
};

export default adapter;
