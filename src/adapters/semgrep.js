/**
 * Semgrep adapter (Semgrep CE / OSS, LGPL-2.1).
 *
 * Invokes the free CLI in JSON mode only. Never touches Semgrep Cloud/Team
 * features, never logs in, never uses --autofix. Loads Semgrep's `auto` config
 * plus Patronus's bundled custom rules directory (Phase 2) when present.
 */

import fs from 'node:fs';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY, CATEGORY_VALUES } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity, inferCategory } from './base.js';

function mapSemgrepSeverity(sev) {
  switch (String(sev || '').toUpperCase()) {
    case 'ERROR': return SEVERITY.high;
    case 'WARNING': return SEVERITY.medium;
    case 'INFO': return SEVERITY.low;
    default: return normalizeSeverity(sev, SEVERITY.medium);
  }
}

function mapConfidence(value) {
  const v = String(value || '').toLowerCase();
  if (v === 'high') return CONFIDENCE.high;
  if (v === 'medium') return CONFIDENCE.medium;
  if (v === 'low') return CONFIDENCE.low;
  return CONFIDENCE.high; // Semgrep matches are deterministic by default.
}

const adapter = {
  id: TOOL.semgrep,
  displayName: 'Semgrep',
  command: 'semgrep',
  versionArgs: ['--version'],
  license: 'LGPL-2.1 (Semgrep CE)',
  homepage: 'https://semgrep.dev',
  install: {
    pip: 'pip install semgrep',
    brew: 'brew install semgrep',
    recommended: 'pip install semgrep  (or)  brew install semgrep',
    url: 'https://semgrep.dev/docs/getting-started/',
  },

  buildInvocation(ctx) {
    const configs = [];
    const userConfigs = ctx.config?.semgrep?.configs;
    if (Array.isArray(userConfigs) && userConfigs.length) {
      configs.push(...userConfigs);
    } else {
      configs.push('auto');
    }
    // Bundled custom rules (Phase 2).
    if (ctx.rulesDir && fs.existsSync(ctx.rulesDir)) {
      configs.push(ctx.rulesDir);
    }

    const args = [];
    for (const c of configs) args.push('--config', c);
    args.push('--json', '--quiet', '--disable-version-check', '--metrics=off', '--no-git-ignore');
    // Never interactive, never a fix mode.
    args.push(ctx.target || '.');

    return {
      command: 'semgrep',
      args,
      cwd: ctx.root,
      output: { type: 'stdout' },
      // Semgrep can be slow; give it a bit more room than the default.
      timeoutMs: Math.max(ctx.config?.toolTimeoutMs ?? 0, 180_000),
    };
  },

  /**
   * @param {any} parsed  Parsed Semgrep JSON.
   * @param {object} ctx
   * @returns {object[]}
   */
  normalize(parsed, ctx) {
    const results = parsed?.results;
    if (!Array.isArray(results)) return [];
    const version = parsed.version ? String(parsed.version) : undefined;

    return results.map((r) => {
      const extra = r.extra || {};
      const meta = extra.metadata || {};

      // Category: prefer explicit Patronus tag, then a taxonomy-valid metadata
      // category, else infer from rule id + message.
      let category = meta['patronus-category'] || meta.patronus_category;
      if (!category || !CATEGORY_VALUES.includes(category)) {
        category = CATEGORY_VALUES.includes(meta.category) ? meta.category : null;
      }
      if (!category) {
        category = inferCategory(`${r.check_id} ${extra.message || ''}`, CATEGORY.other);
      }

      const aiTag = meta['patronus-ai-codegen'] ?? meta.patronus_ai_codegen;
      const aiCodegenRelevant =
        aiTag === true ||
        aiTag === 'true' ||
        (Array.isArray(meta.tags) && meta.tags.includes('ai-codegen'));

      const references = []
        .concat(Array.isArray(meta.references) ? meta.references : [])
        .concat(Array.isArray(meta.owasp) ? meta.owasp : [])
        .concat(Array.isArray(meta.cwe) ? meta.cwe : [])
        .map(String);

      const explicitSeverity = meta['patronus-severity'];

      return createFinding({
        tool: TOOL.semgrep,
        ruleId: r.check_id || 'semgrep',
        severity: explicitSeverity
          ? normalizeSeverity(explicitSeverity)
          : mapSemgrepSeverity(extra.severity),
        category,
        file: r.path,
        line: r.start?.line,
        endLine: r.end?.line,
        column: r.start?.col,
        message: (extra.message || r.check_id || 'Semgrep finding').trim(),
        confidence: mapConfidence(meta.confidence),
        aiCodegenRelevant,
        references: references.length ? references : undefined,
        remediation: meta['patronus-remediation'] || (extra.fix ? `Suggested fix: ${extra.fix}` : undefined),
        toolVersion: version,
        raw: ctx?.verbose ? r : undefined,
      });
    });
  },
};

export default adapter;
