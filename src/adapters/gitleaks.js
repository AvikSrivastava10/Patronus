/**
 * gitleaks adapter (MIT).
 *
 * Detects hardcoded secrets. Scans git history by default (working tree +
 * commits); set config.gitleaks.noGit to scan the working directory only.
 * Writes its JSON report to a temp file outside the user's project, which the
 * base runner reads and then cleans up. Secret values are always redacted.
 */

import path from 'node:path';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { redactSecret } from './base.js';

function severityForRule(ruleId) {
  const id = String(ruleId || '').toLowerCase();
  if (/private[-_]?key|rsa|pgp|-----begin/.test(id)) return SEVERITY.critical;
  if (/aws|gcp|azure|stripe|token|secret|password/.test(id)) return SEVERITY.high;
  return SEVERITY.high;
}

const adapter = {
  id: TOOL.gitleaks,
  displayName: 'gitleaks',
  command: 'gitleaks',
  versionArgs: ['version'],
  license: 'MIT',
  homepage: 'https://github.com/gitleaks/gitleaks',
  install: {
    brew: 'brew install gitleaks',
    go: 'go install github.com/gitleaks/gitleaks/v8@latest',
    recommended: 'brew install gitleaks  (or download a release binary)',
    url: 'https://github.com/gitleaks/gitleaks#installing',
  },

  buildInvocation(ctx) {
    const reportPath = path.join(ctx.tmpDir, 'gitleaks-report.json');
    const args = [
      'detect',
      '--source', ctx.root,
      '--report-format', 'json',
      '--report-path', reportPath,
      '--no-banner',
      '--redact', // ask gitleaks itself to redact secrets in its report
      '--exit-code', '0', // don't treat "found leaks" as a failure exit
    ];
    if (ctx.config?.gitleaks?.noGit) args.push('--no-git');

    return {
      command: 'gitleaks',
      args,
      cwd: ctx.root,
      output: { type: 'file', path: reportPath, cleanup: true },
    };
  },

  normalize(parsed) {
    if (!Array.isArray(parsed)) return [];
    return parsed.map((leak) => {
      const inHistory = Boolean(leak.Commit && leak.Commit !== '');
      const location = inHistory
        ? ` (in commit ${String(leak.Commit).slice(0, 8)})`
        : '';
      const desc = leak.Description || leak.RuleID || 'Hardcoded secret detected';
      const match = leak.Match ? ` Match: ${redactSecret(leak.Match)}` : '';

      return createFinding({
        tool: TOOL.gitleaks,
        ruleId: leak.RuleID || 'gitleaks.secret',
        severity: severityForRule(leak.RuleID),
        category: CATEGORY.secrets,
        file: leak.File || leak.file || '',
        line: leak.StartLine ?? leak.startLine,
        endLine: leak.EndLine ?? leak.endLine,
        column: leak.StartColumn ?? leak.startColumn,
        message: `${desc}${location}.${match}`,
        confidence: CONFIDENCE.high,
        aiCodegenRelevant: false,
        remediation:
          'Rotate the exposed credential immediately and remove it from source/history. Store secrets in environment variables or a secrets manager.',
      });
    });
  },
};

export default adapter;
