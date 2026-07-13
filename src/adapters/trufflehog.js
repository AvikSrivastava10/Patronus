/**
 * truffleHog adapter (AGPL-3.0 CLI; used only as an external tool, not linked).
 *
 * Scans the filesystem for secrets. Verification (which makes live network
 * calls to test whether discovered credentials are active) is DISABLED by
 * default because it has side effects beyond pure detection. Users can opt in
 * via config.trufflehog.verify = true.
 *
 * Output is JSONL (one JSON object per line). Secret values are redacted.
 */

import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { parseJsonlSafe, redactSecret } from './base.js';

function extractLocation(record) {
  const data = record?.SourceMetadata?.Data || {};
  const source = data.Filesystem || data.Git || data.Directory || {};
  return {
    file: source.file || source.File || '',
    line: source.line ?? source.Line ?? null,
  };
}

const adapter = {
  id: TOOL.trufflehog,
  displayName: 'truffleHog',
  command: 'trufflehog',
  versionArgs: ['--version'],
  license: 'AGPL-3.0',
  homepage: 'https://github.com/trufflesecurity/trufflehog',
  install: {
    brew: 'brew install trufflehog',
    go: 'go install github.com/trufflesecurity/trufflehog/v3@latest',
    recommended: 'brew install trufflehog  (or download a release binary)',
    url: 'https://github.com/trufflesecurity/trufflehog#installation',
  },

  buildInvocation(ctx) {
    const args = ['filesystem', ctx.root, '--json'];
    // Opt-in verification only; default is detection-only (no network calls).
    if (!ctx.config?.trufflehog?.verify) {
      args.push('--no-verification');
    }
    return {
      command: 'trufflehog',
      args,
      cwd: ctx.root,
      output: { type: 'stdout' },
    };
  },

  parse(text) {
    return parseJsonlSafe(text);
  },

  normalize(records) {
    if (!Array.isArray(records)) return [];
    return records
      // Keep only actual detector findings, not progress/log lines.
      .filter((r) => r && (r.DetectorName || r.SourceMetadata))
      .map((r) => {
        const { file, line } = extractLocation(r);
        const verified = r.Verified === true;
        const detector = r.DetectorName || r.DetectorType || 'secret';
        const redacted = r.Redacted || redactSecret(r.Raw || r.RawV2 || '');

        return createFinding({
          tool: TOOL.trufflehog,
          ruleId: `trufflehog.${detector}`,
          severity: verified ? SEVERITY.critical : SEVERITY.high,
          category: CATEGORY.secrets,
          file,
          line,
          message: `${verified ? 'Verified' : 'Potential'} ${detector} secret detected (${redacted}).`,
          // Unverified detections are strong but not certain; verified are certain.
          confidence: verified ? CONFIDENCE.high : CONFIDENCE.medium,
          aiCodegenRelevant: false,
          remediation:
            'Rotate the credential and remove it from the codebase. Use environment variables or a secrets manager.',
        });
      });
  },
};

export default adapter;
