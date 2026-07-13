/**
 * Trivy adapter (Apache-2.0).
 *
 * Runs `trivy fs . --format json` with the vuln + misconfig + secret scanners.
 * Covers Dockerfiles, Kubernetes manifests, Terraform, and filesystem-level
 * dependency issues. Read-only; results are normalized across its three finding
 * classes (vulnerabilities, misconfigurations, secrets).
 */

import { TOOL, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity, redactSecret } from './base.js';

const adapter = {
  id: TOOL.trivy,
  displayName: 'Trivy',
  command: 'trivy',
  versionArgs: ['--version'],
  license: 'Apache-2.0',
  homepage: 'https://github.com/aquasecurity/trivy',
  install: {
    brew: 'brew install trivy',
    recommended: 'brew install trivy  (or download a release binary)',
    url: 'https://trivy.dev/latest/getting-started/installation/',
  },

  buildInvocation(ctx) {
    const mode = ctx.config?.trivy?.mode === 'config' ? 'config' : 'fs';
    const args = [mode, '--format', 'json', '--quiet'];
    if (mode === 'fs') {
      args.push('--scanners', 'vuln,misconfig,secret');
    }
    args.push('.');
    return {
      command: 'trivy',
      args,
      cwd: ctx.root,
      output: { type: 'stdout' },
      timeoutMs: Math.max(ctx.config?.toolTimeoutMs ?? 0, 240_000),
    };
  },

  normalize(parsed) {
    const results = parsed?.Results;
    if (!Array.isArray(results)) return [];
    const findings = [];

    for (const res of results) {
      const target = res.Target || res.Class || '';

      for (const v of res.Vulnerabilities || []) {
        findings.push(
          createFinding({
            tool: TOOL.trivy,
            ruleId: v.VulnerabilityID || 'trivy.vuln',
            severity: normalizeSeverity(v.Severity),
            category: CATEGORY.dependencyCve,
            file: target,
            line: null,
            message: `${v.Title || v.VulnerabilityID || 'Vulnerability'} in ${v.PkgName || 'package'} ${v.InstalledVersion || ''}.`,
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            references: v.PrimaryURL ? [v.PrimaryURL] : undefined,
            remediation: v.FixedVersion
              ? `Upgrade ${v.PkgName} to ${v.FixedVersion}.`
              : undefined,
          }),
        );
      }

      for (const m of res.Misconfigurations || []) {
        findings.push(
          createFinding({
            tool: TOOL.trivy,
            ruleId: m.AVDID || m.ID || 'trivy.misconfig',
            severity: normalizeSeverity(m.Severity),
            category: CATEGORY.iacMisconfig,
            file: target,
            line: m.CauseMetadata?.StartLine ?? null,
            endLine: m.CauseMetadata?.EndLine ?? undefined,
            message: `${m.Title || m.ID}: ${m.Message || m.Description || ''}`.trim(),
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            references: m.PrimaryURL ? [m.PrimaryURL] : undefined,
            remediation: m.Resolution || undefined,
          }),
        );
      }

      for (const s of res.Secrets || []) {
        findings.push(
          createFinding({
            tool: TOOL.trivy,
            ruleId: s.RuleID || 'trivy.secret',
            severity: normalizeSeverity(s.Severity, 'high'),
            category: CATEGORY.secrets,
            file: target,
            line: s.StartLine ?? null,
            endLine: s.EndLine ?? undefined,
            message: `${s.Title || s.Category || 'Secret'} detected (${redactSecret(s.Match)}).`,
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            remediation: 'Rotate the credential and remove it from source. Use a secrets manager.',
          }),
        );
      }
    }
    return findings;
  },
};

export default adapter;
