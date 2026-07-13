/**
 * OWASP Dependency-Check adapter (Apache-2.0).
 *
 * Runs only when a supported manifest (Maven/Gradle/.NET, etc.) is detected.
 * This tool is comparatively slow and requires a vulnerability data feed, so it
 * is easily skippable via `--skip owasp-dependency-check`. Writes its JSON
 * report into a temp directory that is read and then cleaned up.
 */

import fs from 'node:fs';
import path from 'node:path';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity } from './base.js';

function severityFromCvss(vuln) {
  if (vuln.severity) return normalizeSeverity(vuln.severity);
  const score = vuln.cvssv3?.baseScore ?? vuln.cvssv2?.score;
  if (typeof score === 'number') {
    if (score >= 9.0) return SEVERITY.critical;
    if (score >= 7.0) return SEVERITY.high;
    if (score >= 4.0) return SEVERITY.medium;
    return SEVERITY.low;
  }
  return SEVERITY.medium;
}

const adapter = {
  id: TOOL.owaspDependencyCheck,
  displayName: 'OWASP Dependency-Check',
  command: 'dependency-check',
  versionArgs: ['--version'],
  license: 'Apache-2.0',
  homepage: 'https://owasp.org/www-project-dependency-check/',
  install: {
    brew: 'brew install dependency-check',
    recommended: 'brew install dependency-check  (or download the CLI release)',
    url: 'https://owasp.org/www-project-dependency-check/',
  },

  buildInvocation(ctx) {
    const outDir = path.join(ctx.tmpDir, 'depcheck');
    try {
      fs.mkdirSync(outDir, { recursive: true });
    } catch {
      /* handled downstream if missing */
    }
    const reportFile = path.join(outDir, 'dependency-check-report.json');
    const projectName = path.basename(ctx.root) || 'patronus-scan';

    return {
      command: 'dependency-check',
      args: [
        '--project', projectName,
        '--scan', '.',
        '--format', 'JSON',
        '--out', outDir,
      ],
      cwd: ctx.root,
      output: { type: 'dir', dir: outDir, file: reportFile, cleanup: true },
      // This tool is slow; allow generous time.
      timeoutMs: Math.max(ctx.config?.toolTimeoutMs ?? 0, 600_000),
    };
  },

  normalize(parsed) {
    const deps = parsed?.dependencies;
    if (!Array.isArray(deps)) return [];
    const findings = [];
    const seen = new Set();

    for (const dep of deps) {
      const vulns = Array.isArray(dep.vulnerabilities) ? dep.vulnerabilities : [];
      for (const v of vulns) {
        const key = `${dep.fileName}::${v.name}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const refs = Array.isArray(v.references)
          ? v.references.map((r) => r.url).filter(Boolean)
          : [];

        findings.push(
          createFinding({
            tool: TOOL.owaspDependencyCheck,
            ruleId: v.name || 'owasp-dc',
            severity: severityFromCvss(v),
            category: CATEGORY.dependencyCve,
            file: dep.fileName || 'dependency',
            line: null,
            message: `${v.name || 'Known vulnerability'} affects ${dep.fileName || 'a dependency'}.`,
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            references: refs.length ? refs.slice(0, 5) : undefined,
            remediation: 'Update the affected dependency to a patched version.',
          }),
        );
      }
    }
    return findings;
  },
};

export default adapter;
