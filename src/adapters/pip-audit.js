/**
 * pip-audit adapter (Apache-2.0).
 *
 * Audits Python dependencies against the OSV / PyPI advisory databases. Scans
 * the requirements file(s) present at the project root. If none are found we
 * skip (rather than auditing an unrelated ambient environment).
 */

import fs from 'node:fs';
import path from 'node:path';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity } from './base.js';

/** Find requirements-style files at the project root. */
function findRequirements(root) {
  let entries = [];
  try {
    entries = fs.readdirSync(root);
  } catch {
    return [];
  }
  return entries.filter((f) => /^requirements.*\.txt$/i.test(f));
}

function referencesFor(vuln) {
  const ids = [vuln.id, ...(Array.isArray(vuln.aliases) ? vuln.aliases : [])].filter(Boolean);
  const refs = [];
  for (const id of ids) {
    if (/^CVE-/i.test(id)) refs.push(`https://nvd.nist.gov/vuln/detail/${id}`);
    else if (/^(PYSEC|GHSA|OSV)-/i.test(id)) refs.push(`https://osv.dev/vulnerability/${id}`);
  }
  return refs;
}

const adapter = {
  id: TOOL.pipAudit,
  displayName: 'pip-audit',
  command: 'pip-audit',
  versionArgs: ['--version'],
  license: 'Apache-2.0',
  homepage: 'https://github.com/pypa/pip-audit',
  install: {
    pip: 'pip install pip-audit',
    recommended: 'pip install pip-audit',
    url: 'https://github.com/pypa/pip-audit#installation',
  },

  precheck(ctx) {
    const reqs = findRequirements(ctx.root);
    if (reqs.length === 0) {
      return {
        skip: true,
        reason: 'no requirements*.txt found at project root',
      };
    }
    return { skip: false };
  },

  buildInvocation(ctx) {
    const reqs = findRequirements(ctx.root);
    const args = ['-f', 'json', '--progress-spinner', 'off'];
    for (const r of reqs) {
      args.push('-r', r);
    }
    return {
      command: 'pip-audit',
      args,
      cwd: ctx.root,
      output: { type: 'stdout' },
      // Store which file(s) we scanned for message context.
      _requirements: reqs,
    };
  },

  normalize(parsed, ctx) {
    const deps = Array.isArray(parsed) ? parsed : parsed?.dependencies;
    if (!Array.isArray(deps)) return [];
    const source = findRequirements(ctx?.root || '.')[0] || 'requirements.txt';

    const findings = [];
    for (const dep of deps) {
      const vulns = Array.isArray(dep.vulns) ? dep.vulns : [];
      for (const vuln of vulns) {
        const fixes = Array.isArray(vuln.fix_versions) ? vuln.fix_versions : [];
        const aliases = Array.isArray(vuln.aliases) && vuln.aliases.length
          ? ` (${vuln.aliases.join(', ')})`
          : '';
        findings.push(
          createFinding({
            tool: TOOL.pipAudit,
            ruleId: vuln.id || `pip-audit.${dep.name}`,
            // pip-audit does not emit CVSS severity by default; a confirmed
            // advisory match is treated as high with high confidence.
            severity: normalizeSeverity(vuln.severity, SEVERITY.high),
            category: CATEGORY.dependencyCve,
            file: source,
            line: null,
            message: `${vuln.id || 'Known vulnerability'}${aliases}: "${dep.name}" ${dep.version || ''} is affected.`,
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            references: referencesFor(vuln),
            remediation: fixes.length
              ? `Upgrade "${dep.name}" to ${fixes.join(' or ')}.`
              : 'No fixed version listed; review the advisory for mitigation.',
          }),
        );
      }
    }
    return findings;
  },
};

export default adapter;
