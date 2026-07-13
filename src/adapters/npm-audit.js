/**
 * npm audit adapter (bundled with npm; free).
 *
 * Runs `npm audit --json` inside the target project. Requires a lockfile for
 * accurate results, so we skip gracefully when neither package-lock.json nor
 * node_modules is present. Handles both the npm v7+ (`vulnerabilities`) and
 * legacy v6 (`advisories`) report shapes.
 */

import fs from 'node:fs';
import path from 'node:path';
import { TOOL, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity } from './base.js';

function ghsaFromUrl(url) {
  const m = String(url || '').match(/GHSA-[0-9a-z-]+/i);
  return m ? m[0] : null;
}

const adapter = {
  id: TOOL.npmAudit,
  displayName: 'npm audit',
  command: 'npm',
  versionArgs: ['--version'],
  license: 'Artistic-2.0 (npm)',
  homepage: 'https://docs.npmjs.com/cli/commands/npm-audit',
  install: {
    recommended: 'ships with Node.js/npm',
    url: 'https://nodejs.org',
  },

  precheck(ctx) {
    const hasLock = ['package-lock.json', 'npm-shrinkwrap.json'].some((f) =>
      fs.existsSync(path.join(ctx.root, f)),
    );
    const hasModules = fs.existsSync(path.join(ctx.root, 'node_modules'));
    if (!hasLock && !hasModules) {
      return { skip: true, reason: 'no package-lock.json/node_modules (run `npm install` first)' };
    }
    return { skip: false };
  },

  buildInvocation(ctx) {
    return {
      command: 'npm',
      // --json machine output; audit is inherently read-only (never `npm audit fix`).
      args: ['audit', '--json'],
      cwd: ctx.root,
      output: { type: 'stdout' },
    };
  },

  normalize(parsed) {
    if (!parsed || typeof parsed !== 'object') return [];
    if (parsed.vulnerabilities && typeof parsed.vulnerabilities === 'object') {
      return normalizeV7(parsed);
    }
    if (parsed.advisories && typeof parsed.advisories === 'object') {
      return normalizeV6(parsed);
    }
    return [];
  },
};

function normalizeV7(parsed) {
  const findings = [];
  const seen = new Set();

  for (const [pkgName, vuln] of Object.entries(parsed.vulnerabilities)) {
    const via = Array.isArray(vuln.via) ? vuln.via : [];
    const advisories = via.filter((v) => v && typeof v === 'object');

    if (advisories.length === 0) {
      // Transitive-only vulnerability with no direct advisory object.
      const key = `${pkgName}::${vuln.range || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(
        createFinding({
          tool: TOOL.npmAudit,
          ruleId: `npm-audit.${pkgName}`,
          severity: normalizeSeverity(vuln.severity),
          category: CATEGORY.dependencyCve,
          file: 'package.json',
          line: null,
          message: `Vulnerable dependency "${pkgName}"${vuln.range ? ` (affected: ${vuln.range})` : ''}.`,
          confidence: CONFIDENCE.high,
          aiCodegenRelevant: false,
          remediation: describeFix(vuln.fixAvailable, pkgName),
        }),
      );
      continue;
    }

    for (const adv of advisories) {
      const ghsa = ghsaFromUrl(adv.url);
      const key = `${pkgName}::${ghsa || adv.source || adv.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(
        createFinding({
          tool: TOOL.npmAudit,
          ruleId: ghsa || `npm-audit.${adv.source || pkgName}`,
          severity: normalizeSeverity(adv.severity || vuln.severity),
          category: CATEGORY.dependencyCve,
          file: 'package.json',
          line: null,
          message: `${adv.title || 'Known vulnerability'} in "${pkgName}"${adv.range ? ` (affected: ${adv.range})` : ''}.`,
          confidence: CONFIDENCE.high,
          aiCodegenRelevant: false,
          references: adv.url ? [adv.url] : undefined,
          remediation: describeFix(vuln.fixAvailable, pkgName),
        }),
      );
    }
  }
  return findings;
}

function normalizeV6(parsed) {
  const findings = [];
  for (const adv of Object.values(parsed.advisories)) {
    findings.push(
      createFinding({
        tool: TOOL.npmAudit,
        ruleId: adv.github_advisory_id || `npm-audit.${adv.id}`,
        severity: normalizeSeverity(adv.severity),
        category: CATEGORY.dependencyCve,
        file: 'package.json',
        line: null,
        message: `${adv.title || 'Known vulnerability'} in "${adv.module_name}"${adv.vulnerable_versions ? ` (affected: ${adv.vulnerable_versions})` : ''}.`,
        confidence: CONFIDENCE.high,
        aiCodegenRelevant: false,
        references: adv.url ? [adv.url] : undefined,
        remediation: adv.recommendation || undefined,
      }),
    );
  }
  return findings;
}

function describeFix(fixAvailable, pkgName) {
  if (fixAvailable === true) return `A fix is available. Run \`npm audit\` to review and update ${pkgName} manually.`;
  if (fixAvailable && typeof fixAvailable === 'object') {
    return `Fix available: upgrade to ${fixAvailable.name}@${fixAvailable.version}${fixAvailable.isSemVerMajor ? ' (major version change)' : ''}.`;
  }
  return 'No automatic fix available; review the advisory and consider an alternative or patched version.';
}

export default adapter;
