/**
 * Terminal reporter (default).
 *
 * Human-readable, color-coded, grouped by severity. Returns a string; the
 * command layer decides whether to print it to stdout or write it to a file.
 * chalk automatically disables color when output is not a TTY.
 */

import chalk from 'chalk';
import { SEVERITIES_DESC } from '../constants.js';
import { STATUS } from '../adapters/base.js';
import { VERSION, PRODUCT } from '../version.js';

const SEV_STYLE = {
  critical: (s) => chalk.bgRed.white.bold(` ${s} `),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
};

const SEV_DOT = {
  critical: chalk.red('●'),
  high: chalk.red('●'),
  medium: chalk.yellow('●'),
  low: chalk.cyan('●'),
};

function sevLabel(sev) {
  const label = sev.toUpperCase().padEnd(8);
  return (SEV_STYLE[sev] || ((s) => s))(label);
}

function statusLine(t) {
  const count = Array.isArray(t.findings) ? t.findings.length : 0;
  const secs = t.durationMs != null ? `${(t.durationMs / 1000).toFixed(1)}s` : '';
  switch (t.status) {
    case STATUS.ok:
      return `  ${chalk.green('✓')} ${chalk.bold(t.id)} ${chalk.gray(`— ${count} finding${count === 1 ? '' : 's'} ${secs && `(${secs})`}`)}`;
    case STATUS.skipped:
      return `  ${chalk.gray('•')} ${chalk.gray(`${t.id} skipped — ${t.reason || 'not applicable'}`)}${t.installHint ? chalk.gray(`\n      install: ${t.installHint}`) : ''}`;
    case STATUS.timeout:
      return `  ${chalk.yellow('⚠')} ${chalk.yellow(`${t.id} timed out — ${t.reason || ''}`)}`;
    case STATUS.error:
      return `  ${chalk.red('✗')} ${chalk.red(`${t.id} error — ${t.reason || 'unknown error'}`)}`;
    default:
      return `  ${t.id}: ${t.status}`;
  }
}

function renderFinding(f, verbose) {
  const lines = [];
  const loc = f.file ? `${f.file}${f.line != null ? `:${f.line}` : ''}` : '(project)';
  const ai = f.aiCodegenRelevant ? chalk.magenta(' [ai-codegen]') : '';
  const agreed =
    Array.isArray(f.agreedTools) && f.agreedTools.length > 1
      ? chalk.gray(` (agreed: ${f.agreedTools.join(', ')})`)
      : '';

  lines.push(`  ${SEV_DOT[f.severity] || '•'} ${sevLabel(f.severity)} ${chalk.dim(f.category)}  ${chalk.underline(loc)}${ai}`);
  lines.push(`     ${f.message}`);

  const meta = [];
  meta.push(chalk.gray(f.tool));
  meta.push(chalk.gray(`confidence: ${f.confidence}`));
  if (verbose) meta.push(chalk.gray(`rule: ${f.ruleId}`));
  if (verbose && f.toolVersion) meta.push(chalk.gray(`v${f.toolVersion}`));
  lines.push(`     ${chalk.gray('↳')} ${meta.join(chalk.gray(' · '))}${agreed}`);

  if (f.remediation) {
    lines.push(`     ${chalk.gray('↳ fix:')} ${chalk.gray(f.remediation)}`);
  }
  if (verbose && Array.isArray(f.references) && f.references.length) {
    lines.push(`     ${chalk.gray('↳ refs:')} ${chalk.gray(f.references.slice(0, 3).join(', '))}`);
  }
  return lines.join('\n');
}

/**
 * @param {object} scan  runScan() result.
 * @param {object} [opts] { verbose }
 * @returns {string}
 */
export function render(scan, opts = {}) {
  const verbose = Boolean(opts.verbose);
  const out = [];

  const stacks = Object.entries(scan.detection.stacks)
    .filter(([, v]) => v)
    .map(([k]) => k);

  out.push('');
  out.push(chalk.bold(`${PRODUCT} v${VERSION}`) + chalk.gray(`  ·  security scan`));
  out.push(chalk.gray(`  target: ${scan.root}`));
  out.push(chalk.gray(`  detected: ${stacks.length ? stacks.join(', ') : 'unknown stack'}`));
  const nodeConstraint = scan.detection?.meta?.nodeConstraint;
  if (nodeConstraint) {
    out.push(chalk.gray(`  project node: ${nodeConstraint.value} (${nodeConstraint.source})`));
  }
  out.push('');

  // Analyzer status
  out.push(chalk.bold('Analyzers'));
  for (const t of scan.toolResults) {
    out.push(statusLine(t));
  }
  if (scan.toolResults.length === 0) {
    out.push(chalk.gray('  (no analyzers selected)'));
  }
  out.push('');

  // Findings grouped by severity
  if (scan.findings.length === 0) {
    out.push(chalk.green.bold('✔ No findings.'));
  } else {
    const groups = groupBySeverity(scan.findings);
    for (const sev of SEVERITIES_DESC) {
      const list = groups[sev];
      if (!list || list.length === 0) continue;
      out.push(chalk.bold(`${sev.toUpperCase()} (${list.length})`));
      for (const f of list) {
        out.push(renderFinding(f, verbose));
        out.push('');
      }
    }
  }

  // Footer summary
  const s = scan.summary;
  out.push(chalk.bold('Summary'));
  out.push(
    `  ${chalk.bold(s.total)} finding${s.total === 1 ? '' : 's'}  ` +
      `${chalk.red(`${s.bySeverity.critical} critical`)}, ` +
      `${chalk.red(`${s.bySeverity.high} high`)}, ` +
      `${chalk.yellow(`${s.bySeverity.medium} medium`)}, ` +
      `${chalk.cyan(`${s.bySeverity.low} low`)}`,
  );
  if (s.aiCodegen > 0) {
    out.push(chalk.magenta(`  ${s.aiCodegen} finding${s.aiCodegen === 1 ? '' : 's'} match AI-codegen antipatterns`));
  }
  if (scan.suppressedCount > 0) {
    out.push(chalk.gray(`  ${scan.suppressedCount} suppressed (.clipeusignore + inline directives)`));
  }
  if (scan.minConfidenceFiltered > 0) {
    out.push(chalk.gray(`  ${scan.minConfidenceFiltered} below --min-confidence=${scan.minConfidence} hidden`));
  }
  if (scan.duplicatesRemoved > 0) {
    out.push(chalk.gray(`  ${scan.duplicatesRemoved} duplicate finding(s) merged`));
  }
  if (scan.baseline && !scan.baseline.updated) {
    out.push(chalk.gray(`  baseline: ${scan.baseline.known ?? 0} known finding(s) hidden; showing NEW only`));
  }
  out.push(chalk.gray(`  completed in ${(scan.durationMs / 1000).toFixed(1)}s`));
  out.push('');

  if (scan.baseline?.updated) {
    out.push(chalk.green.bold(`✔ Baseline recorded — ${scan.baseline.recorded} finding(s) written to ${scan.baseline.file}.`));
  } else if (scan.failed) {
    out.push(chalk.red.bold(`✖ Failed — findings at or above "${scan.threshold}" severity threshold.`));
  } else {
    out.push(chalk.green.bold(`✔ Passed — no findings at or above "${scan.threshold}" severity threshold.`));
  }
  out.push('');

  return out.join('\n');
}

function groupBySeverity(findings) {
  const groups = { critical: [], high: [], medium: [], low: [] };
  for (const f of findings) {
    (groups[f.severity] || (groups[f.severity] = [])).push(f);
  }
  return groups;
}
