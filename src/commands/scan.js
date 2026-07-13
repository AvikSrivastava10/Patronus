/**
 * `patronus scan [path]` command.
 *
 * Runs all applicable analyzers, prints a report in the requested format, and
 * sets the process exit code per the --fail-on threshold.
 *
 * Output routing:
 *   - progress/spinner -> stderr (never pollutes machine output)
 *   - report -> stdout, or to --output <file> when provided
 */

import fs from 'node:fs';
import path from 'node:path';
import { runScan } from '../scan/engine.js';
import { renderReport } from '../report/index.js';
import { log, spinner, setVerbose, chalk } from '../core/logger.js';
import { SEVERITY } from '../constants.js';

function resolveFormat(opts) {
  if (opts.json && opts.markdown) {
    log.warn('Both --json and --markdown given; using --json.');
    return 'json';
  }
  if (opts.json) return 'json';
  if (opts.markdown) return 'markdown';
  return 'terminal';
}

function parseList(value) {
  if (!value) return undefined;
  return String(value)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * @param {string} pathArg
 * @param {object} opts commander options
 */
export async function scanCommand(pathArg, opts = {}) {
  setVerbose(opts.verbose);

  // Validate --fail-on early.
  let failOn = opts.failOn ? String(opts.failOn).toLowerCase() : undefined;
  if (failOn && !SEVERITY[failOn]) {
    log.error(`Invalid --fail-on value "${opts.failOn}". Expected: critical | high | medium | low.`);
    process.exitCode = 2;
    return;
  }

  const format = resolveFormat(opts);
  const target = pathArg || '.';

  // Guard against a nonexistent target path.
  const absTarget = path.resolve(process.cwd(), target);
  if (!fs.existsSync(absTarget)) {
    log.error(`Target path does not exist: ${absTarget}`);
    process.exitCode = 2;
    return;
  }

  let total = 0;
  let completed = 0;
  const sp = spinner('Preparing scan...');

  let scan;
  try {
    scan = await runScan({
      path: target,
      failOn,
      only: parseList(opts.only),
      skip: parseList(opts.skip),
      verbose: opts.verbose,
      hooks: {
        onPlan: (tasks) => {
          total = tasks.length;
          sp.update(`Running ${total} analyzer${total === 1 ? '' : 's'}...`);
        },
        onResult: (r) => {
          completed += 1;
          const label = r.status === 'ok' ? '' : ` (${r.id}: ${r.status})`;
          sp.update(`Analyzed ${completed}/${total}${label}`);
        },
      },
    });
  } catch (err) {
    sp.fail('Scan failed to run.');
    log.error(err.stack || err.message);
    process.exitCode = 2;
    return;
  }

  sp.stop();

  const report = renderReport(scan, { format, verbose: opts.verbose });

  if (opts.output) {
    try {
      fs.writeFileSync(opts.output, `${report}\n`, 'utf8');
      log.success(`Report (${format}) written to ${opts.output}`);
    } catch (err) {
      log.error(`Could not write report to ${opts.output}: ${err.message}`);
      process.exitCode = 2;
      return;
    }
  } else {
    process.stdout.write(`${report}\n`);
  }

  // Brief stderr summary for machine-format runs so humans still get feedback.
  if (format !== 'terminal') {
    const s = scan.summary;
    log.info(
      chalk.gray(
        `patronus: ${s.total} finding(s) — ${s.bySeverity.critical} critical, ${s.bySeverity.high} high, ${s.bySeverity.medium} medium, ${s.bySeverity.low} low.`,
      ),
    );
  }

  process.exitCode = scan.failed ? 1 : 0;
}
