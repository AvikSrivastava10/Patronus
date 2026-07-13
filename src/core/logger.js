/**
 * Logger + spinner helpers.
 *
 * Design rule: ALL human-facing status/progress/diagnostic text goes to
 * stderr. stdout is reserved for machine-consumable report output (--json /
 * --markdown / default terminal report) so Patronus can be safely piped, e.g.
 *   patronus scan --json > report.json
 * without progress noise corrupting the payload.
 */

import chalk from 'chalk';
import ora from 'ora';

let verbose = false;
let quiet = false;

export function setVerbose(value) {
  verbose = Boolean(value);
}

export function setQuiet(value) {
  quiet = Boolean(value);
}

export function isVerbose() {
  return verbose;
}

function write(line) {
  process.stderr.write(`${line}\n`);
}

export const log = {
  info(msg) {
    if (!quiet) write(msg);
  },
  step(msg) {
    if (!quiet) write(`${chalk.cyan('›')} ${msg}`);
  },
  success(msg) {
    if (!quiet) write(`${chalk.green('✓')} ${msg}`);
  },
  warn(msg) {
    if (!quiet) write(`${chalk.yellow('⚠')} ${chalk.yellow(msg)}`);
  },
  error(msg) {
    write(`${chalk.red('✗')} ${chalk.red(msg)}`);
  },
  debug(msg) {
    if (verbose && !quiet) write(chalk.gray(`  debug: ${msg}`));
  },
  /** Print an already-formatted block verbatim to stderr. */
  raw(msg) {
    if (!quiet) write(msg);
  },
  /** Blank line separator. */
  blank() {
    if (!quiet) write('');
  },
};

/**
 * Create an ora spinner bound to stderr. In non-TTY environments (CI) ora
 * degrades to plain logging automatically. Returns a lightweight wrapper that
 * is safe to call even when quiet mode is on.
 */
export function spinner(text) {
  if (quiet || !process.stderr.isTTY) {
    // Non-interactive: emit a single start line, no animation.
    if (!quiet) write(`${chalk.cyan('›')} ${text}`);
    return {
      succeed: (t) => t && log.success(t),
      fail: (t) => t && log.error(t),
      warn: (t) => t && log.warn(t),
      info: (t) => t && log.info(t),
      update: () => {},
      stop: () => {},
    };
  }
  const sp = ora({ text, stream: process.stderr, color: 'cyan' }).start();
  return {
    succeed: (t) => sp.succeed(t),
    fail: (t) => sp.fail(t),
    warn: (t) => sp.warn(t),
    info: (t) => sp.info(t),
    update: (t) => {
      sp.text = t;
    },
    stop: () => sp.stop(),
  };
}

export { chalk };
