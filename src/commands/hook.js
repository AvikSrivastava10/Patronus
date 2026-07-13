/**
 * `patronus hook enable|disable` command.
 *
 * enable  -> installs a pre-push hook running `patronus scan --fail-on=<threshold>`
 * disable -> removes the managed hook block, preserving any other hook content
 */

import path from 'node:path';
import { enableHook, disableHook, hookStatus } from '../hooks/git-hook.js';
import { loadConfig } from '../config/config.js';
import { detectProject } from '../detectors/detect.js';
import { log, chalk } from '../core/logger.js';
import { SEVERITY } from '../constants.js';

export function hookEnableCommand(opts = {}) {
  const root = process.cwd();
  const detection = detectProject(root);
  if (!detection.stacks.git) {
    log.error('No .git directory found. Initialize a git repository first.');
    process.exitCode = 2;
    return;
  }

  const { config } = loadConfig(root);
  let threshold = (opts.failOn ? String(opts.failOn).toLowerCase() : config.failOn) || 'critical';
  if (!SEVERITY[threshold]) {
    log.warn(`Invalid threshold "${threshold}"; using "critical".`);
    threshold = 'critical';
  }

  try {
    const result = enableHook(root, { threshold });
    const rel = path.relative(root, result.path) || result.path;
    log.success(`Pre-push hook ${result.action} (${result.kind}) at ${rel}`);
    log.info(chalk.gray(`   runs: patronus scan --fail-on=${threshold}`));
  } catch (err) {
    log.error(`Could not enable hook: ${err.message}`);
    process.exitCode = 2;
  }
}

export function hookDisableCommand() {
  const root = process.cwd();
  try {
    const result = disableHook(root);
    const rel = path.relative(root, result.path) || result.path;
    switch (result.action) {
      case 'removed':
        log.success(`Removed Patronus block from existing hook at ${rel}.`);
        break;
      case 'file-deleted':
        log.success(`Removed pre-push hook at ${rel}.`);
        break;
      case 'not-present':
        log.info('No Patronus-managed block found in the pre-push hook; nothing to remove.');
        break;
      case 'not-found':
      default:
        log.info('No pre-push hook found; nothing to remove.');
        break;
    }
  } catch (err) {
    log.error(`Could not disable hook: ${err.message}`);
    process.exitCode = 2;
  }
}

export function hookStatusCommand() {
  const root = process.cwd();
  const status = hookStatus(root);
  const rel = path.relative(root, status.path) || status.path;
  if (status.enabled) {
    log.info(`${chalk.green('enabled')} — ${status.kind} hook at ${rel}`);
  } else {
    log.info(`${chalk.gray('disabled')} — no managed hook at ${rel}`);
  }
}
