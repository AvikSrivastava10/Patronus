#!/usr/bin/env node
/**
 * Clipeus CLI entrypoint.
 *
 * Wires the commander program to the command implementations in src/commands.
 * Command set is intentionally fixed for v1: init, scan, hook enable|disable,
 * doctor, plus --version / --help.
 */

import { Command } from 'commander';
import { scanCommand } from '../src/commands/scan.js';
import { doctorCommand } from '../src/commands/doctor.js';
import { initCommand } from '../src/commands/init.js';
import {
  hookEnableCommand,
  hookDisableCommand,
  hookStatusCommand,
} from '../src/commands/hook.js';
import { allSelectableIds } from '../src/scan/engine.js';
import { log } from '../src/core/logger.js';
import { VERSION, PRODUCT } from '../src/version.js';

const program = new Command();

program
  .name('clipeus')
  .description(
    `${PRODUCT} — free, read-only security & vulnerability auditing for your project.\n` +
      'Orchestrates open-source scanners and adds custom detection for gaps common in\n' +
      'AI-assisted ("vibe coded") development. Never modifies your code.',
  )
  .version(VERSION, '-v, --version', 'output the version number')
  .showHelpAfterError('(add --help for usage)');

program
  .command('init')
  .description('detect the project, check/install underlying tools, optionally add a pre-push hook, and write config')
  .action(async () => {
    await initCommand();
  });

program
  .command('scan')
  .argument('[path]', 'path to scan', '.')
  .description('run all applicable analyzers and report findings')
  .option('--json', 'output findings as JSON (unified schema)')
  .option('--markdown', 'output a markdown summary suitable for a PR comment')
  .option('--sarif', 'output SARIF 2.1.0 (GitHub code scanning / IDE viewers)')
  .option('--fail-on <severity>', 'minimum severity that causes a non-zero exit code: critical|high|medium|low')
  .option('--min-confidence <level>', 'only report findings at/above this confidence: high|medium|low')
  .option('--only <list>', 'run only the named tool(s)/check(s), comma-separated')
  .option('--skip <list>', 'run everything except the named tool(s)/check(s), comma-separated')
  .option('--baseline <file>', 'compare against a baseline file and report only NEW findings')
  .option('--update-baseline', 'record the current findings as the baseline (requires --baseline)')
  .option('--offline', 'avoid network features (e.g. Semgrep registry); use bundled rules only')
  .option('--verbose', 'include rule id, tool version, and references per finding')
  .option('--output <file>', 'write the report to a file instead of stdout')
  .addHelpText(
    'after',
    `\nAvailable tools/checks for --only/--skip:\n  ${allSelectableIds().join(', ')}\n\nExamples:\n  $ clipeus scan\n  $ clipeus scan ./services/api --fail-on=high\n  $ clipeus scan --sarif --output clipeus.sarif\n  $ clipeus scan --baseline .clipeus-baseline.json --fail-on=high   # gate only new issues\n  $ clipeus scan --baseline .clipeus-baseline.json --update-baseline # accept current state\n  $ clipeus scan --min-confidence=medium --offline`,
  )
  .action(async (pathArg, opts) => {
    await scanCommand(pathArg, opts);
  });

const hook = program
  .command('hook')
  .description('manage the git pre-push scan hook');

hook
  .command('enable')
  .description('install a pre-push hook that blocks pushes on findings at/above the threshold')
  .option('--fail-on <severity>', 'threshold the hook enforces (defaults to config failOn or critical)')
  .action((opts) => {
    hookEnableCommand(opts);
  });

hook
  .command('disable')
  .description('remove the Clipeus pre-push hook (preserves other hook content)')
  .action(() => {
    hookDisableCommand();
  });

hook
  .command('status')
  .description('show whether the pre-push hook is installed')
  .action(() => {
    hookStatusCommand();
  });

program
  .command('doctor')
  .description('check that every underlying tool is installed and runnable (read-only)')
  .action(async () => {
    await doctorCommand();
  });

program.parseAsync(process.argv).catch((err) => {
  log.error(err?.stack || err?.message || String(err));
  process.exit(1);
});
