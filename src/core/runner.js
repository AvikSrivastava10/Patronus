/**
 * Subprocess runner.
 *
 * Central choke point for every external tool invocation. Enforces the core
 * guarantees:
 *   - never throws to the caller (returns a structured result instead), so a
 *     single tool failure can never crash the overall scan;
 *   - always timeout-guarded;
 *   - read-only: this module never passes fix/write/autofix style arguments;
 *     adapters are responsible for constructing safe arg lists, but this is the
 *     only place processes are spawned.
 */

import process from 'node:process';
import { execa } from 'execa';
import { DEFAULT_TOOL_TIMEOUT_MS } from '../constants.js';
import { log } from './logger.js';

const MAX_BUFFER = 64 * 1024 * 1024; // 64MB, some scanners emit large JSON.

/**
 * Argument tokens that would indicate a mutating / auto-fix invocation. This is
 * a defensive guardrail: if any adapter ever accidentally passes one of these,
 * the run is refused rather than risking modification of the user's project.
 */
const FORBIDDEN_ARG_PATTERNS = [
  /^--fix$/i,
  /^--autofix$/i,
  /^--fix-dry-run$/i,
  /^--write$/i,
  /^--apply$/i,
  /^--force$/i,
];

function assertReadOnlyArgs(command, args) {
  for (const arg of args) {
    if (typeof arg !== 'string') continue;
    for (const pattern of FORBIDDEN_ARG_PATTERNS) {
      if (pattern.test(arg)) {
        throw new Error(
          `Refusing to run "${command} ${arg}": Patronus is strictly read-only and never invokes fix/write modes.`,
        );
      }
    }
  }
}

/**
 * Check whether a command is resolvable on PATH. Cross-platform, cheap, and
 * timeout-guarded. Never throws.
 * @param {string} command
 * @returns {Promise<boolean>}
 */
export async function commandExists(command) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const res = await execa(finder, [command], {
      timeout: 5000,
      reject: false,
      windowsHide: true,
    });
    return res.exitCode === 0 && String(res.stdout).trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Best-effort tool version string. Never throws; returns null if unavailable.
 * @param {string} command
 * @param {string[]} versionArgs
 * @returns {Promise<string|null>}
 */
export async function getToolVersion(command, versionArgs = ['--version']) {
  try {
    const res = await execa(command, versionArgs, {
      timeout: 15000,
      reject: false,
      windowsHide: true,
    });
    const out = `${res.stdout ?? ''}\n${res.stderr ?? ''}`.trim();
    if (!out) return null;
    // Return the first non-empty line, trimmed; keep it short.
    const firstLine = out.split(/\r?\n/).find((l) => l.trim().length > 0) ?? out;
    return firstLine.trim().slice(0, 200);
  } catch {
    return null;
  }
}

/**
 * @typedef {Object} RunResult
 * @property {boolean} ok            true when the process ran and exited 0.
 * @property {boolean} ran           true when the process was actually spawned.
 * @property {string}  stdout
 * @property {string}  stderr
 * @property {number|null} exitCode
 * @property {boolean} timedOut
 * @property {boolean} notFound      true when the binary was not found (ENOENT).
 * @property {string|null} errorCode Node/execa error code, if any.
 * @property {string|null} errorMessage
 * @property {number}  durationMs
 */

/**
 * Run a tool and always resolve with a structured {@link RunResult}. Non-zero
 * exit codes are NOT treated as thrown errors (many scanners exit non-zero
 * simply because they found issues).
 *
 * @param {Object} opts
 * @param {string} opts.command
 * @param {string[]} [opts.args]
 * @param {string} [opts.cwd]
 * @param {number} [opts.timeoutMs]
 * @param {Record<string,string>} [opts.env]
 * @param {string} [opts.input]     Optional stdin payload.
 * @returns {Promise<RunResult>}
 */
export async function runTool({
  command,
  args = [],
  cwd = process.cwd(),
  timeoutMs = DEFAULT_TOOL_TIMEOUT_MS,
  env,
  input,
}) {
  const started = Date.now();
  const base = {
    ok: false,
    ran: false,
    stdout: '',
    stderr: '',
    exitCode: null,
    timedOut: false,
    notFound: false,
    errorCode: null,
    errorMessage: null,
    durationMs: 0,
  };

  try {
    assertReadOnlyArgs(command, args);
  } catch (err) {
    return { ...base, errorMessage: err.message, durationMs: Date.now() - started };
  }

  log.debug(`exec: ${command} ${args.join(' ')} (timeout ${timeoutMs}ms, cwd ${cwd})`);

  try {
    const res = await execa(command, args, {
      cwd,
      timeout: timeoutMs,
      reject: false,
      windowsHide: true,
      maxBuffer: MAX_BUFFER,
      env: env ? { ...process.env, ...env } : undefined,
      input,
      stripFinalNewline: false,
    });

    const durationMs = Date.now() - started;
    return {
      ok: res.exitCode === 0 && !res.failed,
      ran: true,
      stdout: res.stdout ?? '',
      stderr: res.stderr ?? '',
      exitCode: typeof res.exitCode === 'number' ? res.exitCode : null,
      timedOut: Boolean(res.timedOut),
      notFound: res.code === 'ENOENT',
      errorCode: res.code ?? null,
      errorMessage: res.failed ? res.shortMessage ?? res.message ?? null : null,
      durationMs,
    };
  } catch (err) {
    // execa can still throw for spawn-level failures (e.g. ENOENT) even with
    // reject:false, depending on the error. Capture and degrade gracefully.
    const durationMs = Date.now() - started;
    return {
      ...base,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
      exitCode: typeof err.exitCode === 'number' ? err.exitCode : null,
      timedOut: Boolean(err.timedOut),
      notFound: err.code === 'ENOENT',
      errorCode: err.code ?? null,
      errorMessage: err.shortMessage ?? err.message ?? String(err),
      durationMs,
    };
  }
}
