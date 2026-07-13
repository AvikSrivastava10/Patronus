/**
 * Adapter base: shared helpers + the generic adapter runner.
 *
 * Each tool adapter exports an object describing how to invoke the tool and how
 * to normalize its output. `runAdapter` is the single, hardened entry point
 * that:
 *   - checks availability,
 *   - builds a read-only invocation,
 *   - runs it under a timeout,
 *   - parses + normalizes output into unified findings,
 *   - and ALWAYS resolves with a structured status (never throws).
 *
 * @typedef {Object} Adapter
 * @property {string} id
 * @property {string} displayName
 * @property {string} command
 * @property {string[]} [versionArgs]
 * @property {string} [license]
 * @property {string} [homepage]
 * @property {Object} [install]          Install hints per package manager.
 * @property {(ctx:object)=>object} [buildInvocation]  Returns invocation descriptor.
 * @property {(text:string, ctx:object)=>any} [parse]  Raw text -> parsed payload.
 * @property {(parsed:any, ctx:object)=>object[]} normalize  Parsed -> Finding[].
 * @property {(ctx:object)=>Promise<object>} [runCustom]  Fully custom runner.
 */

import fs from 'node:fs';
import { SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { runTool, commandExists, getToolVersion } from '../core/runner.js';
import { log } from '../core/logger.js';

/**
 * Best-effort mapping of free-text (rule id + message) onto the internal
 * category taxonomy. Used by adapters whose tools don't emit a category we can
 * map deterministically (Semgrep community rules, ESLint, Bandit).
 */
export function inferCategory(text, fallback = CATEGORY.other) {
  const s = String(text || '').toLowerCase();
  const rules = [
    [/cookie/, CATEGORY.insecureCookie],
    [/\bcors\b|access-control-allow-origin/, CATEGORY.corsMisconfig],
    [/\bjwt\b|jsonwebtoken|jws\b/, CATEGORY.insecureJwt],
    [/sql|sqli|injection|command.?inj|\beval\b|\bexec\b|code.?inj/, CATEGORY.injection],
    [/ssrf|server.?side.?request/, CATEGORY.ssrf],
    [/path.?travers|directory.?travers|\blfi\b/, CATEGORY.pathTraversal],
    [/deserial|pickle|unmarshal|yaml.?load/, CATEGORY.deserialization],
    [/md5|sha1|sha-1|weak.?hash|weak.?crypto|\bdes\b|\brc4\b|password.?hash|bcrypt|scrypt|argon/, CATEGORY.insecureCrypto],
    [/tls|ssl|certificate|verify|rejectunauthorized|insecure.?request/, CATEGORY.insecureTransport],
    [/secret|hardcoded|api.?key|access.?key|private.?key|credential|password\b/, CATEGORY.secrets],
    [/cve-|vulnerab|advisory|outdated|dependency/, CATEGORY.dependencyCve],
    [/debug|stack.?trace|traceback|error.?detail|verbose.?error/, CATEGORY.infoDisclosure],
    [/dockerfile|kubernetes|k8s|terraform|iac|misconfig/, CATEGORY.iacMisconfig],
    [/csrf|xss|cross.?site|sanitiz|unsanitiz/, CATEGORY.injection],
  ];
  for (const [re, cat] of rules) {
    if (re.test(s)) return cat;
  }
  return fallback;
}

/** Adapter run outcome statuses. */
export const STATUS = Object.freeze({
  ok: 'ok',
  skipped: 'skipped',
  error: 'error',
  timeout: 'timeout',
});

/** Map a wide variety of tool severity spellings onto the canonical scale. */
export function normalizeSeverity(value, fallback = SEVERITY.medium) {
  if (value == null) return fallback;
  const v = String(value).toLowerCase().trim();
  switch (v) {
    case 'critical':
    case 'crit':
      return SEVERITY.critical;
    case 'high':
    case 'error':
    case 'severe':
      return SEVERITY.high;
    case 'moderate':
    case 'medium':
    case 'warning':
    case 'warn':
    case 'med':
      return SEVERITY.medium;
    case 'low':
    case 'info':
    case 'informational':
    case 'note':
    case 'unknown':
    case 'negligible':
      return SEVERITY.low;
    default:
      return fallback;
  }
}

/** Safe JSON parse that returns null instead of throwing. */
export function parseJsonSafe(text) {
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Parse JSONL (newline-delimited JSON), skipping unparseable lines. */
export function parseJsonlSafe(text) {
  if (!text) return [];
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      /* ignore malformed line */
    }
  }
  return out;
}

/**
 * Redact a secret value so it never appears in a report. Keeps a short prefix
 * for correlation only.
 */
export function redactSecret(value) {
  if (!value) return '[redacted]';
  const s = String(value);
  if (s.length <= 6) return '******';
  return `${s.slice(0, 3)}…[redacted, ${s.length} chars]`;
}

/** Format install instructions into a single-line hint. */
export function installHint(adapter) {
  const i = adapter.install || {};
  if (i.recommended) return i.recommended;
  const parts = [];
  if (i.pip) parts.push(i.pip);
  if (i.brew) parts.push(i.brew);
  if (i.npm) parts.push(i.npm);
  if (i.go) parts.push(i.go);
  if (i.url) parts.push(`see ${i.url}`);
  return parts.length ? parts.join('  |  ') : `install ${adapter.command}`;
}

function readOutput(invocation, runResult) {
  const out = invocation.output || { type: 'stdout' };
  if (out.type === 'stdout') return runResult.stdout;
  if (out.type === 'file' || out.type === 'dir') {
    const filePath = out.type === 'file' ? out.path : out.file;
    try {
      if (fs.existsSync(filePath)) return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
      log.debug(`readOutput: could not read ${filePath} (${err.message})`);
    }
    // Fall back to stdout if the file wasn't produced.
    return runResult.stdout;
  }
  return runResult.stdout;
}

function cleanupOutput(invocation) {
  const out = invocation.output;
  if (!out || !out.cleanup) return;
  const target = out.type === 'file' ? out.path : out.dir || out.file;
  if (!target) return;
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
}

/**
 * Run one adapter end-to-end. Never throws.
 *
 * @param {Adapter} adapter
 * @param {object} ctx  Scan context (root, config, detection, tmpDir, ...).
 * @returns {Promise<{
 *   id:string, displayName:string, status:string, findings:object[],
 *   reason:string|null, version:string|null, durationMs:number,
 *   installHint:string|null, rawExitCode:number|null
 * }>}
 */
export async function runAdapter(adapter, ctx) {
  const started = Date.now();
  const result = {
    id: adapter.id,
    displayName: adapter.displayName,
    status: STATUS.skipped,
    findings: [],
    reason: null,
    version: null,
    durationMs: 0,
    installHint: null,
    rawExitCode: null,
  };

  try {
    // Fully custom adapters (e.g. ESLint via bundled deps) manage their own flow.
    if (typeof adapter.runCustom === 'function') {
      const custom = await adapter.runCustom(ctx);
      return {
        ...result,
        status: custom.status ?? STATUS.ok,
        findings: Array.isArray(custom.findings) ? custom.findings : [],
        reason: custom.reason ?? null,
        version: custom.version ?? null,
        durationMs: Date.now() - started,
        installHint: custom.installHint ?? null,
      };
    }

    const available = await commandExists(adapter.command);
    if (!available) {
      return {
        ...result,
        status: STATUS.skipped,
        reason: `${adapter.command} is not installed`,
        installHint: installHint(adapter),
        durationMs: Date.now() - started,
      };
    }

    // Optional adapter-specific precondition (e.g. npm audit needs a lockfile).
    if (typeof adapter.precheck === 'function') {
      const pre = adapter.precheck(ctx);
      if (pre && pre.skip) {
        return {
          ...result,
          status: STATUS.skipped,
          reason: pre.reason || 'precondition not met',
          durationMs: Date.now() - started,
        };
      }
    }

    result.version = await getToolVersion(adapter.command, adapter.versionArgs);

    const invocation = adapter.buildInvocation(ctx);
    const runResult = await runTool({
      command: invocation.command ?? adapter.command,
      args: invocation.args ?? [],
      cwd: invocation.cwd ?? ctx.root,
      timeoutMs: invocation.timeoutMs ?? ctx.config?.toolTimeoutMs,
      env: invocation.env,
      input: invocation.input,
    });
    result.rawExitCode = runResult.exitCode;

    if (runResult.timedOut) {
      cleanupOutput(invocation);
      return {
        ...result,
        status: STATUS.timeout,
        reason: `timed out after ${Math.round((invocation.timeoutMs ?? ctx.config?.toolTimeoutMs ?? 0) / 1000)}s`,
        durationMs: Date.now() - started,
      };
    }
    if (runResult.notFound) {
      cleanupOutput(invocation);
      return {
        ...result,
        status: STATUS.skipped,
        reason: `${adapter.command} is not installed`,
        installHint: installHint(adapter),
        durationMs: Date.now() - started,
      };
    }

    const outputText = readOutput(invocation, runResult);
    const parser = typeof adapter.parse === 'function' ? adapter.parse : parseJsonSafe;
    const parsed = parser(outputText, ctx);
    cleanupOutput(invocation);

    if (parsed == null) {
      // No parseable output. If the tool also failed, surface an error;
      // otherwise treat as a clean run with zero findings.
      if (!runResult.ok && runResult.exitCode !== 0) {
        const stderrSnippet = (runResult.stderr || runResult.errorMessage || '').split(/\r?\n/).slice(0, 3).join(' ').slice(0, 300);
        return {
          ...result,
          status: STATUS.error,
          reason: stderrSnippet || `exited ${runResult.exitCode} with unparseable output`,
          durationMs: Date.now() - started,
        };
      }
      return { ...result, status: STATUS.ok, findings: [], durationMs: Date.now() - started };
    }

    let findings = [];
    try {
      findings = adapter.normalize(parsed, ctx) || [];
    } catch (err) {
      return {
        ...result,
        status: STATUS.error,
        reason: `normalization failed: ${err.message}`,
        durationMs: Date.now() - started,
      };
    }

    return {
      ...result,
      status: STATUS.ok,
      findings,
      durationMs: Date.now() - started,
    };
  } catch (err) {
    log.debug(`runAdapter(${adapter.id}) crashed: ${err.stack || err.message}`);
    return {
      ...result,
      status: STATUS.error,
      reason: err.message,
      durationMs: Date.now() - started,
    };
  }
}

export { SEVERITY, CONFIDENCE };
