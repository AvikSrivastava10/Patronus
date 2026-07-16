/**
 * Configuration loading + defaults.
 *
 * Clipeus reads `clipeus.config.json` (preferred) or `.clipeusrc` /
 * `.clipeusrc.json` from the scan root. Missing or malformed config never
 * crashes the run: we warn and fall back to defaults. User config is deep-merged
 * onto defaults so partial overrides work.
 */

import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_TOOL_TIMEOUT_MS, SEVERITY } from '../constants.js';
import { log } from '../core/logger.js';

const CONFIG_FILENAMES = ['clipeus.config.json', '.clipeusrc.json', '.clipeusrc'];

/**
 * The canonical default configuration. `init` writes a trimmed, user-friendly
 * version of this; the scanner always merges user config over these values.
 */
export function getDefaultConfig() {
  return {
    // Minimum severity that causes a non-zero exit code.
    failOn: SEVERITY.critical,

    // Per-tool subprocess timeout (ms).
    toolTimeoutMs: DEFAULT_TOOL_TIMEOUT_MS,

    // Explicit enable/disable overrides. Empty `enabled` means "auto-detect".
    tools: {
      enabled: [],
      disabled: [],
    },

    // Tuning knobs for the standalone checkers (Phase 3).
    checkers: {
      // Route path fragments considered "sensitive" for the missing-auth check.
      sensitivePathKeywords: [
        'admin', 'user', 'users', 'account', 'accounts', 'payment', 'payments',
        'billing', 'checkout', 'settings', 'profile', 'internal', 'dashboard',
        'order', 'orders', 'invoice', 'transfer', 'withdraw',
      ],
      // Recognized auth middleware / decorator names (JS + Python).
      authMiddlewareNames: [
        'requireAuth', 'requireLogin', 'isAuthenticated', 'ensureAuth',
        'ensureAuthenticated', 'ensureLoggedIn', 'authenticate', 'authGuard',
        'authMiddleware', 'verifyToken', 'verifyJwt', 'checkAuth', 'protect',
        'login_required', 'permission_classes', 'permission_required',
        'authentication_classes', 'jwt_required', 'token_required',
      ],
      // Recognized rate-limiting middleware / decorator names.
      rateLimitMiddlewareNames: [
        'rateLimit', 'rateLimiter', 'limiter', 'Limiter', 'RateLimiter',
        'expressRateLimit', 'slowDown', 'throttle', 'rate_limit', 'limits',
        'shared_limit', 'default_limits',
      ],
      // Route path fragments that especially warrant rate limiting.
      sensitiveRoutePatterns: [
        'login', 'signin', 'sign-in', 'signup', 'sign-up', 'register',
        'password', 'reset', 'forgot', 'otp', 'verify', 'verification',
        'token', 'auth', '2fa', 'mfa',
      ],
    },

    // Tuning knobs for the taint tracker (Phase 4).
    taint: {
      sources: [
        'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
        'request.body', 'request.query', 'request.params',
        'request.form', 'request.args', 'request.values', 'request.json',
        'request.data', 'request.GET', 'request.POST', 'process.argv',
      ],
      sinks: [
        'eval', 'exec', 'execSync', 'child_process.exec', 'child_process.execSync',
        'child_process.spawn', 'query', 'execute', 'executemany', 'raw',
        'fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync',
        'os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
        'subprocess.Popen', 'cursor.execute',
      ],
      sanitizers: [
        'escape', 'escapeHtml', 'sanitize', 'sanitizeHtml', 'validate',
        'parameterize', 'parseInt', 'parseFloat', 'Number', 'encodeURIComponent',
        'shlex.quote', 'bleach.clean', 'escape_string', 'mysql.escape',
        'validator', 'zod', 'joi',
      ],
    },

    // How to treat likely-false-positive secret hits inside data files
    // (CSV/Parquet/ML datasets, …):
    //   'demote' (default) — drop to low severity/confidence but keep on record,
    //   'ignore'           — drop them entirely,
    //   'keep'             — no special handling (report as the scanner rated them).
    // High-confidence rule matches and verified secrets are never affected.
    secrets: {
      dataFiles: 'demote',
    },

    // Additional suppression patterns merged with .clipeusignore entries.
    ignore: [],
  };
}

/** Known configuration keys, for typo detection (warnings only). */
const KNOWN_KEYS = {
  root: ['failOn', 'toolTimeoutMs', 'tools', 'checkers', 'taint', 'ignore', 'secrets', 'semgrep', 'gitleaks', 'trufflehog', 'trivy'],
  tools: ['enabled', 'disabled'],
  checkers: ['sensitivePathKeywords', 'authMiddlewareNames', 'rateLimitMiddlewareNames', 'sensitiveRoutePatterns'],
  taint: ['sources', 'sinks', 'sanitizers'],
  secrets: ['dataFiles'],
};

/** Warn (never throw) about unrecognized config keys to catch typos. */
function validateConfig(parsed, fileLabel) {
  const warnUnknown = (obj, known, scope) => {
    if (!isPlainObject(obj)) return;
    for (const key of Object.keys(obj)) {
      if (!known.includes(key)) {
        log.warn(`${fileLabel}: unknown config key "${scope}${key}" (ignored — check for typos).`);
      }
    }
  };
  warnUnknown(parsed, KNOWN_KEYS.root, '');
  warnUnknown(parsed.tools, KNOWN_KEYS.tools, 'tools.');
  warnUnknown(parsed.checkers, KNOWN_KEYS.checkers, 'checkers.');
  warnUnknown(parsed.taint, KNOWN_KEYS.taint, 'taint.');
  warnUnknown(parsed.secrets, KNOWN_KEYS.secrets, 'secrets.');
}

function isPlainObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

/** Deep-merge `source` onto `target` (arrays are replaced, not concatenated). */
function deepMerge(target, source) {
  const out = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (isPlainObject(value) && isPlainObject(out[key])) {
      out[key] = deepMerge(out[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Locate the first existing config file in `cwd`.
 * @returns {string|null} absolute path or null.
 */
export function findConfigFile(cwd = process.cwd()) {
  for (const name of CONFIG_FILENAMES) {
    const p = path.join(cwd, name);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  }
  return null;
}

/**
 * Load and merge configuration. Never throws.
 * @param {string} cwd
 * @returns {{ config: object, path: string|null }}
 */
export function loadConfig(cwd = process.cwd()) {
  const defaults = getDefaultConfig();
  const file = findConfigFile(cwd);
  if (!file) return { config: defaults, path: null };

  try {
    const rawText = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(rawText);
    if (!isPlainObject(parsed)) {
      log.warn(`Config at ${path.basename(file)} is not an object; using defaults.`);
      return { config: defaults, path: file };
    }
    validateConfig(parsed, path.basename(file));
    if (parsed.failOn && !SEVERITY[String(parsed.failOn).toLowerCase()]) {
      log.warn(`Config failOn "${parsed.failOn}" is invalid; expected critical|high|medium|low.`);
      delete parsed.failOn;
    }
    return { config: deepMerge(defaults, parsed), path: file };
  } catch (err) {
    log.warn(`Failed to parse ${path.basename(file)} (${err.message}); using defaults.`);
    return { config: defaults, path: file };
  }
}

export { CONFIG_FILENAMES };
