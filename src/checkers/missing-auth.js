/**
 * Checker: missing authentication/authorization on sensitive routes.
 *
 * Parses route definitions (Express, Flask) and flags handlers on
 * sensitive-looking paths that have no recognizable auth guard in their
 * middleware/decorator chain (or applied globally).
 *
 * This is a heuristic — findings are medium confidence. The "sensitive path"
 * keyword list and recognized auth guard names are configurable via
 * patronus.config.json so teams can tune it to their own naming.
 */

import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { STATUS } from '../adapters/base.js';
import { analyzeProject } from '../analysis/routes.js';

const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

// Generous "looks like auth" keywords: we only flag a route when NONE of its
// guards look auth-related, favoring precision (fewer false positives).
const AUTH_KEYWORDS = [
  'auth', 'login', 'jwt', 'token', 'session', 'permission', 'protect',
  'guard', 'verify', 'ensure', 'require', 'authoriz', 'authenticat', 'admin',
];

function isAuthGuard(name, configuredNames) {
  const n = String(name).toLowerCase();
  if (configuredNames.has(n)) return true;
  return AUTH_KEYWORDS.some((k) => n.includes(k));
}

function isSensitivePath(route, keywords) {
  const p = String(route.path || '').toLowerCase();
  if (keywords.some((k) => p.includes(k.toLowerCase()))) return true;
  // Mutating verbs under /api/* are sensitive even without a keyword match.
  if (MUTATING.has(route.method) && /(^|\/)api(\/|$)/.test(p)) return true;
  return false;
}

const checker = {
  id: TOOL.authChecker,
  displayName: 'Missing auth (routes)',

  appliesTo(detection) {
    return detection.languages.includes('javascript') || detection.languages.includes('python');
  },

  async run(ctx) {
    const analysis = analyzeProject(ctx);
    if (!analysis.webAppDetected || analysis.routes.length === 0) {
      return { status: STATUS.ok, findings: [] };
    }

    const cfg = ctx.config?.checkers || {};
    const sensitiveKeywords = cfg.sensitivePathKeywords || [];
    const authNames = new Set((cfg.authMiddlewareNames || []).map((s) => s.toLowerCase()));

    // A globally-applied auth guard covers everything (lenient, low-FP).
    const globalHasAuth = analysis.globalGuards.some((g) => isAuthGuard(g, authNames));
    if (globalHasAuth) {
      return { status: STATUS.ok, findings: [] };
    }

    const findings = [];
    for (const route of analysis.routes) {
      if (!isSensitivePath(route, sensitiveKeywords)) continue;
      const guarded = route.guards.some((g) => isAuthGuard(g, authNames));
      if (guarded) continue;

      findings.push(
        createFinding({
          tool: TOOL.authChecker,
          ruleId: 'patronus.missing-auth',
          severity: SEVERITY.high,
          category: CATEGORY.missingAuth,
          file: route.file,
          line: route.line,
          message: `Route ${route.method} ${route.path} looks sensitive but has no detected authentication/authorization guard in its handler chain.`,
          confidence: CONFIDENCE.medium,
          aiCodegenRelevant: true,
          remediation:
            'Attach an auth middleware/decorator (e.g. requireAuth, @login_required) to this route, or apply one globally. If this route is intentionally public, add it to .patronusignore or tune checkers.sensitivePathKeywords.',
          references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
        }),
      );
    }

    return { status: STATUS.ok, findings };
  },
};

export default checker;
