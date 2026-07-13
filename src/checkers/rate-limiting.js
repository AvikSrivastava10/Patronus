/**
 * Checker: missing rate limiting on sensitive endpoints.
 *
 * Flags authentication-style routes (login, signup, password reset, OTP
 * verification, etc.) when NO rate limiter is detected anywhere in the app.
 * Brute-force and credential-stuffing protection depends on rate limiting these
 * endpoints.
 *
 * Heuristic, medium confidence. Route patterns and recognized rate-limit
 * middleware names are configurable.
 */

import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { STATUS } from '../adapters/base.js';
import { analyzeProject } from '../analysis/routes.js';

function matchesSensitiveRoute(route, patterns) {
  const p = String(route.path || '').toLowerCase();
  return patterns.some((pat) => p.includes(pat.toLowerCase()));
}

const checker = {
  id: TOOL.rateLimitChecker,
  displayName: 'Missing rate limiting',

  appliesTo(detection) {
    return detection.languages.includes('javascript') || detection.languages.includes('python');
  },

  async run(ctx) {
    const analysis = analyzeProject(ctx);
    if (!analysis.webAppDetected || analysis.routes.length === 0) {
      return { status: STATUS.ok, findings: [] };
    }

    const cfg = ctx.config?.checkers || {};
    const routePatterns = cfg.sensitiveRoutePatterns || [];
    const rlNames = new Set((cfg.rateLimitMiddlewareNames || []).map((s) => s.toLowerCase()));

    // If a rate limiter is configured anywhere (import, factory, global or
    // per-route guard), assume the app has rate limiting and don't flag.
    const guardHasLimiter = (guards) => guards.some((g) => rlNames.has(String(g).toLowerCase()));
    const limiterAnywhere =
      analysis.rateLimiterConfigured ||
      guardHasLimiter(analysis.globalGuards) ||
      analysis.routes.some((r) => guardHasLimiter(r.guards));

    if (limiterAnywhere) {
      return { status: STATUS.ok, findings: [] };
    }

    const findings = [];
    for (const route of analysis.routes) {
      if (!matchesSensitiveRoute(route, routePatterns)) continue;
      findings.push(
        createFinding({
          tool: TOOL.rateLimitChecker,
          ruleId: 'patronus.missing-rate-limit',
          severity: SEVERITY.medium,
          category: CATEGORY.missingRateLimit,
          file: route.file,
          line: route.line,
          message: `Auth-sensitive route ${route.method} ${route.path} has no rate limiting, and no rate limiter was detected anywhere in the app. This enables brute-force / credential-stuffing attacks.`,
          confidence: CONFIDENCE.medium,
          aiCodegenRelevant: true,
          remediation:
            'Add a rate limiter (e.g. express-rate-limit, flask-limiter) to authentication endpoints, or globally.',
          references: ['https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks'],
        }),
      );
    }

    return { status: STATUS.ok, findings };
  },
};

export default checker;
