/**
 * Checker: missing security headers.
 *
 * For a detected web app, flags the absence of a security-headers layer:
 *   - Node/Express: `helmet` (or manual CSP + HSTS)
 *   - Python/Flask: flask-talisman / secure (or manual CSP + HSTS)
 *
 * Emits a single project-level finding when no such protection is detected.
 * Heuristic (headers might be set at a proxy/CDN), so medium confidence.
 */

import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { STATUS } from '../adapters/base.js';
import { analyzeProject } from '../analysis/routes.js';

const checker = {
  id: TOOL.securityHeadersChecker,
  displayName: 'Missing security headers',

  appliesTo(detection) {
    return detection.languages.includes('javascript') || detection.languages.includes('python');
  },

  async run(ctx) {
    const analysis = analyzeProject(ctx);
    if (!analysis.webAppDetected) {
      return { status: STATUS.ok, findings: [] };
    }

    const headersHandled =
      analysis.helmetUsed || (analysis.cspConfigured && analysis.hstsConfigured);
    if (headersHandled) {
      return { status: STATUS.ok, findings: [] };
    }

    const missing = [];
    if (!analysis.cspConfigured) missing.push('Content-Security-Policy');
    if (!analysis.hstsConfigured) missing.push('Strict-Transport-Security (HSTS)');

    const file = analysis.routes[0]?.file || '';
    const finding = createFinding({
      tool: TOOL.securityHeadersChecker,
      ruleId: 'patronus.missing-security-headers',
      severity: SEVERITY.medium,
      category: CATEGORY.missingSecurityHeaders,
      file,
      line: null,
      message: `No security-headers middleware detected (e.g. helmet / flask-talisman) and key headers appear unset: ${missing.join(', ')}. Responses may lack CSP, HSTS, X-Content-Type-Options, and related protections.`,
      confidence: CONFIDENCE.medium,
      aiCodegenRelevant: true,
      remediation:
        'Add a security-headers layer: `app.use(helmet())` (Express) or flask-talisman (Flask). Configure CSP and HSTS explicitly. If headers are set at a reverse proxy/CDN, suppress this via .patronusignore.',
      references: ['https://owasp.org/www-project-secure-headers/'],
    });

    return { status: STATUS.ok, findings: [finding] };
  },
};

export default checker;
