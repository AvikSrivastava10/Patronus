/**
 * Registry of standalone Patronus checkers (Phase 3).
 *
 * Each checker conforms to the internal-analyzer interface:
 *   {
 *     id: string,
 *     displayName: string,
 *     appliesTo(detection): boolean,
 *     run(ctx): Promise<{ status, findings, reason?, version?, durationMs? }>
 *   }
 */

import missingAuth from './missing-auth.js';
import rateLimiting from './rate-limiting.js';
import securityHeaders from './security-headers.js';

export const ALL_CHECKERS = [missingAuth, rateLimiting, securityHeaders];
