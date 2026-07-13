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
 *
 * Populated in Phase 3 (missing-auth, rate-limiting, security-headers).
 */

export const ALL_CHECKERS = [];
