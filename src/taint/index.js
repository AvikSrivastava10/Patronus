/**
 * Registry for the cross-file taint tracking engine (Phase 4).
 *
 * Exposes taint analysis as one or more internal analyzers conforming to the
 * same interface as the Phase 3 checkers, so the scan engine can treat every
 * detection layer uniformly. Populated in Phase 4.
 */

export const TAINT_ANALYZERS = [];
