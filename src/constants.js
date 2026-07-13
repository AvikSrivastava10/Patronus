/**
 * Shared constants for Patronus.
 *
 * These define the canonical vocabulary that every layer (adapters, checkers,
 * taint tracker, reporting) normalizes into. Keeping them in one place ensures
 * the unified schema stays consistent across the whole pipeline.
 */

/**
 * Canonical severity levels. Every tool's native severity scale is normalized
 * into exactly one of these. The numeric weight is used for `--fail-on`
 * threshold comparisons and for sorting/grouping in reports.
 */
export const SEVERITY = Object.freeze({
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
});

export const SEVERITY_ORDER = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

/** Ordered list, most severe first. Useful for grouped reporting. */
export const SEVERITIES_DESC = Object.freeze(['critical', 'high', 'medium', 'low']);

/** Confidence levels attached to findings. Heuristic checks use medium/low. */
export const CONFIDENCE = Object.freeze({
  high: 'high',
  medium: 'medium',
  low: 'low',
});

export const CONFIDENCE_ORDER = Object.freeze({
  high: 3,
  medium: 2,
  low: 1,
});

/**
 * Internal category taxonomy. Findings from every source map onto this set
 * regardless of which tool produced them, so dedup and filtering work across
 * tools. Keep this list stable; adapters and rules reference these strings.
 */
export const CATEGORY = Object.freeze({
  injection: 'injection',
  secrets: 'secrets',
  dependencyCve: 'dependency-cve',
  insecureConfig: 'insecure-config',
  missingAuth: 'missing-auth',
  missingRateLimit: 'missing-rate-limit',
  missingSecurityHeaders: 'missing-security-headers',
  insecureCrypto: 'insecure-crypto',
  insecureTransport: 'insecure-transport',
  insecureCookie: 'insecure-cookie-flags',
  insecureJwt: 'insecure-jwt',
  corsMisconfig: 'cors-misconfig',
  infoDisclosure: 'info-disclosure',
  iacMisconfig: 'iac-misconfig',
  ssrf: 'ssrf',
  pathTraversal: 'path-traversal',
  deserialization: 'insecure-deserialization',
  other: 'other',
});

export const CATEGORY_VALUES = Object.freeze(Object.values(CATEGORY));

/**
 * Canonical tool / check identifiers used in the `tool` field of findings.
 * External scanners plus the internal Patronus checkers/engines.
 */
export const TOOL = Object.freeze({
  semgrep: 'semgrep',
  gitleaks: 'gitleaks',
  trufflehog: 'trufflehog',
  npmAudit: 'npm-audit',
  pipAudit: 'pip-audit',
  eslint: 'eslint',
  bandit: 'bandit',
  trivy: 'trivy',
  owaspDependencyCheck: 'owasp-dependency-check',
  // Internal Patronus detection layers:
  authChecker: 'patronus-auth',
  rateLimitChecker: 'patronus-rate-limit',
  securityHeadersChecker: 'patronus-security-headers',
  taint: 'patronus-taint',
});

/** Default per-tool subprocess timeout in milliseconds. */
export const DEFAULT_TOOL_TIMEOUT_MS = 120_000;

/** Marker filenames used by project detection, grouped by stack. */
export const MARKERS = Object.freeze({
  node: ['package.json'],
  python: ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg'],
  docker: ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yaml', 'compose.yml'],
  terraform: ['*.tf'],
  java: ['pom.xml', 'build.gradle', 'build.gradle.kts'],
  dotnet: ['*.csproj', '*.sln', '*.vbproj', '*.fsproj'],
});

export const PRODUCT_NAME = 'Patronus';
