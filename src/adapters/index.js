/**
 * Adapter registry. Maps tool ids to their adapter modules.
 */

import semgrep from './semgrep.js';
import gitleaks from './gitleaks.js';
import trufflehog from './trufflehog.js';
import npmAudit from './npm-audit.js';
import pipAudit from './pip-audit.js';
import eslint from './eslint.js';
import bandit from './bandit.js';
import trivy from './trivy.js';

export const ALL_ADAPTERS = [
  semgrep,
  gitleaks,
  trufflehog,
  npmAudit,
  pipAudit,
  eslint,
  bandit,
  trivy,
];

export const ADAPTERS = Object.freeze(
  Object.fromEntries(ALL_ADAPTERS.map((a) => [a.id, a])),
);

/** Get an adapter by its tool id, or undefined. */
export function getAdapter(id) {
  return ADAPTERS[id];
}

export {
  semgrep,
  gitleaks,
  trufflehog,
  npmAudit,
  pipAudit,
  eslint,
  bandit,
  trivy,
};
