/**
 * Resolve the package version at runtime (used by --version and report output).
 */

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let version = '0.0.0';
try {
  version = require('../package.json').version || version;
} catch {
  /* fall back to placeholder */
}

export const VERSION = version;
export const PRODUCT = 'Patronus';
