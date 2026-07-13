/**
 * Bundled ESLint flat config used by Patronus's ESLint adapter.
 *
 * This is intentionally self-contained: it registers ONLY the security-focused
 * plugins (eslint-plugin-security, eslint-plugin-no-unsanitized) and enables
 * their rules. Patronus points ESLint at this file with `overrideConfigFile`,
 * so results are independent of whatever ESLint config the target project has
 * (or lacks). Plugins resolve from Patronus's own node_modules.
 *
 * Nothing here modifies user code: ESLint is run in lint-only mode.
 */

import security from 'eslint-plugin-security';
import nounsanitized from 'eslint-plugin-no-unsanitized';
import tsParser from '@typescript-eslint/parser';

// Pull the plugin's recommended rule set if exposed, else enable all its rules.
const securityRules =
  security?.configs?.recommended?.rules ??
  Object.fromEntries(Object.keys(security?.rules ?? {}).map((r) => [`security/${r}`, 'warn']));

const noUnsanitizedRules = {
  'no-unsanitized/method': 'error',
  'no-unsanitized/property': 'error',
};

const plugins = { security, 'no-unsanitized': nounsanitized };
const rules = { ...securityRules, ...noUnsanitizedRules };

const jsLanguageOptions = {
  ecmaVersion: 'latest',
  sourceType: 'module',
  parserOptions: { ecmaFeatures: { jsx: true } },
};

export default [
  {
    // Never descend into dependency/build output.
    ignores: [
      '**/node_modules/**', '**/dist/**', '**/build/**', '**/out/**',
      '**/coverage/**', '**/.next/**', '**/.nuxt/**', '**/vendor/**',
      '**/*.min.js', '**/.venv/**', '**/venv/**',
    ],
  },
  {
    files: ['**/*.js', '**/*.jsx', '**/*.mjs', '**/*.cjs'],
    languageOptions: jsLanguageOptions,
    plugins,
    rules,
  },
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins,
    rules,
  },
];
