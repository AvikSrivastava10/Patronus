/**
 * JavaScript/TypeScript parsing helpers built on @babel/parser + traverse.
 *
 * Everything here is read-only and never throws: a file that fails to parse
 * yields null so the caller can skip it and continue (a single malformed file
 * must never crash a checker or the scan).
 */

import { parse } from '@babel/parser';
import babelTraverse from '@babel/traverse';
import { log } from '../core/logger.js';

// @babel/traverse ships as CommonJS; under ESM the callable lands on .default
// (sometimes double-wrapped). Normalize to the actual function.
export const traverse =
  typeof babelTraverse === 'function'
    ? babelTraverse
    : babelTraverse?.default?.default || babelTraverse?.default || babelTraverse;

const TS_EXTS = new Set(['.ts', '.tsx', '.mts', '.cts']);
const JSX_EXTS = new Set(['.jsx', '.tsx', '.js', '.mjs', '.cjs']);

/**
 * Parse JS/TS source into a Babel AST. Never throws.
 * @param {string} code
 * @param {object} [opts]
 * @param {string} [opts.filename]  Used to infer TS/JSX plugins.
 * @param {boolean} [opts.typescript]
 * @param {boolean} [opts.jsx]
 * @returns {import('@babel/types').File | null}
 */
export function parseJs(code, opts = {}) {
  if (typeof code !== 'string' || code.length === 0) return null;

  const ext = opts.filename ? extname(opts.filename) : '';
  const wantTs = opts.typescript ?? TS_EXTS.has(ext);
  const wantJsx = opts.jsx ?? (JSX_EXTS.has(ext) || ext === '');

  const plugins = [];
  if (wantTs) plugins.push('typescript');
  if (wantJsx) plugins.push('jsx');
  plugins.push('decorators-legacy', 'classProperties', 'importAttributes', 'dynamicImport');

  try {
    return parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      errorRecovery: true,
      plugins,
    });
  } catch (err) {
    log.debug(`parseJs failed for ${opts.filename || '<inline>'}: ${err.message}`);
    return null;
  }
}

/**
 * Traverse an AST with a visitor object. Never throws.
 * @param {object} ast
 * @param {object} visitors
 * @returns {boolean} true if traversal completed without error
 */
export function walkAst(ast, visitors) {
  if (!ast) return false;
  try {
    traverse(ast, visitors);
    return true;
  } catch (err) {
    log.debug(`walkAst error: ${err.message}`);
    return false;
  }
}

function extname(file) {
  const i = file.lastIndexOf('.');
  return i >= 0 ? file.slice(i).toLowerCase() : '';
}

/**
 * Resolve the "name" of a callee/argument node for middleware matching.
 * Handles Identifier, MemberExpression, and CallExpression (returns the callee
 * name, e.g. rateLimit({...}) -> "rateLimit").
 * @param {object} node
 * @returns {string|null}
 */
export function nodeName(node) {
  if (!node) return null;
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'MemberExpression':
      // e.g. passport.authenticate -> "authenticate"; auth.required -> "required"
      return node.property?.name || node.property?.value || nodeName(node.object);
    case 'CallExpression':
      return nodeName(node.callee);
    case 'StringLiteral':
      return node.value;
    default:
      return null;
  }
}

/** Extract a string literal value from a node, or null. */
export function stringValue(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.quasis.length === 1) {
    return node.quasis[0].value.cooked;
  }
  return null;
}
