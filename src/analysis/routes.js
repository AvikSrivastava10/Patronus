/**
 * Shared project route/middleware analysis for the Phase 3 checkers.
 *
 * Walks the project's JS/TS and Python sources once and extracts:
 *   - route definitions with their guard (middleware / decorator) names,
 *   - project-wide guards (global Express middleware, global limiters),
 *   - security-header signals (helmet, CSP/HSTS, flask-talisman, etc.).
 *
 * The result is memoized on the scan ctx so all three checkers share a single
 * parse pass. Everything is read-only and degrades gracefully: unparseable
 * files are skipped and counted, never fatal.
 */

import fs from 'node:fs';
import path from 'node:path';
import { walk } from '../core/fswalk.js';
import { parseJs, walkAst, nodeName, stringValue } from './js-parse.js';
import { log } from '../core/logger.js';

const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'all', 'head', 'options']);
const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const PY_EXTS = ['.py'];
const ANALYSIS_KEY = Symbol.for('patronus.routeAnalysis');

/** @typedef {{ framework:string, method:string, path:string, file:string, line:number|null, guards:string[] }} Route */

function analyzeJsFile(code, rel) {
  const ast = parseJs(code, { filename: rel });
  if (!ast) return { parseError: true };

  const routes = [];
  const globalGuards = [];
  const imports = new Set();
  const flags = { helmet: false, csp: false, hsts: false, rateLimit: false };

  walkAst(ast, {
    ImportDeclaration(p) {
      if (p.node.source?.value) imports.add(p.node.source.value);
    },
    CallExpression(p) {
      const node = p.node;
      const callee = node.callee;
      const args = node.arguments || [];

      // require('x')
      if (callee.type === 'Identifier' && callee.name === 'require' && args[0]?.type === 'StringLiteral') {
        imports.add(args[0].value);
      }

      const calleeName = nodeName(callee);
      if (calleeName === 'helmet') flags.helmet = true;

      if (callee.type === 'MemberExpression') {
        const method = callee.property?.name;
        const line = node.loc?.start.line ?? null;

        if (HTTP_METHODS.has(method) && args.length >= 1) {
          const routePath = stringValue(args[0]);
          if (routePath != null) {
            const guards = args.slice(1).map(nodeName).filter(Boolean);
            routes.push({ framework: 'express', method: method.toUpperCase(), path: routePath, line, guards });
          }
        } else if (method === 'use') {
          // Global or path-mounted middleware. Treated as project-wide guards.
          const mountStr = stringValue(args[0]);
          const mwArgs = mountStr != null ? args.slice(1) : args;
          for (const a of mwArgs) {
            const n = nodeName(a);
            if (n) {
              globalGuards.push(n);
              if (n === 'helmet') flags.helmet = true;
            }
          }
        } else if (['setHeader', 'header', 'set'].includes(method)) {
          const headerName = stringValue(args[0]);
          if (headerName) {
            if (/content-security-policy/i.test(headerName)) flags.csp = true;
            if (/strict-transport-security/i.test(headerName)) flags.hsts = true;
          }
        }
      }
    },
  });

  for (const imp of imports) {
    if (imp === 'helmet') flags.helmet = true;
    if (/(rate-limit|slow-down|rate-limiter-flexible)/i.test(imp)) flags.rateLimit = true;
  }

  return { parseError: false, routes, globalGuards, imports: [...imports], flags };
}

/** Regex-based Flask/Django route + decorator extraction (heuristic). */
function analyzePyFile(code) {
  const lines = code.split(/\r?\n/);
  const routes = [];
  const imports = new Set();
  const flags = { helmet: false, csp: false, hsts: false, rateLimit: false };

  // Imports + library signals.
  for (const line of lines) {
    const im = line.match(/^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/);
    if (im) imports.add((im[1] || im[2] || '').split('.')[0]);
    if (/talisman|flask_talisman|secure\b/i.test(line)) {
      flags.csp = true;
      flags.hsts = true;
      flags.helmet = true; // treat a headers library as "headers configured"
    }
    if (/flask_limiter|Limiter\s*\(|@\w*limiter\.limit/i.test(line)) flags.rateLimit = true;
    if (/['"]Content-Security-Policy['"]/i.test(line)) flags.csp = true;
    if (/['"]Strict-Transport-Security['"]/i.test(line)) flags.hsts = true;
  }

  // Walk decorator stacks -> route + guards.
  let decoratorStack = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('@')) {
      decoratorStack.push({ text: line, line: i + 1 });
      continue;
    }
    if (/^(async\s+)?def\s+/.test(line) && decoratorStack.length) {
      const routeDec = decoratorStack.find((d) =>
        /@\s*[\w.]+\.(route|get|post|put|delete|patch)\s*\(/.test(d.text),
      );
      if (routeDec) {
        const pathMatch = routeDec.text.match(/\(\s*['"]([^'"]+)['"]/);
        const methodMatch = routeDec.text.match(/\.(route|get|post|put|delete|patch)\s*\(/);
        const guards = decoratorStack
          .filter((d) => d !== routeDec)
          .map((d) => {
            const m = d.text.match(/@\s*([\w.]+)/);
            if (!m) return null;
            const parts = m[1].split('.');
            return parts[parts.length - 1];
          })
          .filter(Boolean);
        routes.push({
          framework: 'flask',
          method: (methodMatch?.[1] === 'route' ? 'ANY' : methodMatch?.[1]?.toUpperCase()) || 'ANY',
          path: pathMatch ? pathMatch[1] : '',
          line: routeDec.line,
          guards,
        });
      }
      decoratorStack = [];
    } else if (line && !line.startsWith('#')) {
      decoratorStack = [];
    }
  }

  return { parseError: false, routes, globalGuards: [], imports: [...imports], flags };
}

/**
 * Analyze the whole project once (memoized on ctx).
 * @param {object} ctx  Scan context { root, config, ... }
 * @returns {{
 *   routes: Route[], globalGuards: string[],
 *   helmetUsed: boolean, cspConfigured: boolean, hstsConfigured: boolean,
 *   rateLimiterConfigured: boolean, webAppDetected: boolean,
 *   filesAnalyzed: number, parseErrors: number
 * }}
 */
export function analyzeProject(ctx) {
  if (ctx && ctx[ANALYSIS_KEY]) return ctx[ANALYSIS_KEY];

  const root = ctx.root;
  const files = walk(root, { extensions: [...JS_EXTS, ...PY_EXTS], maxFiles: 5000 });

  const routes = [];
  const globalGuards = new Set();
  let helmetUsed = false;
  let cspConfigured = false;
  let hstsConfigured = false;
  let rateLimiterConfigured = false;
  let webAppDetected = false;
  let filesAnalyzed = 0;
  let parseErrors = 0;

  for (const abs of files) {
    let code;
    try {
      code = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const rel = path.relative(root, abs).replace(/\\/g, '/');
    const isPy = abs.toLowerCase().endsWith('.py');

    let result;
    try {
      result = isPy ? analyzePyFile(code) : analyzeJsFile(code, rel);
    } catch (err) {
      log.debug(`route analysis failed for ${rel}: ${err.message}`);
      parseErrors += 1;
      continue;
    }
    if (result.parseError) {
      parseErrors += 1;
      continue;
    }
    filesAnalyzed += 1;

    for (const r of result.routes) {
      routes.push({ ...r, file: rel });
    }
    for (const g of result.globalGuards) globalGuards.add(g);
    if (result.flags.helmet) helmetUsed = true;
    if (result.flags.csp) cspConfigured = true;
    if (result.flags.hsts) hstsConfigured = true;
    if (result.flags.rateLimit) rateLimiterConfigured = true;
    if (
      result.routes.length > 0 ||
      result.imports.some((i) => /^(express|fastify|koa|flask|django|@hapi)/i.test(i))
    ) {
      webAppDetected = true;
    }
  }

  const analysis = {
    routes,
    globalGuards: [...globalGuards],
    helmetUsed,
    cspConfigured,
    hstsConfigured,
    rateLimiterConfigured,
    webAppDetected,
    filesAnalyzed,
    parseErrors,
  };

  if (ctx) {
    try {
      ctx[ANALYSIS_KEY] = analysis;
    } catch {
      /* ctx may be frozen; ignore */
    }
  }
  return analysis;
}

export { HTTP_METHODS };
