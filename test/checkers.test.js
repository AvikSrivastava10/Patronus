import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDefaultConfig } from '../src/index.js';
import { analyzeProject } from '../src/analysis/routes.js';
import authChecker from '../src/checkers/missing-auth.js';
import rateLimitChecker from '../src/checkers/rate-limiting.js';
import headersChecker from '../src/checkers/security-headers.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

function ctxFor(name, languages = ['javascript']) {
  return { root: fixture(name), config: getDefaultConfig(), detection: { languages } };
}

describe('analyzeProject (route extraction)', () => {
  it('extracts Express routes with their guards', () => {
    const a = analyzeProject(ctxFor('insecure-express'));
    const login = a.routes.find((r) => r.path === '/login');
    const adminUsers = a.routes.find((r) => r.path === '/admin/users');
    expect(login).toBeTruthy();
    expect(login.method).toBe('POST');
    expect(adminUsers.guards).toContain('requireAuth');
    expect(a.helmetUsed).toBe(false);
    expect(a.webAppDetected).toBe(true);
  });

  it('detects helmet + rate limiter in a hardened app', () => {
    const a = analyzeProject(ctxFor('secure-express'));
    expect(a.helmetUsed).toBe(true);
    expect(a.rateLimiterConfigured).toBe(true);
  });

  it('extracts Flask routes and decorators', () => {
    const a = analyzeProject(ctxFor('flask-app', ['python']));
    const del = a.routes.find((r) => r.path === '/admin/delete');
    const users = a.routes.find((r) => r.path === '/admin/users');
    expect(del).toBeTruthy();
    expect(users.guards).toContain('login_required');
  });
});

describe('missing-auth checker', () => {
  it('flags a sensitive Express route with no auth guard', async () => {
    const { findings } = await authChecker.run(ctxFor('insecure-express'));
    const paths = findings.map((f) => f.message);
    expect(findings.length).toBe(1);
    expect(paths[0]).toMatch(/\/admin\/delete-user/);
    expect(findings[0].category).toBe('missing-auth');
    expect(findings[0].confidence).toBe('medium');
  });

  it('does not flag a guarded route', async () => {
    const { findings } = await authChecker.run(ctxFor('insecure-express'));
    expect(findings.some((f) => f.message.includes('/admin/users'))).toBe(false);
  });

  it('produces no findings for a hardened app', async () => {
    const { findings } = await authChecker.run(ctxFor('secure-express'));
    expect(findings).toHaveLength(0);
  });

  it('flags a sensitive Flask route without a decorator guard', async () => {
    const { findings } = await authChecker.run(ctxFor('flask-app', ['python']));
    expect(findings.some((f) => f.message.includes('/admin/delete'))).toBe(true);
    expect(findings.some((f) => f.message.includes('/admin/users'))).toBe(false);
  });
});

describe('rate-limiting checker', () => {
  it('flags an auth route when no limiter exists anywhere', async () => {
    const { findings } = await rateLimitChecker.run(ctxFor('insecure-express'));
    expect(findings.some((f) => f.message.includes('/login'))).toBe(true);
    expect(findings[0].category).toBe('missing-rate-limit');
  });

  it('produces no findings when a rate limiter is configured', async () => {
    const { findings } = await rateLimitChecker.run(ctxFor('secure-express'));
    expect(findings).toHaveLength(0);
  });
});

describe('security-headers checker', () => {
  it('flags a web app with no helmet/CSP/HSTS', async () => {
    const { findings } = await headersChecker.run(ctxFor('insecure-express'));
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('missing-security-headers');
  });

  it('produces no findings when helmet is used', async () => {
    const { findings } = await headersChecker.run(ctxFor('secure-express'));
    expect(findings).toHaveLength(0);
  });
});
