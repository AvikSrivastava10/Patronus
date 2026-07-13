import { describe, it, expect } from 'vitest';
import { createFinding } from '../src/index.js';
import { renderReport } from '../src/report/index.js';

function fakeScan(overrides = {}) {
  const findings = overrides.findings || [
    createFinding({ tool: 'semgrep', ruleId: 'patronus.jwt.none', file: 'src/auth.js', line: 12, category: 'insecure-jwt', severity: 'critical', confidence: 'high', aiCodegenRelevant: true, message: 'JWT alg none', remediation: 'verify signature' }),
    createFinding({ tool: 'eslint', ruleId: 'security/detect-child-process', file: 'src/run.js', line: 3, category: 'injection', severity: 'high', confidence: 'medium', message: 'child_process' }),
  ];
  return {
    root: '/proj',
    target: '.',
    detection: { stacks: { node: true, git: true, python: false, docker: false, terraform: false, kubernetes: false, java: false, dotnet: false }, languages: ['javascript'] },
    toolResults: [
      { id: 'semgrep', status: 'ok', findings: [findings[0]], durationMs: 1200 },
      { id: 'gitleaks', status: 'skipped', reason: 'gitleaks is not installed', installHint: 'brew install gitleaks', findings: [], durationMs: 5 },
      { id: 'trivy', status: 'error', reason: 'boom', findings: [], durationMs: 10 },
    ],
    findings,
    suppressedCount: 1,
    duplicatesRemoved: 2,
    summary: { total: findings.length, bySeverity: { critical: 1, high: 1, medium: 0, low: 0 }, byCategory: {}, aiCodegen: 1 },
    threshold: 'high',
    failed: true,
    durationMs: 1500,
    finishedAt: Date.now(),
    ...overrides,
  };
}

describe('json reporter', () => {
  it('produces valid JSON with the unified findings array and metadata', () => {
    const text = renderReport(fakeScan(), { format: 'json' });
    const obj = JSON.parse(text);
    expect(obj.tool).toBe('patronus');
    expect(obj.failed).toBe(true);
    expect(obj.failOn).toBe('high');
    expect(Array.isArray(obj.findings)).toBe(true);
    expect(obj.findings[0].category).toBe('insecure-jwt');
    expect(obj.detection.stacks).toContain('node');
    expect(obj.tools.find((t) => t.id === 'gitleaks').status).toBe('skipped');
  });

  it('strips raw payloads unless verbose', () => {
    const f = createFinding({ tool: 't', ruleId: 'r', file: 'a.js', line: 1, category: 'other', raw: { big: 'data' } });
    const scan = fakeScan({ findings: [f] });
    const lean = JSON.parse(renderReport(scan, { format: 'json', verbose: false }));
    expect('raw' in lean.findings[0]).toBe(false);
    const verbose = JSON.parse(renderReport(scan, { format: 'json', verbose: true }));
    expect(verbose.findings[0].raw).toEqual({ big: 'data' });
  });
});

describe('markdown reporter', () => {
  it('renders a PR-ready summary with severity table and verdict', () => {
    const md = renderReport(fakeScan(), { format: 'markdown' });
    expect(md).toMatch(/## .*Security Scan/);
    expect(md).toMatch(/Failed/);
    expect(md).toMatch(/\| Severity \| Count \|/);
    expect(md).toMatch(/insecure-jwt/);
    expect(md).toMatch(/ai-codegen/);
    expect(md).toMatch(/read-only/i);
  });

  it('escapes pipe characters in messages', () => {
    const f = createFinding({ tool: 't', ruleId: 'r', file: 'a.js', line: 1, category: 'other', message: 'a | b | c' });
    const md = renderReport(fakeScan({ findings: [f] }), { format: 'markdown' });
    expect(md).toMatch(/a \\\| b \\\| c/);
  });
});

describe('terminal reporter', () => {
  it('groups by severity and shows a verdict + analyzer status', () => {
    const text = renderReport(fakeScan(), { format: 'terminal' });
    expect(text).toMatch(/CRITICAL \(1\)/);
    expect(text).toMatch(/HIGH \(1\)/);
    expect(text).toMatch(/Failed/);
    expect(text).toMatch(/gitleaks skipped/);
  });

  it('shows a clean pass when there are no findings', () => {
    const scan = fakeScan({ findings: [], failed: false, summary: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {}, aiCodegen: 0 } });
    const text = renderReport(scan, { format: 'terminal' });
    expect(text).toMatch(/No findings/);
    expect(text).toMatch(/Passed/);
  });
});
