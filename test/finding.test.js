import { describe, it, expect } from 'vitest';
import {
  createFinding,
  normalizePath,
  compareSeverity,
  meetsSeverityThreshold,
  fingerprintFinding,
} from '../src/index.js';

describe('createFinding', () => {
  it('coerces severity/confidence/category and normalizes path + line', () => {
    const f = createFinding({
      tool: 'semgrep',
      ruleId: 'r1',
      severity: 'HIGH',
      category: 'insecure-jwt',
      file: '.\\src\\auth\\jwt.js',
      line: '42',
      message: '  bad jwt  ',
      confidence: 'Medium',
    });
    expect(f.severity).toBe('high');
    expect(f.confidence).toBe('medium');
    expect(f.category).toBe('insecure-jwt');
    expect(f.file).toBe('src/auth/jwt.js');
    expect(f.line).toBe(42);
    expect(f.message).toBe('bad jwt');
    expect(f.aiCodegenRelevant).toBe(false);
  });

  it('falls back to safe defaults for invalid enum values', () => {
    const f = createFinding({ severity: 'nope', confidence: 'nope', category: 'nope' });
    expect(f.severity).toBe('medium');
    expect(f.confidence).toBe('high');
    expect(f.category).toBe('other');
    expect(f.tool).toBe('unknown');
    expect(f.line).toBe(null);
    expect(f.message).toMatch(/no message/i);
  });

  it('keeps optional fields only when provided', () => {
    const f = createFinding({ message: 'x' });
    expect('remediation' in f).toBe(false);
    expect('references' in f).toBe(false);
    const g = createFinding({ message: 'x', remediation: 'do y', references: ['a', 'a', 'b'] });
    expect(g.remediation).toBe('do y');
    expect(g.references).toEqual(['a', 'a', 'b']);
  });
});

describe('normalizePath', () => {
  it('converts backslashes and strips leading ./', () => {
    expect(normalizePath('.\\a\\b.js')).toBe('a/b.js');
    expect(normalizePath('a/b')).toBe('a/b');
    expect(normalizePath(null)).toBe('');
  });
});

describe('severity helpers', () => {
  it('compareSeverity orders correctly', () => {
    expect(compareSeverity('critical', 'low')).toBeGreaterThan(0);
    expect(compareSeverity('low', 'high')).toBeLessThan(0);
    expect(compareSeverity('medium', 'medium')).toBe(0);
  });

  it('meetsSeverityThreshold is inclusive of the threshold', () => {
    expect(meetsSeverityThreshold('high', 'high')).toBe(true);
    expect(meetsSeverityThreshold('critical', 'high')).toBe(true);
    expect(meetsSeverityThreshold('medium', 'high')).toBe(false);
    expect(meetsSeverityThreshold('low', 'critical')).toBe(false);
  });
});

describe('fingerprintFinding', () => {
  it('uses file+line+category for line-scoped findings (merges across tools)', () => {
    const a = createFinding({ tool: 'semgrep', ruleId: 'x', file: 'a.js', line: 5, category: 'injection' });
    const b = createFinding({ tool: 'eslint', ruleId: 'y', file: 'a.js', line: 5, category: 'injection' });
    expect(fingerprintFinding(a)).toBe(fingerprintFinding(b));
  });

  it('includes ruleId for line-less findings (keeps distinct CVEs separate)', () => {
    const a = createFinding({ tool: 'npm-audit', ruleId: 'CVE-1', file: 'package.json', category: 'dependency-cve' });
    const b = createFinding({ tool: 'npm-audit', ruleId: 'CVE-2', file: 'package.json', category: 'dependency-cve' });
    expect(fingerprintFinding(a)).not.toBe(fingerprintFinding(b));
  });
});
