import { describe, it, expect } from 'vitest';
import { createFinding } from '../src/index.js';
import { render } from '../src/report/sarif.js';

function fakeScan(findings) {
  return {
    root: '/proj',
    target: '.',
    detection: { stacks: { node: true }, languages: ['javascript'] },
    toolResults: [],
    findings,
    summary: { total: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {}, aiCodegen: 0 },
    threshold: 'high',
    failed: false,
    durationMs: 100,
    finishedAt: Date.now(),
  };
}

describe('sarif reporter', () => {
  const findings = [
    createFinding({ tool: 'semgrep', ruleId: 'clipeus-jwt-algorithm-none', category: 'insecure-jwt', file: 'src/a.js', line: 12, severity: 'critical', confidence: 'high', message: 'jwt none', remediation: 'verify' }),
    createFinding({ tool: 'eslint', ruleId: 'security/detect-child-process', category: 'injection', file: 'src/b.js', line: 3, severity: 'medium', confidence: 'medium', message: 'child_process' }),
    createFinding({ tool: 'clipeus-taint', ruleId: 'clipeus.taint.injection', category: 'injection', file: 'src/c.js', line: 5, severity: 'low', confidence: 'low', message: 'taint' }),
  ];
  const sarif = JSON.parse(render(fakeScan(findings)));

  it('is a valid SARIF 2.1.0 document', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif-2\.1\.0/);
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('Clipeus');
  });

  it('maps severities to SARIF levels', () => {
    const results = sarif.runs[0].results;
    expect(results[0].level).toBe('error'); // critical
    expect(results[1].level).toBe('warning'); // medium
    expect(results[2].level).toBe('note'); // low
  });

  it('emits rules with security-severity and results with locations + fingerprints', () => {
    const driver = sarif.runs[0].tool.driver;
    expect(driver.rules.length).toBe(3);
    expect(driver.rules[0].properties['security-severity']).toBe('9.5');
    const r0 = sarif.runs[0].results[0];
    expect(r0.locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.js');
    expect(r0.locations[0].physicalLocation.region.startLine).toBe(12);
    expect(typeof r0.partialFingerprints['clipeus/v1']).toBe('string');
    expect(r0.message.text).toMatch(/Remediation:/);
  });

  it('reuses a single rule entry for repeated rule ids', () => {
    const many = [findings[1], findings[1]];
    const doc = JSON.parse(render(fakeScan(many)));
    expect(doc.runs[0].tool.driver.rules).toHaveLength(1);
    expect(doc.runs[0].results).toHaveLength(2);
  });
});
