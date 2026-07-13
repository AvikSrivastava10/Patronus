import { describe, it, expect } from 'vitest';
import { createFinding } from '../src/index.js';
import { deduplicate, sortFindings, summarize } from '../src/core/dedup.js';

describe('deduplicate', () => {
  it('merges findings with the same fingerprint, keeping highest confidence and recording agreement', () => {
    const findings = [
      createFinding({ tool: 'semgrep', ruleId: 'a', file: 'x.js', line: 10, category: 'injection', severity: 'medium', confidence: 'high' }),
      createFinding({ tool: 'eslint', ruleId: 'b', file: 'x.js', line: 10, category: 'injection', severity: 'high', confidence: 'low' }),
    ];
    const { findings: merged, duplicatesRemoved } = deduplicate(findings);
    expect(merged).toHaveLength(1);
    expect(duplicatesRemoved).toBe(1);
    // Highest-confidence representative is semgrep, but severity escalates to high.
    expect(merged[0].tool).toBe('semgrep');
    expect(merged[0].severity).toBe('high');
    expect(merged[0].agreedTools).toEqual(['eslint', 'semgrep']);
  });

  it('does not merge distinct dependency CVEs on package.json', () => {
    const findings = [
      createFinding({ tool: 'npm-audit', ruleId: 'CVE-1', file: 'package.json', category: 'dependency-cve', severity: 'high' }),
      createFinding({ tool: 'npm-audit', ruleId: 'CVE-2', file: 'package.json', category: 'dependency-cve', severity: 'high' }),
    ];
    const { findings: merged } = deduplicate(findings);
    expect(merged).toHaveLength(2);
  });

  it('merges references across duplicates', () => {
    const findings = [
      createFinding({ tool: 'a', ruleId: 'r', file: 'x.js', line: 1, category: 'secrets', references: ['u1'] }),
      createFinding({ tool: 'b', ruleId: 'r', file: 'x.js', line: 1, category: 'secrets', references: ['u2'] }),
    ];
    const { findings: merged } = deduplicate(findings);
    expect(merged[0].references.sort()).toEqual(['u1', 'u2']);
  });
});

describe('sortFindings', () => {
  it('orders by severity desc, then confidence desc, then file', () => {
    const findings = [
      createFinding({ tool: 't', ruleId: 'r', file: 'b.js', line: 1, category: 'other', severity: 'low', confidence: 'high' }),
      createFinding({ tool: 't', ruleId: 'r', file: 'a.js', line: 1, category: 'other', severity: 'critical', confidence: 'low' }),
      createFinding({ tool: 't', ruleId: 'r', file: 'a.js', line: 2, category: 'other', severity: 'critical', confidence: 'high' }),
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[0].confidence).toBe('high');
    expect(sorted[2].severity).toBe('low');
  });
});

describe('summarize', () => {
  it('counts by severity, category, and ai-codegen relevance', () => {
    const findings = [
      createFinding({ tool: 't', ruleId: 'r', file: 'a.js', line: 1, category: 'injection', severity: 'critical', aiCodegenRelevant: true }),
      createFinding({ tool: 't', ruleId: 'r', file: 'b.js', line: 1, category: 'secrets', severity: 'low' }),
    ];
    const s = summarize(findings);
    expect(s.total).toBe(2);
    expect(s.bySeverity.critical).toBe(1);
    expect(s.bySeverity.low).toBe(1);
    expect(s.byCategory.injection).toBe(1);
    expect(s.aiCodegen).toBe(1);
  });
});
