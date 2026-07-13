import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createFinding } from '../src/index.js';
import {
  baselineFingerprint,
  loadBaseline,
  writeBaseline,
  partitionByBaseline,
} from '../src/config/baseline.js';

function f(overrides) {
  return createFinding({
    tool: 'semgrep',
    ruleId: 'clipeus-jwt-algorithm-none',
    category: 'insecure-jwt',
    file: 'src/auth.js',
    line: 12,
    message: 'JWT alg none',
    severity: 'high',
    ...overrides,
  });
}

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-baseline-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('baselineFingerprint', () => {
  it('is stable and line-independent', () => {
    expect(baselineFingerprint(f())).toBe(baselineFingerprint(f({ line: 99 })));
  });
  it('differs when tool/rule/file/message changes', () => {
    const base = baselineFingerprint(f());
    expect(baselineFingerprint(f({ ruleId: 'other' }))).not.toBe(base);
    expect(baselineFingerprint(f({ file: 'src/other.js' }))).not.toBe(base);
    expect(baselineFingerprint(f({ message: 'different' }))).not.toBe(base);
  });
});

describe('write/load baseline', () => {
  it('round-trips fingerprints', () => {
    const file = path.join(dir, 'baseline.json');
    const count = writeBaseline(file, [f(), f({ ruleId: 'r2' })]);
    expect(count).toBe(2);
    const loaded = loadBaseline(file);
    expect(loaded.fingerprints.has(baselineFingerprint(f()))).toBe(true);
    expect(loaded.fingerprints.size).toBe(2);
  });
  it('returns null for a missing baseline file', () => {
    expect(loadBaseline(path.join(dir, 'nope.json'))).toBe(null);
  });
  it('deduplicates identical findings when writing', () => {
    const file = path.join(dir, 'b.json');
    expect(writeBaseline(file, [f(), f({ line: 50 })])).toBe(1);
  });
});

describe('partitionByBaseline', () => {
  it('splits into new and known', () => {
    const known = f();
    const set = new Set([baselineFingerprint(known)]);
    const { newFindings, knownFindings } = partitionByBaseline(
      [known, f({ ruleId: 'new-rule', message: 'new one' })],
      set,
    );
    expect(knownFindings).toHaveLength(1);
    expect(newFindings).toHaveLength(1);
    expect(newFindings[0].ruleId).toBe('new-rule');
  });
});
