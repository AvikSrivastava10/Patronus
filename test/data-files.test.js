import { describe, it, expect } from 'vitest';
import { isDataFile, applyDataFileSecretPolicy, DATA_FILE_EXTENSIONS } from '../src/core/data-files.js';

describe('isDataFile', () => {
  it('recognizes data/dataset extensions (any separator, any case)', () => {
    expect(isDataFile('data/raw/kaggle/train.csv')).toBe(true);
    expect(isDataFile('D:/proj/data/raw/train.CSV')).toBe(true);
    expect(isDataFile('data\\big.parquet')).toBe(true);
    expect(isDataFile('features.npy')).toBe(true);
    expect(isDataFile('export.jsonl')).toBe(true);
    expect(isDataFile('db/app.sqlite3')).toBe(true);
  });

  it('does not treat source/config files as data files', () => {
    expect(isDataFile('src/app.ts')).toBe(false);
    expect(isDataFile('.env')).toBe(false);
    expect(isDataFile('config.json')).toBe(false);
    expect(isDataFile('fix-missing-user.sql')).toBe(false);
    expect(isDataFile('README.md')).toBe(false);
    expect(isDataFile('noext')).toBe(false);
    expect(isDataFile('')).toBe(false);
    expect(isDataFile(null)).toBe(false);
  });
});

describe('applyDataFileSecretPolicy', () => {
  const secret = (over = {}) => ({
    category: 'secrets',
    severity: 'high',
    confidence: 'medium',
    file: 'data/raw/train.csv',
    ...over,
  });

  it('demotes an unverified (medium-confidence) secret in a data file (default policy)', () => {
    const { findings, demoted, ignored } = applyDataFileSecretPolicy([secret()]);
    expect(demoted).toBe(1);
    expect(ignored).toBe(0);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].confidence).toBe('low');
    expect(findings[0].demotedReason).toBe('data-file');
  });

  it("policy 'ignore' drops the finding entirely", () => {
    const { findings, demoted, ignored } = applyDataFileSecretPolicy([secret()], 'ignore');
    expect(ignored).toBe(1);
    expect(demoted).toBe(0);
    expect(findings).toHaveLength(0);
  });

  it("policy 'keep' leaves the finding untouched", () => {
    const { findings, demoted, ignored } = applyDataFileSecretPolicy([secret()], 'keep');
    expect(demoted).toBe(0);
    expect(ignored).toBe(0);
    expect(findings[0].severity).toBe('high');
  });

  it('leaves high-confidence secrets alone even under demote/ignore (e.g. gitleaks rules)', () => {
    expect(applyDataFileSecretPolicy([secret({ confidence: 'high' })]).demoted).toBe(0);
    expect(applyDataFileSecretPolicy([secret({ confidence: 'high' })], 'ignore').ignored).toBe(0);
  });

  it('leaves verified/critical secrets alone even in a data file', () => {
    const { demoted, ignored } = applyDataFileSecretPolicy(
      [secret({ severity: 'critical', confidence: 'high' })],
      'ignore',
    );
    expect(demoted).toBe(0);
    expect(ignored).toBe(0);
  });

  it('does not touch secrets in source files or non-secret findings', () => {
    expect(applyDataFileSecretPolicy([secret({ file: 'src/config.ts' })]).demoted).toBe(0);
    expect(
      applyDataFileSecretPolicy([{ category: 'dependency-cve', severity: 'high', confidence: 'high', file: 'data.csv' }]).demoted,
    ).toBe(0);
  });

  it('handles empty input', () => {
    expect(applyDataFileSecretPolicy([]).findings).toEqual([]);
    expect(DATA_FILE_EXTENSIONS.has('.csv')).toBe(true);
  });
});
