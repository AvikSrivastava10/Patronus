import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const taintJs = path.join(__dirname, 'fixtures', 'taint-js');

let tmp;
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-pipeline-'));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('runScan post-processing pipeline', () => {
  it('reports taint findings across confidences', async () => {
    const scan = await runScan({ path: taintJs, only: 'clipeus-taint' });
    expect(scan.findings.length).toBe(3);
    expect(scan.findings.filter((f) => f.confidence === 'medium').length).toBe(1);
    expect(scan.findings.filter((f) => f.confidence === 'low').length).toBe(2);
  });

  it('--min-confidence hides lower-confidence findings', async () => {
    const scan = await runScan({ path: taintJs, only: 'clipeus-taint', minConfidence: 'medium' });
    expect(scan.findings.every((f) => f.confidence === 'medium' || f.confidence === 'high')).toBe(true);
    expect(scan.findings.length).toBe(1);
    expect(scan.minConfidenceFiltered).toBe(2);
  });

  it('baseline records current state then reports zero new findings', async () => {
    const baselineFile = path.join(tmp, 'baseline.json');

    const rec = await runScan({ path: taintJs, only: 'clipeus-taint', baselineFile, updateBaseline: true });
    expect(rec.baseline.updated).toBe(true);
    expect(rec.baseline.recorded).toBe(3);
    expect(rec.failed).toBe(false);
    expect(fs.existsSync(baselineFile)).toBe(true);

    const cmp = await runScan({ path: taintJs, only: 'clipeus-taint', baselineFile, failOn: 'low' });
    expect(cmp.baseline.new).toBe(0);
    expect(cmp.baseline.known).toBe(3);
    expect(cmp.findings).toHaveLength(0);
    expect(cmp.failed).toBe(false);
  });

  it('a missing baseline file treats all findings as new', async () => {
    const scan = await runScan({ path: taintJs, only: 'clipeus-taint', baselineFile: path.join(tmp, 'nope.json') });
    expect(scan.baseline.missing).toBe(true);
    expect(scan.baseline.new).toBe(3);
  });
});
