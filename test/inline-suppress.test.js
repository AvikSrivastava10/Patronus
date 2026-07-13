import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createFinding } from '../src/index.js';
import { applyInlineSuppressions } from '../src/config/inline-suppress.js';

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-inline-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(name, content) {
  fs.writeFileSync(path.join(dir, name), content, 'utf8');
}

function f(file, line, overrides = {}) {
  return createFinding({
    tool: 'clipeus-taint',
    ruleId: 'clipeus.taint.injection',
    category: 'injection',
    file,
    line,
    message: 'taint',
    severity: 'high',
    ...overrides,
  });
}

describe('applyInlineSuppressions', () => {
  it('suppresses a finding on a clipeus-disable-line', () => {
    write('a.js', ['const x = 1;', 'evil(x); // clipeus-disable-line', 'ok();'].join('\n'));
    const { kept, suppressed } = applyInlineSuppressions([f('a.js', 2)], dir);
    expect(suppressed).toHaveLength(1);
    expect(kept).toHaveLength(0);
  });

  it('suppresses a finding on the line after clipeus-disable-next-line', () => {
    write('b.js', ['// clipeus-disable-next-line', 'evil();'].join('\n'));
    const { kept } = applyInlineSuppressions([f('b.js', 2)], dir);
    expect(kept).toHaveLength(0);
  });

  it('honors rule/category ids on the directive', () => {
    write('c.js', ['evil(); // clipeus-disable-line injection', 'evil2(); // clipeus-disable-line secrets'].join('\n'));
    // line 1: category injection matches -> suppressed
    // line 2: only "secrets" listed, our finding is injection -> kept
    const res = applyInlineSuppressions([f('c.js', 1), f('c.js', 2)], dir);
    expect(res.suppressed).toHaveLength(1);
    expect(res.kept).toHaveLength(1);
    expect(res.kept[0].line).toBe(2);
  });

  it('suppresses all findings in a file with clipeus-disable-file', () => {
    write('d.js', ['/* clipeus-disable-file */', 'a();', 'b();'].join('\n'));
    const { kept } = applyInlineSuppressions([f('d.js', 2), f('d.js', 3)], dir);
    expect(kept).toHaveLength(0);
  });

  it('keeps findings with no matching directive', () => {
    write('e.js', ['a();', 'b();'].join('\n'));
    const { kept, suppressed } = applyInlineSuppressions([f('e.js', 1)], dir);
    expect(kept).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('supports the # comment style (Python)', () => {
    write('f.py', ['os.system(x)  # clipeus-disable-line'].join('\n'));
    const { kept } = applyInlineSuppressions([f('f.py', 1)], dir);
    expect(kept).toHaveLength(0);
  });
});
