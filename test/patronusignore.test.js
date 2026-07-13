import { describe, it, expect } from 'vitest';
import { parseIgnoreLines } from '../src/config/patronusignore.js';
import { createFinding } from '../src/index.js';

function f(overrides) {
  return createFinding({
    tool: 't',
    ruleId: 'security/detect-object-injection',
    file: 'src/app.js',
    line: 10,
    category: 'injection',
    severity: 'medium',
    ...overrides,
  });
}

describe('parseIgnoreLines', () => {
  it('suppresses by path glob (basename anywhere)', () => {
    const s = parseIgnoreLines(['*.min.js']);
    expect(s.matchesPath('dist/vendor/app.min.js')).toBe(true);
    expect(s.matchesPath('src/app.js')).toBe(false);
  });

  it('suppresses everything under an anchored directory glob', () => {
    const s = parseIgnoreLines(['src/legacy/**']);
    expect(s.matchesPath('src/legacy/old.js')).toBe(true);
    expect(s.matchesPath('src/legacy/nested/deep.js')).toBe(true);
    expect(s.matchesPath('src/current/new.js')).toBe(false);
  });

  it('matches a directory and its contents when named without a wildcard', () => {
    const s = parseIgnoreLines(['src/legacy']);
    expect(s.matchesPath('src/legacy')).toBe(true);
    expect(s.matchesPath('src/legacy/old.js')).toBe(true);
  });

  it('supports directory patterns with trailing slash', () => {
    const s = parseIgnoreLines(['test/fixtures/']);
    expect(s.matchesPath('test/fixtures/sample/app.js')).toBe(true);
  });

  it('supports negation with last-match-wins', () => {
    const s = parseIgnoreLines(['src/**', '!src/keep.js']);
    expect(s.matchesPath('src/other.js')).toBe(true);
    expect(s.matchesPath('src/keep.js')).toBe(false);
  });

  it('suppresses by rule id (exact and glob)', () => {
    const s = parseIgnoreLines(['rule:security/detect-object-injection']);
    expect(s.matchesRule('security/detect-object-injection')).toBe(true);
    expect(s.matchesRule('security/detect-child-process')).toBe(false);

    const g = parseIgnoreLines(['rule:security/*']);
    expect(g.matchesRule('security/detect-child-process')).toBe(true);
  });

  it('suppresses by category', () => {
    const s = parseIgnoreLines(['category:injection']);
    expect(s.matchesCategory('injection')).toBe(true);
    expect(s.matchesCategory('secrets')).toBe(false);
  });

  it('ignores comments and blank lines', () => {
    const s = parseIgnoreLines(['# a comment', '', '   ', '*.log']);
    expect(s.pathPatterns).toHaveLength(1);
  });

  it('apply() partitions findings into kept and suppressed', () => {
    const s = parseIgnoreLines(['category:injection']);
    const { kept, suppressed } = s.apply([f(), f({ category: 'secrets', ruleId: 'r2' })]);
    expect(suppressed).toHaveLength(1);
    expect(kept).toHaveLength(1);
    expect(kept[0].category).toBe('secrets');
  });

  it('shouldSuppress combines all dimensions', () => {
    const s = parseIgnoreLines(['src/vendor/**', 'rule:x.y', 'category:secrets']);
    expect(s.shouldSuppress(f({ file: 'src/vendor/a.js' }))).toBe(true);
    expect(s.shouldSuppress(f({ ruleId: 'x.y', file: 'src/app.js', category: 'injection' }))).toBe(true);
    expect(s.shouldSuppress(f({ category: 'secrets', ruleId: 'z', file: 'src/app.js' }))).toBe(true);
    expect(s.shouldSuppress(f({ file: 'src/app.js', category: 'injection', ruleId: 'z' }))).toBe(false);
  });
});
