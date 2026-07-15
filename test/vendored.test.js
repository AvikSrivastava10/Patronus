import { describe, it, expect } from 'vitest';
import { isVendoredPath, filterVendoredFindings, VENDORED_DIRS } from '../src/core/vendored.js';

describe('isVendoredPath', () => {
  it('flags paths inside third-party/cache dirs (posix and windows separators)', () => {
    expect(isVendoredPath('node_modules/@types/node/http.d.ts')).toBe(true);
    expect(isVendoredPath('D:/work/app/node_modules/pkg/index.js')).toBe(true);
    expect(isVendoredPath('D:\\work\\app\\node_modules\\pkg\\index.js')).toBe(true);
    expect(isVendoredPath('backend/.venv/Lib/site-packages/foo.py')).toBe(true);
    expect(isVendoredPath('vendor/bundle/x.rb')).toBe(true);
  });

  it('does NOT flag the user\'s own source or ambiguous dirs', () => {
    expect(isVendoredPath('src/components/App.tsx')).toBe(false);
    expect(isVendoredPath('package.json')).toBe(false);
    expect(isVendoredPath('.env')).toBe(false);
    expect(isVendoredPath('fix-missing-user.sql')).toBe(false);
    // Ambiguous dirs are deliberately NOT filtered (may hold real user secrets).
    expect(isVendoredPath('bin/deploy.sh')).toBe(false);
    expect(isVendoredPath('env/config.py')).toBe(false);
    expect(isVendoredPath('dist/bundle.js')).toBe(false);
    expect(isVendoredPath('build/output.js')).toBe(false);
  });

  it('handles empty/nullish input safely', () => {
    expect(isVendoredPath('')).toBe(false);
    expect(isVendoredPath(null)).toBe(false);
    expect(isVendoredPath(undefined)).toBe(false);
  });

  it('does not match a substring that merely contains a vendored name', () => {
    // "node_modules_backup" is a different directory, not node_modules.
    expect(isVendoredPath('node_modules_backup/file.js')).toBe(false);
    expect(isVendoredPath('my-vendor/file.js')).toBe(false);
  });
});

describe('filterVendoredFindings', () => {
  it('partitions findings into kept and filtered', () => {
    const findings = [
      { file: 'src/app.ts', ruleId: 'a' },
      { file: 'node_modules/pkg/index.js', ruleId: 'b' },
      { file: 'package.json', ruleId: 'c' },
      { file: 'D:/proj/node_modules/@types/node/url.d.ts', ruleId: 'd' },
    ];
    const { kept, filtered } = filterVendoredFindings(findings);
    expect(kept.map((f) => f.ruleId)).toEqual(['a', 'c']);
    expect(filtered.map((f) => f.ruleId)).toEqual(['b', 'd']);
  });

  it('handles findings with no file and empty input', () => {
    expect(filterVendoredFindings([]).kept).toEqual([]);
    const { kept } = filterVendoredFindings([{ ruleId: 'x' }]);
    expect(kept).toHaveLength(1);
  });

  it('exposes a non-empty vendored dir set including node_modules', () => {
    expect(VENDORED_DIRS.has('node_modules')).toBe(true);
    expect(VENDORED_DIRS.has('.venv')).toBe(true);
    // ambiguous dirs must not be in the set
    expect(VENDORED_DIRS.has('bin')).toBe(false);
    expect(VENDORED_DIRS.has('dist')).toBe(false);
  });
});
