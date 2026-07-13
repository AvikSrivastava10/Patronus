import { describe, it, expect } from 'vitest';
import { selectAnalyzers, allSelectableIds } from '../src/scan/engine.js';
import { getDefaultConfig } from '../src/index.js';
import { TOOL } from '../src/constants.js';

function detection(tools, languages = ['javascript']) {
  return {
    enabledTools: new Set(tools),
    languages,
    stacks: { node: true },
  };
}

describe('selectAnalyzers', () => {
  it('defaults to the detected tool set', () => {
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit, TOOL.eslint]),
      config: getDefaultConfig(),
    });
    expect(toolSet.has(TOOL.semgrep)).toBe(true);
    expect(toolSet.has(TOOL.npmAudit)).toBe(true);
    expect(toolSet.has(TOOL.eslint)).toBe(true);
  });

  it('--only overrides detection and runs exactly the named known units', () => {
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit, TOOL.eslint]),
      config: getDefaultConfig(),
      only: [TOOL.semgrep],
    });
    expect([...toolSet]).toEqual([TOOL.semgrep]);
  });

  it('--skip removes tools from the set', () => {
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit, TOOL.eslint]),
      config: getDefaultConfig(),
      skip: [TOOL.eslint],
    });
    expect(toolSet.has(TOOL.eslint)).toBe(false);
    expect(toolSet.has(TOOL.semgrep)).toBe(true);
  });

  it('config.tools.disabled removes tools', () => {
    const config = getDefaultConfig();
    config.tools.disabled = [TOOL.npmAudit];
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit]),
      config,
    });
    expect(toolSet.has(TOOL.npmAudit)).toBe(false);
  });

  it('config.tools.enabled (when set) replaces the detected set', () => {
    const config = getDefaultConfig();
    config.tools.enabled = [TOOL.trivy];
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit]),
      config,
    });
    expect([...toolSet]).toEqual([TOOL.trivy]);
  });

  it('accepts comma-separated strings for only/skip', () => {
    const { toolSet } = selectAnalyzers({
      detection: detection([TOOL.semgrep, TOOL.npmAudit, TOOL.eslint]),
      config: getDefaultConfig(),
      only: `${TOOL.semgrep},${TOOL.eslint}`,
    });
    expect(toolSet.has(TOOL.semgrep)).toBe(true);
    expect(toolSet.has(TOOL.eslint)).toBe(true);
    expect(toolSet.has(TOOL.npmAudit)).toBe(false);
  });
});

describe('allSelectableIds', () => {
  it('includes the external tool ids', () => {
    const ids = allSelectableIds();
    expect(ids).toContain(TOOL.semgrep);
    expect(ids).toContain(TOOL.gitleaks);
    expect(ids).toContain(TOOL.eslint);
  });
});
