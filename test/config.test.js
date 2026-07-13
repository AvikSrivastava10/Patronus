import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, getDefaultConfig } from '../src/index.js';

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'patronus-cfg-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('loadConfig', () => {
  it('returns defaults when no config file exists', () => {
    const { config, path: p } = loadConfig(dir);
    expect(p).toBe(null);
    expect(config.failOn).toBe('critical');
    expect(config.toolTimeoutMs).toBe(120000);
    expect(Array.isArray(config.taint.sources)).toBe(true);
  });

  it('deep-merges user config over defaults', () => {
    fs.writeFileSync(
      path.join(dir, 'patronus.config.json'),
      JSON.stringify({ failOn: 'high', tools: { disabled: ['trivy'] } }),
    );
    const { config } = loadConfig(dir);
    expect(config.failOn).toBe('high');
    expect(config.tools.disabled).toEqual(['trivy']);
    // Untouched nested defaults survive the merge.
    expect(config.tools.enabled).toEqual([]);
    expect(config.checkers.authMiddlewareNames.length).toBeGreaterThan(0);
  });

  it('ignores an invalid failOn value but keeps other keys', () => {
    fs.writeFileSync(
      path.join(dir, 'patronus.config.json'),
      JSON.stringify({ failOn: 'banana', toolTimeoutMs: 5000 }),
    );
    const { config } = loadConfig(dir);
    expect(config.failOn).toBe('critical'); // reverted to default
    expect(config.toolTimeoutMs).toBe(5000);
  });

  it('falls back to defaults on malformed JSON without throwing', () => {
    fs.writeFileSync(path.join(dir, 'patronus.config.json'), '{ not valid json ');
    const { config } = loadConfig(dir);
    expect(config.failOn).toBe('critical');
  });
});

describe('getDefaultConfig', () => {
  it('is a fresh object each call', () => {
    const a = getDefaultConfig();
    const b = getDefaultConfig();
    a.failOn = 'low';
    expect(b.failOn).toBe('critical');
  });
});
