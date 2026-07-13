import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { enableHook, disableHook, hookStatus } from '../src/hooks/git-hook.js';

let dir;
let hookPath;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'patronus-hook-'));
  fs.mkdirSync(path.join(dir, '.git', 'hooks'), { recursive: true });
  hookPath = path.join(dir, '.git', 'hooks', 'pre-push');
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('enableHook / disableHook', () => {
  it('creates a hook that runs patronus scan with the threshold', () => {
    const res = enableHook(dir, { threshold: 'high' });
    expect(res.action).toBe('created');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content).toMatch(/#!\/bin\/sh/);
    expect(content).toMatch(/patronus scan --fail-on=high/);
    expect(hookStatus(dir).enabled).toBe(true);
  });

  it('is idempotent: re-enabling updates the managed block, not appends', () => {
    enableHook(dir, { threshold: 'critical' });
    const res = enableHook(dir, { threshold: 'medium' });
    expect(res.action).toBe('updated');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content).toMatch(/--fail-on=medium/);
    expect(content).not.toMatch(/--fail-on=critical/);
    // Only one managed block.
    expect(content.match(/patronus \(managed\)/g)).toHaveLength(2); // BEGIN + END markers
  });

  it('preserves pre-existing hook content when appending', () => {
    fs.writeFileSync(hookPath, '#!/bin/sh\necho "existing hook"\n');
    const res = enableHook(dir, { threshold: 'high' });
    expect(res.action).toBe('appended');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content).toMatch(/echo "existing hook"/);
    expect(content).toMatch(/patronus scan --fail-on=high/);
  });

  it('disable removes only our block and keeps other content', () => {
    fs.writeFileSync(hookPath, '#!/bin/sh\necho "existing hook"\n');
    enableHook(dir, { threshold: 'high' });
    const res = disableHook(dir);
    expect(res.action).toBe('removed');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content).toMatch(/echo "existing hook"/);
    expect(content).not.toMatch(/patronus \(managed\)/);
  });

  it('disable deletes the file when it contained only our block', () => {
    enableHook(dir, { threshold: 'high' });
    const res = disableHook(dir);
    expect(res.action).toBe('file-deleted');
    expect(fs.existsSync(hookPath)).toBe(false);
  });

  it('disable is a no-op when nothing is installed', () => {
    expect(disableHook(dir).action).toBe('not-found');
  });

  it('targets .husky/pre-push when husky is present', () => {
    fs.mkdirSync(path.join(dir, '.husky'));
    const res = enableHook(dir, { threshold: 'low' });
    expect(res.kind).toBe('husky');
    expect(res.path).toBe(path.join(dir, '.husky', 'pre-push'));
  });
});
