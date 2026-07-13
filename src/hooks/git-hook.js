/**
 * Git pre-push hook management.
 *
 * `enable` installs a pre-push hook that runs `patronus scan --fail-on=<threshold>`
 * and blocks the push on a non-zero exit. `disable` removes it cleanly.
 *
 * Existing hook content is always preserved: our lines live between managed
 * markers, so we only ever add/remove our own block and never clobber other
 * hooks. If the project uses husky, we target `.husky/pre-push` instead.
 */

import fs from 'node:fs';
import path from 'node:path';

const BEGIN = '# >>> patronus (managed) >>>';
const END = '# <<< patronus (managed) <<<';

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Resolve the hooks directory, accounting for husky and `.git` file worktrees. */
export function resolveHookTarget(root) {
  const huskyDir = path.join(root, '.husky');
  if (fs.existsSync(huskyDir) && fs.statSync(huskyDir).isDirectory()) {
    return { path: path.join(huskyDir, 'pre-push'), kind: 'husky' };
  }

  const dotGit = path.join(root, '.git');
  let gitDir = dotGit;
  try {
    const st = fs.statSync(dotGit);
    if (st.isFile()) {
      // Worktree/submodule: ".git" is a file with "gitdir: <path>".
      const content = fs.readFileSync(dotGit, 'utf8');
      const m = content.match(/gitdir:\s*(.+)\s*/);
      if (m) {
        gitDir = path.isAbsolute(m[1]) ? m[1] : path.resolve(root, m[1]);
      }
    }
  } catch {
    /* fall through with default */
  }
  return { path: path.join(gitDir, 'hooks', 'pre-push'), kind: 'git' };
}

function buildBlock(threshold) {
  return [
    BEGIN,
    '# Added by `patronus hook enable`. Remove with `patronus hook disable`.',
    `npx patronus scan --fail-on=${threshold} || {`,
    `  echo "patronus: push blocked by findings at or above ${threshold} severity." >&2`,
    '  exit 1',
    '}',
    END,
  ].join('\n');
}

/**
 * Install / update the pre-push hook.
 * @param {string} root
 * @param {object} [opts] { threshold }
 * @returns {{ path:string, kind:string, action:'created'|'updated'|'appended' }}
 */
export function enableHook(root, opts = {}) {
  const threshold = opts.threshold || 'critical';
  const target = resolveHookTarget(root);
  const block = buildBlock(threshold);

  fs.mkdirSync(path.dirname(target.path), { recursive: true });

  let action;
  if (fs.existsSync(target.path)) {
    const existing = fs.readFileSync(target.path, 'utf8');
    if (existing.includes(BEGIN)) {
      // Replace the existing managed block (updates threshold).
      const blockRegex = new RegExp(`${escapeRegex(BEGIN)}[\\s\\S]*?${escapeRegex(END)}`);
      const updated = existing.replace(blockRegex, block);
      fs.writeFileSync(target.path, updated, 'utf8');
      action = 'updated';
    } else {
      // Preserve existing hook content; append our block.
      const sep = existing.endsWith('\n') ? '\n' : '\n\n';
      fs.writeFileSync(target.path, `${existing}${sep}${block}\n`, 'utf8');
      action = 'appended';
    }
  } else {
    const header = target.kind === 'husky' ? '' : '#!/bin/sh\n\n';
    fs.writeFileSync(target.path, `${header}${block}\n`, 'utf8');
    action = 'created';
  }

  try {
    fs.chmodSync(target.path, 0o755);
  } catch {
    /* chmod is a no-op / not permitted on some platforms; harmless */
  }

  return { path: target.path, kind: target.kind, action };
}

/**
 * Remove the managed pre-push block. Preserves any other hook content; deletes
 * the file only if it contained nothing but our block (+ shebang).
 * @param {string} root
 * @returns {{ path:string, action:'removed'|'file-deleted'|'not-found'|'not-present' }}
 */
export function disableHook(root) {
  const target = resolveHookTarget(root);
  if (!fs.existsSync(target.path)) {
    return { path: target.path, action: 'not-found' };
  }

  const existing = fs.readFileSync(target.path, 'utf8');
  if (!existing.includes(BEGIN)) {
    return { path: target.path, action: 'not-present' };
  }

  const blockRegex = new RegExp(`\\n?${escapeRegex(BEGIN)}[\\s\\S]*?${escapeRegex(END)}\\n?`, 'g');
  const remaining = existing.replace(blockRegex, '\n');
  const stripped = remaining.replace(/^#!.*\n?/, '').trim();

  if (stripped.length === 0) {
    // The file only contained our block (and maybe a shebang): remove it.
    fs.rmSync(target.path, { force: true });
    return { path: target.path, action: 'file-deleted' };
  }

  fs.writeFileSync(target.path, `${remaining.trimEnd()}\n`, 'utf8');
  return { path: target.path, action: 'removed' };
}

/** Report whether the managed hook is currently installed. */
export function hookStatus(root) {
  const target = resolveHookTarget(root);
  if (!fs.existsSync(target.path)) return { enabled: false, ...target };
  try {
    const content = fs.readFileSync(target.path, 'utf8');
    return { enabled: content.includes(BEGIN), ...target };
  } catch {
    return { enabled: false, ...target };
  }
}
