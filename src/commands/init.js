/**
 * `clipeus init` command.
 *
 * First-run setup:
 *   1. Detect the project's stack.
 *   2. Check which underlying tools are installed; offer to install any missing
 *      ones via their own package manager (interactive only — never installs
 *      software without explicit confirmation).
 *   3. Offer to install the pre-push scan hook.
 *   4. Write a default clipeus.config.json.
 *   5. Add Clipeus's generated artifacts to the project's .gitignore.
 *
 * Read-only w.r.t. source code: the only files this may write are Clipeus's
 * own config, its .gitignore entries, and (with consent) the git hook.
 */

import fs from 'node:fs';
import path from 'node:path';
import { ALL_ADAPTERS, getAdapter } from '../adapters/index.js';
import { commandExists, runTool } from '../core/runner.js';
import { installHint } from '../adapters/base.js';
import { detectProject } from '../detectors/detect.js';
import { resolveToolInEnvironments } from '../detectors/environments.js';
import { loadConfig } from '../config/config.js';
import { ensureGitignore } from '../config/gitignore.js';
import { downloadTool, DOWNLOAD_DESCRIPTORS } from '../core/binary-download.js';
import { enableHook } from '../hooks/git-hook.js';
import { confirm, isInteractive } from '../core/prompt.js';
import { log, spinner, chalk } from '../core/logger.js';
import { SEVERITY } from '../constants.js';
import { PRODUCT } from '../version.js';

const CONFIG_FILE = 'clipeus.config.json';

function curatedConfig() {
  return {
    failOn: SEVERITY.critical,
    toolTimeoutMs: 120000,
    tools: { enabled: [], disabled: [] },
    checkers: {
      sensitivePathKeywords: [
        'admin', 'user', 'account', 'payment', 'billing', 'checkout',
        'settings', 'internal', 'dashboard',
      ],
      sensitiveRoutePatterns: [
        'login', 'signup', 'register', 'password', 'reset', 'otp', 'verify', 'token',
      ],
    },
    // 'demote' (default) | 'ignore' | 'keep' — how to treat likely-false-positive
    // secret hits inside data files (CSV/Parquet/datasets).
    secrets: { dataFiles: 'demote' },
    ignore: [],
  };
}

/** Determine runnable install candidates for a tool, in priority order. */
async function candidateInstallers(install = {}, opts = {}) {
  const out = [];
  if (install.pip) {
    const pkg = install.pip.replace(/^pip3?\s+install\s+/i, '').trim().split(/\s+/)[0];
    if (pkg) {
      // Prefer the project's virtualenv so the install lands where the project
      // (and later Clipeus runs) actually look for it.
      const venv = (opts.pythonEnvs || [])[0];
      if (venv?.python) {
        out.push({ command: venv.python, args: ['-m', 'pip', 'install', pkg], display: `${venv.source}: pip install ${pkg}` });
      }
      if (await commandExists('pip3')) out.push({ command: 'pip3', args: ['install', pkg], display: `pip3 install ${pkg}` });
      else if (await commandExists('pip')) out.push({ command: 'pip', args: ['install', pkg], display: `pip install ${pkg}` });
      else if (await commandExists('python')) out.push({ command: 'python', args: ['-m', 'pip', 'install', pkg], display: `python -m pip install ${pkg}` });
    }
  }
  if (install.go && (await commandExists('go'))) {
    const parts = install.go.split(/\s+/);
    out.push({ command: parts[0], args: parts.slice(1), display: install.go });
  }
  if (install.brew && (await commandExists('brew'))) {
    const pkg = install.brew.replace(/^brew\s+install\s+/i, '').trim().split(/\s+/)[0];
    if (pkg) out.push({ command: 'brew', args: ['install', pkg], display: `brew install ${pkg}` });
  }
  if (install.npm) {
    const parts = install.npm.split(/\s+/);
    out.push({ command: parts[0], args: parts.slice(1), display: install.npm });
  }
  return out;
}

/** Whether a tool is available, honoring the project's virtualenv(s). */
async function toolAvailable(adapter, detection) {
  if (resolveToolInEnvironments(detection?.pythonEnvs || [], adapter.command)) return true;
  return commandExists(adapter.command);
}

/**
 * Prerequisite runtimes/package managers for each auto-install method, with a
 * human label and where to get it. Used to tell the user *why* a tool can't be
 * installed automatically (e.g. "gitleaks needs Go, which isn't installed").
 */
const INSTALL_PREREQS = {
  pip: { commands: ['pip3', 'pip', 'python'], label: 'Python + pip', url: 'https://www.python.org/downloads/' },
  go: { commands: ['go'], label: 'Go', url: 'https://go.dev/dl/' },
  brew: { commands: ['brew'], label: 'Homebrew (macOS/Linux)', url: 'https://brew.sh' },
  npm: { commands: ['npm'], label: 'npm (Node.js)', url: 'https://nodejs.org' },
};

/**
 * For a tool with no runnable auto-installer, work out which prerequisite is
 * missing for each install method its adapter supports. This lets `init`
 * explain the specific blocker (a missing runtime/package manager) instead of a
 * generic "no installer available".
 *
 * @param {object} [install]  adapter.install hints (pip/go/brew/npm/...).
 * @param {(cmd:string)=>Promise<boolean>} [has]  existence check (injectable for tests).
 * @returns {Promise<Array<{method:string,label:string,url:string,command:string}>>}
 */
export async function missingPrereqs(install = {}, has = commandExists) {
  const reasons = [];
  for (const [method, info] of Object.entries(INSTALL_PREREQS)) {
    const command = install?.[method];
    if (!command) continue;
    let present = false;
    for (const cmd of info.commands) {
      if (await has(cmd)) {
        present = true;
        break;
      }
    }
    if (!present) reasons.push({ method, label: info.label, url: info.url, command });
  }
  return reasons;
}

/**
 * @param {object} [opts]
 */
export async function initCommand(opts = {}) {
  const root = process.cwd();
  log.raw('');
  log.raw(chalk.bold(`${PRODUCT} init`));
  log.raw('');

  // 1. Detect
  const detection = detectProject(root);
  const stacks = Object.entries(detection.stacks).filter(([, v]) => v).map(([k]) => k);
  log.step(`Detected stack: ${stacks.length ? chalk.bold(stacks.join(', ')) : 'unknown'}`);

  const requiredToolIds = [...detection.enabledTools];
  if (requiredToolIds.length === 0) {
    log.warn('No recognizable project markers found. You can still run `clipeus scan`.');
  } else {
    log.step(`Relevant tools: ${requiredToolIds.join(', ')}`);
  }
  log.blank();

  // 2. Tool availability + optional install
  const interactive = isInteractive();
  for (const id of requiredToolIds) {
    const adapter = getAdapter(id);
    if (!adapter) continue;
    // Bundled adapters need no install.
    if (typeof adapter.runCustom === 'function') {
      log.success(`${id} is bundled with ${PRODUCT}.`);
      continue;
    }
    const exists = await toolAvailable(adapter, detection);
    if (exists) {
      log.success(`${id} is installed.`);
      continue;
    }

    log.warn(`${id} is not installed.`);

    if (!interactive) {
      log.info(chalk.gray(`   install with: ${installHint(adapter)}`));
      continue;
    }

    // If this tool has a binary-download descriptor, offer that as the primary
    // path — no Go/Homebrew/Chocolatey needed, just an internet connection.
    if (DOWNLOAD_DESCRIPTORS[id]) {
      const yes = await confirm(`Download ${id} binary (no dependencies needed)?`, true);
      if (yes) {
        const sp = spinner(`Downloading ${id}...`);
        const dlResult = await downloadTool(id, {
          onProgress: (msg) => { sp.text = msg; },
        });
        if (dlResult.ok) {
          sp.succeed(`Installed ${id} v${dlResult.version} (downloaded to ~/.clipeus/bin/).`);
          continue;
        } else {
          sp.fail(`Download failed: ${dlResult.error}`);
          log.info(chalk.gray(`   You can also install manually: ${installHint(adapter)}`));
          continue;
        }
      } else {
        log.info(chalk.gray(`   skipped. Install later with \`clipeus init\` or manually: ${installHint(adapter)}`));
        continue;
      }
    }

    // For non-downloadable tools, try package-manager candidates.
    const candidates = await candidateInstallers(adapter.install, { pythonEnvs: detection.pythonEnvs });

    if (candidates.length === 0) {
      const blocked = await missingPrereqs(adapter.install);
      if (blocked.length) {
        log.info(chalk.gray(`   Can't install ${id} automatically — a required dependency is missing:`));
        for (const b of blocked) {
          log.info(chalk.gray(`     • ${b.label} not found (needed for "${b.command}") — get it at ${b.url}`));
        }
      } else {
        log.info(chalk.gray(`   No auto-installer is available for ${id} on this system.`));
      }
      if (adapter.install?.url) {
        log.info(chalk.gray(`     • or install ${id} directly (e.g. a prebuilt binary): ${adapter.install.url}`));
      }
      log.info(chalk.gray(`   Install the required dependency above, then re-run \`clipeus init\` to set up ${id}.`));
      continue;
    }

    const chosen = candidates[0];
    const yes = await confirm(`Install ${id} with "${chosen.display}"?`, false);
    if (!yes) {
      log.info(chalk.gray(`   skipped. Install later with: ${installHint(adapter)}`));
      continue;
    }

    const sp = spinner(`Installing ${id}...`);
    const res = await runTool({ command: chosen.command, args: chosen.args, timeoutMs: 300000, cwd: root });
    if (res.ok && (await toolAvailable(adapter, detection))) {
      sp.succeed(`Installed ${id}.`);
    } else {
      sp.fail(`Could not install ${id} automatically.`);
      const detail = (res.stderr || res.errorMessage || '')
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .slice(0, 2)
        .join(' ');
      if (detail) log.info(chalk.gray(`   reason: ${detail.slice(0, 300)}`));
      log.info(chalk.gray(`   Install ${id} manually, then re-run \`clipeus init\`: ${installHint(adapter)}`));
    }
  }
  log.blank();

  // 3. Pre-push hook
  if (detection.stacks.git) {
    const enable = await confirm('Enable pre-push scan hook?', false);
    if (enable) {
      const { config } = loadConfig(root);
      try {
        const result = enableHook(root, { threshold: config.failOn });
        log.success(`Pre-push hook ${result.action} at ${path.relative(root, result.path) || result.path}`);
      } catch (err) {
        log.error(`Could not install hook: ${err.message}`);
      }
    } else {
      log.info(chalk.gray('   skipped. Enable later with `clipeus hook enable`.'));
    }
  } else {
    log.info(chalk.gray('No .git directory found; skipping pre-push hook setup.'));
  }
  log.blank();

  // 4. Write config
  const configPath = path.join(root, CONFIG_FILE);
  let write = true;
  if (fs.existsSync(configPath)) {
    write = interactive
      ? await confirm(`${CONFIG_FILE} already exists. Overwrite?`, false)
      : false;
    if (!write) log.info(chalk.gray(`   kept existing ${CONFIG_FILE}.`));
  }
  if (write) {
    try {
      fs.writeFileSync(configPath, `${JSON.stringify(curatedConfig(), null, 2)}\n`, 'utf8');
      log.success(`Wrote ${CONFIG_FILE}.`);
    } catch (err) {
      log.error(`Could not write ${CONFIG_FILE}: ${err.message}`);
    }
  }

  // 5. Keep Clipeus's generated artifacts (reports, cache) out of version control.
  if (detection.stacks.git) {
    const gi = ensureGitignore(root);
    if (gi.changed) {
      log.success(`Updated .gitignore (${gi.added.join(', ')}).`);
    } else if (!gi.present) {
      log.info(chalk.gray('   no .gitignore found — skipping (create one and re-run init if you want Clipeus entries added).'));
    } else if (gi.error) {
      log.info(chalk.gray(`   could not update .gitignore: ${gi.error}`));
    }
  }

  log.blank();
  log.raw(chalk.green.bold('✔ Setup complete.') + chalk.gray('  Run `clipeus scan` to audit your project.'));
  log.blank();
}
