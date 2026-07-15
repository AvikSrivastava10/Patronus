/**
 * Project detection.
 *
 * Scans the target directory (top level plus reasonably nested locations) for
 * marker files and maps them to the set of tools/checkers that make sense for
 * the stack. This keeps Clipeus project-aware: we never run a Python scanner
 * on a pure JS project, etc.
 *
 * The result is stored in the scan context so later phases (custom rules, route
 * parsing, taint tracking) know which language(s) to target.
 */

import fs from 'node:fs';
import path from 'node:path';
import { TOOL } from '../constants.js';
import { walk, listTopLevel } from '../core/fswalk.js';
import { findPythonEnvironments } from './environments.js';
import { log } from '../core/logger.js';

/** Extensions that count as "source files" for the always-on Semgrep pass. */
const SOURCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
  '.py', '.rb', '.go', '.java', '.cs', '.php', '.rs', '.kt', '.kts',
  '.scala', '.c', '.cc', '.cpp', '.h', '.hpp', '.swift', '.sh', '.bash',
  '.tf', '.yaml', '.yml',
]);

const JS_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte']);

const NPM_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

/**
 * Heuristically decide whether a YAML file is a Kubernetes manifest by looking
 * for top-level `kind:` and `apiVersion:` keys. Reads only a bounded prefix.
 * @param {string} file
 * @returns {boolean}
 */
function looksLikeK8sManifest(file) {
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(4096);
    const bytes = fs.readSync(fd, buf, 0, 4096, 0);
    fs.closeSync(fd);
    const text = buf.toString('utf8', 0, bytes);
    const hasKind = /^\s*kind:\s*\S+/m.test(text);
    const hasApiVersion = /^\s*apiVersion:\s*\S+/m.test(text);
    return hasKind && hasApiVersion;
  } catch {
    return false;
  }
}

/**
 * @typedef {Object} DetectionResult
 * @property {string}  root
 * @property {Object}  stacks   Booleans per stack.
 * @property {string[]} languages  e.g. ['javascript','python'] for custom layers.
 * @property {Object}  markers  Which marker files/dirs were found, per stack.
 * @property {Set<string>} enabledTools  External tool ids to run.
 * @property {boolean} hasSourceFiles
 * @property {Object}  meta     Extra info (lockfiles present, counts).
 */

/**
 * Detect the project's stack and the set of applicable tools.
 * @param {string} root
 * @param {Object} [opts]
 * @param {number} [opts.maxDepth=8]
 * @returns {DetectionResult}
 */
export function detectProject(root, opts = {}) {
  const { maxDepth = 8 } = opts;
  const abs = path.resolve(root);

  const markers = {
    node: [], python: [], docker: [], terraform: [],
    kubernetes: [], java: [], dotnet: [], git: [],
  };
  const meta = {
    npmLockfile: null,
    npmLockfiles: [],
    npmLockfileDir: null,
    k8sManifests: [],
    fileCount: 0,
    nodeConstraint: detectNodeConstraint(abs),
  };

  // Absolute locations captured during the walk, used to locate modules/lockfiles
  // that may live in a subfolder rather than the project root.
  const npmLockfilePaths = [];
  const packageJsonDirs = new Set();

  // .git may be a directory (normal) or a file (worktrees/submodules).
  if (fs.existsSync(path.join(abs, '.git'))) {
    markers.git.push('.git');
  }

  let files = [];
  try {
    files = walk(abs, { maxDepth, maxFiles: 30_000 });
  } catch (err) {
    log.debug(`detect: walk failed (${err.message})`);
    files = [];
  }
  meta.fileCount = files.length;

  const extensions = new Set();
  let hasSourceFiles = false;
  const yamlCandidates = [];

  for (const file of files) {
    const base = path.basename(file);
    const ext = path.extname(file).toLowerCase();
    extensions.add(ext);
    if (SOURCE_EXTENSIONS.has(ext)) hasSourceFiles = true;

    // Node
    if (base === 'package.json') {
      markers.node.push(rel(abs, file));
      packageJsonDirs.add(path.dirname(file));
    }
    if (NPM_LOCKFILES.includes(base)) {
      if (!meta.npmLockfile) meta.npmLockfile = base;
      npmLockfilePaths.push(file);
    }

    // Python
    if (['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg'].includes(base)) {
      markers.python.push(rel(abs, file));
    }
    if (ext === '.py') pushUnique(markers.python, `*.py (${path.dirname(rel(abs, file)) || '.'})`);

    // Docker
    if (base === 'Dockerfile' || base.startsWith('Dockerfile.') || base.endsWith('.Dockerfile')) {
      markers.docker.push(rel(abs, file));
    }
    if (['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'].includes(base)) {
      markers.docker.push(rel(abs, file));
    }

    // Terraform
    if (ext === '.tf' || ext === '.tfvars') pushUnique(markers.terraform, `*.tf (${path.dirname(rel(abs, file)) || '.'})`);

    // Java
    if (base === 'pom.xml' || base === 'build.gradle' || base === 'build.gradle.kts') {
      markers.java.push(rel(abs, file));
    }

    // .NET
    if (['.csproj', '.vbproj', '.fsproj', '.sln'].includes(ext)) {
      markers.dotnet.push(rel(abs, file));
    }

    // Candidate k8s YAML (defer content check)
    if ((ext === '.yaml' || ext === '.yml') &&
        !['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'].includes(base)) {
      yamlCandidates.push(file);
    }
  }

  // Bounded k8s manifest content check.
  for (const file of yamlCandidates.slice(0, 200)) {
    if (looksLikeK8sManifest(file)) {
      const r = rel(abs, file);
      markers.kubernetes.push(r);
      meta.k8sManifests.push(r);
    }
  }

  const stacks = {
    node: markers.node.length > 0,
    python: markers.python.length > 0,
    docker: markers.docker.length > 0,
    terraform: markers.terraform.length > 0,
    kubernetes: markers.kubernetes.length > 0,
    java: markers.java.length > 0,
    dotnet: markers.dotnet.length > 0,
    git: markers.git.length > 0,
  };

  const languages = [];
  if (stacks.node || hasExt(extensions, JS_EXT)) languages.push('javascript');
  if (stacks.python) languages.push('python');

  const enabledTools = computeEnabledTools(stacks, hasSourceFiles);

  // Where Node lockfiles actually live (they may be in a subfolder, not root).
  meta.npmLockfiles = npmLockfilePaths.map((p) => rel(abs, p));
  meta.npmLockfileDir = npmLockfilePaths.length ? path.dirname(npmLockfilePaths[0]) : null;
  const nodeModuleDirs = [...packageJsonDirs];

  // Python virtualenvs anywhere in the main layout (root or a subfolder).
  const pythonEnvs = stacks.python ? findPythonEnvironments(abs) : [];

  return {
    root: abs, stacks, languages, markers, enabledTools, hasSourceFiles, meta,
    nodeModuleDirs, pythonEnvs,
  };
}

/** Map detected stacks to the external tool ids that should run. */
export function computeEnabledTools(stacks, hasSourceFiles) {
  const tools = new Set();
  if (stacks.node) {
    tools.add(TOOL.npmAudit);
    tools.add(TOOL.eslint);
  }
  if (stacks.python) {
    tools.add(TOOL.pipAudit);
    tools.add(TOOL.bandit);
  }
  if (stacks.docker || stacks.terraform || stacks.kubernetes) {
    tools.add(TOOL.trivy);
  }
  if (stacks.git) {
    tools.add(TOOL.gitleaks);
    tools.add(TOOL.trufflehog);
  }
  if (hasSourceFiles) {
    tools.add(TOOL.semgrep);
  }
  return tools;
}

/** Which internal Clipeus checkers/engines apply, based on languages. */
export function computeEnabledCheckers(detection) {
  const checkers = new Set();
  if (detection.languages.includes('javascript') || detection.languages.includes('python')) {
    checkers.add(TOOL.authChecker);
    checkers.add(TOOL.rateLimitChecker);
    checkers.add(TOOL.securityHeadersChecker);
    checkers.add(TOOL.taint);
  }
  return checkers;
}

function rel(root, file) {
  return path.relative(root, file).replace(/\\/g, '/');
}

function pushUnique(arr, value) {
  if (!arr.includes(value)) arr.push(value);
}

function hasExt(set, group) {
  for (const e of group) if (set.has(e)) return true;
  return false;
}

/**
 * Read the target project's declared Node version constraint, if any, from
 * .nvmrc, .node-version, or package.json "engines.node". Lets Clipeus report
 * the toolchain it detected and adapt messaging. Read-only, never throws.
 * @returns {{source:string, value:string}|null}
 */
function detectNodeConstraint(root) {
  const readFirstLine = (name) => {
    try {
      const p = path.join(root, name);
      if (fs.existsSync(p) && fs.statSync(p).isFile()) {
        const v = fs.readFileSync(p, 'utf8').trim().split(/\r?\n/)[0].trim();
        return v || null;
      }
    } catch { /* ignore */ }
    return null;
  };

  const nvmrc = readFirstLine('.nvmrc');
  if (nvmrc) return { source: '.nvmrc', value: nvmrc };
  const nodeVersion = readFirstLine('.node-version');
  if (nodeVersion) return { source: '.node-version', value: nodeVersion };

  try {
    const pkgPath = path.join(root, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const eng = pkg?.engines?.node;
      if (eng) return { source: 'package.json engines.node', value: String(eng) };
    }
  } catch { /* ignore */ }
  return null;
}

/** Top-level marker summary without a full walk (used by `init` for speed). */
export function quickDetect(root) {
  const abs = path.resolve(root);
  const { files, dirs } = listTopLevel(abs);
  return {
    root: abs,
    hasPackageJson: files.includes('package.json'),
    hasGit: dirs.includes('.git') || files.includes('.git'),
    files,
    dirs,
  };
}
