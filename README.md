# Clipeus

**Free, open-source, on-demand security & vulnerability auditing for your codebase — with special attention to the bugs that AI-assisted ("vibe coded") development tends to introduce.**

Clipeus is an **orchestrator plus a differentiator**. It runs the best free/open-source security scanners for your stack, normalizes everything into one report, and adds its own detection layer for the gaps those tools structurally cannot cover (missing auth on routes, missing rate limiting, missing security headers, and cross-file taint from user input to dangerous sinks).

---

## 🔒 The read-only guarantee

**Clipeus never modifies your source code, dependencies, or git history. Ever.**

- It only **reads** files and **writes its own report** (to stdout, or to a file you name with `--output`).
- It never invokes any underlying tool's `--fix` / `--write` / auto-remediation mode — this is enforced in code.
- Intermediate output from underlying tools is written to a temporary directory outside your project and cleaned up afterward.

If a check fails, is missing, or errors out, Clipeus reports that one check as skipped/failed and keeps going. **One broken component never takes down the whole scan.**

---

## Requirements

- **Node.js** `^18.19 || ^20.9 || >=21.1` (any current LTS works).
- Clipeus adapts to your environment: it only runs the analyzers relevant to your stack, and skips any whose requirements aren't met — including its bundled ESLint layer if the Node version is too old — reporting each skip with a reason instead of failing.

## Installation

Options are listed in increasing order of commitment. Pick the one that fits.

### 1. Try it instantly, no install

```bash
npx clipeus scan
```

### 2. Install globally, for use across many projects

```bash
npm install -g clipeus
clipeus scan
```

### 3. Install as a dev dependency, for teams that want it version-locked and wired into CI

Clipeus is a scanning tool, not a runtime dependency — install it as a **dev** dependency so it never ends up in a production `node_modules`.

```bash
npm install --save-dev clipeus
```

Then add a script to your `package.json`:

```json
{
  "scripts": {
    "security-scan": "clipeus scan"
  }
}
```

## First run

After installing, run the one-time setup:

```bash
clipeus init
```

`clipeus init` will:

1. **Detect your project type** by scanning for marker files (`package.json`, `requirements.txt`, `Dockerfile`, `*.tf`, `.git`, `pom.xml`, etc.).
2. **Check which underlying tools are installed**, and offer to install any that are missing via their own package manager.
3. Offer to install a **pre-push git hook** that blocks pushes with security findings.
4. Write a default **`clipeus.config.json`**.

Then, for regular use:

```bash
clipeus scan
```

---

## Commands

| Command | What it does |
| --- | --- |
| `clipeus init` | First-run setup: detect stack, check/install tools, optional pre-push hook, write config. |
| `clipeus scan [path]` | Run all applicable analyzers against `path` (default: current directory) and print a report. Exit code reflects `--fail-on`. |
| `clipeus hook enable` | Install a git pre-push hook that runs `clipeus scan --fail-on=<threshold>` and blocks the push on failure. |
| `clipeus hook disable` | Remove the Clipeus hook (preserves any other hook content). |
| `clipeus hook status` | Show whether the managed hook is installed. |
| `clipeus doctor` | Diagnostic: check every underlying tool is installed and runnable, report versions. Read-only. |
| `clipeus --version` | Print the version. |
| `clipeus --help` | Show help. |

### `scan` flags

| Flag | Behavior |
| --- | --- |
| `--json` | Output findings as JSON in the unified schema (to stdout, or `--output <file>`). |
| `--markdown` | Output a markdown summary, ready to paste into a PR comment (pure templating, no AI/LLM involved). |
| `--sarif` | Output SARIF 2.1.0 for GitHub code scanning (Security tab) and IDE SARIF viewers. |
| `--fail-on=<critical\|high\|medium\|low>` | Minimum severity that causes a non-zero exit code. Default: `critical`. |
| `--min-confidence=<high\|medium\|low>` | Hide findings below this confidence (reduce heuristic noise). |
| `--only=<tool1,tool2>` | Run only the named tool(s)/check(s). |
| `--skip=<tool1,tool2>` | Run everything except the named tool(s)/check(s). |
| `--baseline <file>` | Compare against a baseline and report only **new** findings. |
| `--update-baseline` | Record the current findings as the baseline (requires `--baseline`). |
| `--offline` | Avoid network features (e.g. the Semgrep registry); use bundled rules only. |
| `--verbose` | Include rule id, tool version, and references per finding. |
| `--output <file>` | Write the report to a file instead of stdout. |

```bash
# Examples
clipeus scan
clipeus scan ./services/api --fail-on=high
clipeus scan --json --output clipeus-report.json
clipeus scan --sarif --output clipeus.sarif        # upload to GitHub code scanning
clipeus scan --only=semgrep,gitleaks --markdown
clipeus scan --min-confidence=medium --offline     # high-signal, no network
```

### Baseline: adopt on a legacy codebase without the noise

Record the current findings as an accepted baseline, then have CI fail only on **new** issues:

```bash
# One-time: accept the current state.
clipeus scan --baseline .clipeus-baseline.json --update-baseline

# From then on (e.g. in CI / the pre-push hook): only regressions fail.
clipeus scan --baseline .clipeus-baseline.json --fail-on=high
```

Baseline fingerprints are line-independent, so unrelated edits that shift code around don't resurface already-accepted findings.

### Inline suppressions

Acknowledge a finding right where it lives, in any language's comment syntax:

```js
// clipeus-disable-next-line              // suppress every finding on the next line
foo(userInput);                           // clipeus-disable-line injection   (only the "injection" category)
```

```python
os.system(cmd)  # clipeus-disable-line    (this line only)
```

Use `clipeus-disable-file` (or a bare `clipeus-disable`) at the top of a file to suppress the whole file. Each directive optionally takes a comma/space-separated list of rule ids, categories, or tool ids; with none, it suppresses everything in scope.

---

## What Clipeus runs (all free & open-source)

Clipeus is **project-aware**: it only runs the tools relevant to your detected stack. Missing tools are skipped with an install hint (except ESLint, which is bundled). No paid or cloud-only features of any tool are ever used.

| Tool | Purpose | License | Enabled when |
| --- | --- | --- | --- |
| [Semgrep CE](https://semgrep.dev) | Static analysis (+ Clipeus's custom ruleset) | LGPL-2.1 | any source files |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection (working tree + git history) | MIT | `.git` present |
| [truffleHog](https://github.com/trufflesecurity/trufflehog) | Secret detection (verification off by default) | AGPL-3.0 | `.git` present |
| npm audit | Node dependency CVEs | ships with npm | `package.json` |
| [ESLint](https://eslint.org) + `eslint-plugin-security` + `eslint-plugin-no-unsanitized` | JS/TS security linting (uses the **project's own ESLint** when present, else the bundled one) | MIT | JS/TS project |
| [pip-audit](https://github.com/pypa/pip-audit) | Python dependency CVEs | Apache-2.0 | Python project |
| [Bandit](https://github.com/PyCQA/bandit) | Python security linting | Apache-2.0 | Python project |
| [Trivy](https://github.com/aquasecurity/trivy) | Dockerfiles, Kubernetes, Terraform, filesystem deps | Apache-2.0 | Docker/K8s/Terraform |

### Clipeus's own detection layer (the differentiator)

On top of the tools above, Clipeus adds detection for gaps that generic scanners miss — the kinds of issues that show up disproportionately in AI-generated code:

- **Custom Semgrep rules** — permissive CORS, insecure JWT (`alg: none`, hardcoded secret, missing expiration), insecure cookie flags, weak password hashing, disabled TLS verification, likely-hallucinated security APIs, debug mode in production, error/stack-trace disclosure, GraphQL introspection, missing webhook signature verification.
- **`clipeus-auth`** — routes on sensitive paths with no authentication/authorization guard.
- **`clipeus-rate-limit`** — auth-style endpoints (login, signup, password reset, OTP) with no rate limiting anywhere in the app.
- **`clipeus-security-headers`** — no `helmet` / CSP / HSTS (or `flask-talisman`).
- **`clipeus-taint`** — cross-file taint tracking from user-controlled sources (`req.body`, `request.args`, …) into dangerous sinks (`eval`, `child_process.exec`, SQL `query`, filesystem calls) without a sanitizer in between.

Selectable ids for `--only` / `--skip`: `semgrep, gitleaks, trufflehog, npm-audit, pip-audit, eslint, bandit, trivy, clipeus-auth, clipeus-rate-limit, clipeus-security-headers, clipeus-taint`.

---

## Output & exit codes

- **Terminal (default):** color-coded, grouped by severity, human-readable.
- **`--json`:** the full normalized findings array plus scan metadata.
- **`--markdown`:** PR-comment-ready summary.
- **`--sarif`:** SARIF 2.1.0 for GitHub code scanning and IDE SARIF viewers.
- **Exit code:** non-zero when any finding is at or above `--fail-on` (default `critical`), zero otherwise (with `--baseline`, only *new* findings count). Ideal for CI and the pre-push hook.

Every finding — from every source — is normalized into one schema:

```json
{
  "tool": "semgrep",
  "ruleId": "clipeus-jwt-algorithm-none",
  "severity": "high",
  "category": "insecure-jwt",
  "file": "src/auth/session.js",
  "line": 42,
  "message": "JWT verified with the \"none\" algorithm; signatures are not checked.",
  "confidence": "high",
  "aiCodegenRelevant": true
}
```

Findings that overlap across tools (same file + line + category) are **deduplicated**, keeping the highest-confidence one and noting which tools agreed. Heuristic findings (the custom checkers and taint tracker) carry `medium`/`low` confidence so you can tell them apart from deterministic tool findings.

### CI usage

```bash
# Non-interactive; fail the build on high+ findings; emit a JSON artifact.
CI=1 clipeus scan --fail-on=high --json --output clipeus-report.json

# GitHub code scanning: emit SARIF and upload it to the Security tab.
CI=1 clipeus scan --sarif --output clipeus.sarif
#   - uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: clipeus.sarif }
```

Set `CI=1` or `CLIPEUS_NONINTERACTIVE=1` to guarantee Clipeus never prompts.

---

## Configuration

`clipeus.config.json` (or `.clipeusrc`) at your project root. All keys are optional; defaults are used otherwise.

```json
{
  "failOn": "critical",
  "toolTimeoutMs": 120000,
  "tools": { "enabled": [], "disabled": [] },
  "semgrep": { "registry": "p/default" },
  "checkers": {
    "sensitivePathKeywords": ["admin", "user", "payment", "billing"],
    "authMiddlewareNames": ["requireAuth", "isAuthenticated", "login_required"],
    "rateLimitMiddlewareNames": ["rateLimit", "limiter"],
    "sensitiveRoutePatterns": ["login", "signup", "password", "otp"]
  },
  "taint": {
    "sources": ["req.body", "req.query", "request.form"],
    "sinks": ["eval", "child_process.exec", "query"],
    "sanitizers": ["escape", "parameterize", "validate"]
  }
}
```

- `tools.enabled` empty means **auto-detect**. Listing tools overrides detection.
- `semgrep.registry` is the Semgrep registry ruleset run online (default `p/default`); set it to `false` to scan with only Clipeus's bundled rules, or set `semgrep.configs` to a list to choose the rule sources yourself. Clipeus never uses Semgrep's `auto` config, so scans stay telemetry-free (`--metrics=off`), and `--offline` drops the registry entirely.
- `secrets.dataFiles` controls likely-false-positive secret hits inside data files (CSV/Parquet/ML datasets): `demote` (default — dropped to low severity but kept on record), `ignore` (dropped entirely), or `keep` (reported as-is). High-confidence rule matches and verified secrets are never affected, even in a data file.
- The checker keyword lists are fully tunable to your project's naming conventions.

### `.clipeusignore`

Gitignore-style suppression file at your project root. Suppress by path glob, rule id, or category:

```gitignore
# path globs (gitignore semantics, incl. ! negation)
src/legacy/**
*.min.js

# rule ids (exact or glob)
rule:security/detect-object-injection
rule:clipeus-cors-*

# whole categories
category:info-disclosure
```

---

## How it works (build phases)

1. **Orchestration** — detect the stack, run applicable tools in parallel (each timeout-guarded and failure-isolated), normalize + deduplicate, report.
2. **Custom Semgrep rules** — bundled AI-codegen / generic-gap rules loaded alongside Semgrep's community ruleset.
3. **Standalone checkers** — AST-based route/middleware analysis for missing auth, missing rate limiting, and missing security headers.
4. **Cross-file taint tracking** — a scoped, inter-procedural source→sink dataflow engine for JS/TS (plus a best-effort Python heuristic).

---

## Development

```bash
npm install
npm test           # vitest unit + integration tests
```

Custom Semgrep rules ship with co-located true-positive / true-negative fixtures (`// ruleid:` / `// ok:` annotations) and can be validated with `semgrep --test src/rules` where Semgrep is available. `test/rules.test.js` validates every rule's structure and taxonomy without needing Semgrep installed.

---

## License

[MIT](./LICENSE) © Avik Srivastava
