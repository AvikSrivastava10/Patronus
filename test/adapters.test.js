import { describe, it, expect } from 'vitest';
import semgrep from '../src/adapters/semgrep.js';
import gitleaks from '../src/adapters/gitleaks.js';
import trufflehog from '../src/adapters/trufflehog.js';
import npmAudit from '../src/adapters/npm-audit.js';
import pipAudit from '../src/adapters/pip-audit.js';
import bandit from '../src/adapters/bandit.js';
import trivy from '../src/adapters/trivy.js';
import owasp from '../src/adapters/owasp-dependency-check.js';
import eslint from '../src/adapters/eslint.js';

describe('semgrep.normalize', () => {
  it('maps severity, honors patronus metadata tags', () => {
    const raw = {
      version: '1.50.0',
      results: [
        {
          check_id: 'patronus.jwt.none-algorithm',
          path: 'src/auth.js',
          start: { line: 12, col: 3 },
          end: { line: 12 },
          extra: {
            message: 'JWT verification disabled',
            severity: 'ERROR',
            metadata: {
              'patronus-category': 'insecure-jwt',
              'patronus-ai-codegen': true,
              references: ['https://cwe.mitre.org/data/definitions/347.html'],
            },
          },
        },
      ],
    };
    const [f] = semgrep.normalize(raw, {});
    expect(f.tool).toBe('semgrep');
    expect(f.severity).toBe('high');
    expect(f.category).toBe('insecure-jwt');
    expect(f.aiCodegenRelevant).toBe(true);
    expect(f.file).toBe('src/auth.js');
    expect(f.line).toBe(12);
    expect(f.references).toContain('https://cwe.mitre.org/data/definitions/347.html');
  });

  it('infers category from rule id when metadata is absent', () => {
    const raw = { results: [{ check_id: 'js.express.cors-wildcard', path: 'a.js', start: { line: 1 }, extra: { severity: 'WARNING', message: 'CORS *' } }] };
    const [f] = semgrep.normalize(raw, {});
    expect(f.category).toBe('cors-misconfig');
    expect(f.severity).toBe('medium');
  });

  it('returns [] for missing results', () => {
    expect(semgrep.normalize({}, {})).toEqual([]);
  });
});

describe('gitleaks.normalize', () => {
  it('maps to secrets category and redacts the secret value', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const raw = [
      { RuleID: 'aws-access-token', Description: 'AWS Access Key', File: 'config.js', StartLine: 4, Match: secret, Secret: secret, Commit: 'abcdef1234567890' },
    ];
    const [f] = gitleaks.normalize(raw);
    expect(f.category).toBe('secrets');
    expect(f.severity).toBe('high');
    expect(f.file).toBe('config.js');
    expect(f.line).toBe(4);
    expect(f.message).not.toContain(secret);
    expect(f.message).toMatch(/commit abcdef12/);
  });

  it('rates private keys as critical', () => {
    const [f] = gitleaks.normalize([{ RuleID: 'private-key', File: 'id_rsa', StartLine: 1, Match: 'x' }]);
    expect(f.severity).toBe('critical');
  });
});

describe('trufflehog.normalize (JSONL)', () => {
  it('parses JSONL, flags verified as critical and redacts', () => {
    const jsonl = [
      JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIAVERYSECRETKEY', SourceMetadata: { Data: { Filesystem: { file: 'env.js', line: 7 } } } }),
      'not-json-log-line',
      JSON.stringify({ DetectorName: 'Slack', Verified: false, Raw: 'xoxb-123', SourceMetadata: { Data: { Filesystem: { file: 'a.js', line: 2 } } } }),
    ].join('\n');
    const parsed = trufflehog.parse(jsonl);
    const findings = trufflehog.normalize(parsed);
    expect(findings).toHaveLength(2);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].message).not.toContain('AKIAVERYSECRETKEY');
    expect(findings[1].severity).toBe('high');
    expect(findings[1].confidence).toBe('medium');
  });
});

describe('npm-audit.normalize', () => {
  it('handles npm v7 vulnerabilities with advisory objects', () => {
    const raw = {
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          via: [{ source: 1065, title: 'Prototype Pollution', url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695', severity: 'high', range: '<4.17.19' }],
          range: '<4.17.19',
          fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
        },
      },
    };
    const findings = npmAudit.normalize(raw);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('GHSA-jf85-cpcp-j695');
    expect(findings[0].category).toBe('dependency-cve');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].message).toMatch(/lodash/);
    expect(findings[0].remediation).toMatch(/4\.17\.21/);
  });

  it('handles transitive-only vulnerabilities (string via)', () => {
    const raw = { vulnerabilities: { foo: { name: 'foo', severity: 'moderate', via: ['bar'], range: '*' } } };
    const [f] = npmAudit.normalize(raw);
    expect(f.severity).toBe('medium');
    expect(f.category).toBe('dependency-cve');
  });
});

describe('pip-audit.normalize', () => {
  it('maps vulns with fix versions and CVE references', () => {
    const raw = { dependencies: [{ name: 'flask', version: '0.5', vulns: [{ id: 'PYSEC-2019-179', fix_versions: ['0.12.3'], aliases: ['CVE-2018-1000656'] }] }] };
    const [f] = pipAudit.normalize(raw, { root: '/does/not/exist' });
    expect(f.ruleId).toBe('PYSEC-2019-179');
    expect(f.category).toBe('dependency-cve');
    expect(f.remediation).toMatch(/0\.12\.3/);
    expect(f.references.some((r) => r.includes('CVE-2018-1000656') || r.includes('PYSEC-2019-179'))).toBe(true);
  });
});

describe('bandit.normalize', () => {
  it('maps test ids to categories and severity/confidence', () => {
    const raw = {
      results: [
        { test_id: 'B602', test_name: 'subprocess_popen_with_shell_equals_true', filename: './run.py', issue_severity: 'HIGH', issue_confidence: 'HIGH', issue_text: 'shell=True', line_number: 9, more_info: 'https://bandit.readthedocs.io' },
        { test_id: 'B303', test_name: 'md5', filename: './h.py', issue_severity: 'MEDIUM', issue_confidence: 'MEDIUM', issue_text: 'md5 used', line_number: 3 },
      ],
    };
    const findings = bandit.normalize(raw);
    expect(findings[0].category).toBe('injection');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('high');
    expect(findings[1].category).toBe('insecure-crypto');
    expect(findings[1].confidence).toBe('medium');
  });
});

describe('trivy.normalize', () => {
  it('normalizes vulnerabilities, misconfigurations, and secrets', () => {
    const raw = {
      Results: [
        { Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-1', PkgName: 'ejs', InstalledVersion: '2.0', FixedVersion: '3.1.7', Severity: 'CRITICAL', Title: 'RCE', PrimaryURL: 'https://x' }] },
        { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', AVDID: 'AVD-DS-0002', Title: 'root user', Message: 'runs as root', Severity: 'HIGH', Resolution: 'add USER', CauseMetadata: { StartLine: 5 } }] },
        { Target: '.env', Secrets: [{ RuleID: 'aws', Category: 'AWS', Severity: 'CRITICAL', Title: 'AWS key', StartLine: 2, Match: 'AKIA...' }] },
      ],
    };
    const findings = trivy.normalize(raw);
    expect(findings).toHaveLength(3);
    const cats = findings.map((f) => f.category).sort();
    expect(cats).toEqual(['dependency-cve', 'iac-misconfig', 'secrets']);
    const misconfig = findings.find((f) => f.category === 'iac-misconfig');
    expect(misconfig.line).toBe(5);
    expect(misconfig.severity).toBe('high');
  });
});

describe('owasp-dependency-check.normalize', () => {
  it('derives severity from CVSS when severity string is absent', () => {
    const raw = { dependencies: [{ fileName: 'lib.jar', vulnerabilities: [{ name: 'CVE-2020-1', cvssv3: { baseScore: 9.8 }, references: [{ url: 'https://nvd' }] }] }] };
    const [f] = owasp.normalize(raw);
    expect(f.severity).toBe('critical');
    expect(f.category).toBe('dependency-cve');
    expect(f.ruleId).toBe('CVE-2020-1');
  });
});

describe('eslint.normalize', () => {
  it('maps security plugin rules and drops parse errors', () => {
    const results = [
      {
        filePath: 'app.js',
        messages: [
          { ruleId: 'security/detect-child-process', severity: 2, message: 'child_process', line: 3, column: 5 },
          { ruleId: null, fatal: true, message: 'Parsing error', line: 1, column: 1 },
          { ruleId: 'no-console', severity: 1, message: 'console', line: 4 },
        ],
      },
    ];
    const findings = eslint.normalize(results, { root: '' });
    // Only the security rule survives (parse error + non-security rule filtered out).
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('security/detect-child-process');
    expect(findings[0].category).toBe('injection');
    expect(findings[0].severity).toBe('high');
  });
});
