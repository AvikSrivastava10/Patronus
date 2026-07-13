/**
 * Bandit adapter (Apache-2.0). Python security linter.
 *
 * Runs `bandit -r . -f json` (read-only). Maps Bandit's severity/confidence and
 * a subset of well-known test ids onto the unified schema.
 */

import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity, inferCategory } from './base.js';

/** Bandit confidence (HIGH/MEDIUM/LOW) -> unified confidence. */
function mapConfidence(value) {
  switch (String(value || '').toUpperCase()) {
    case 'HIGH': return CONFIDENCE.high;
    case 'MEDIUM': return CONFIDENCE.medium;
    case 'LOW': return CONFIDENCE.low;
    default: return CONFIDENCE.medium;
  }
}

/** Map notable Bandit test ids to our taxonomy. */
const TEST_CATEGORY = {
  B102: CATEGORY.injection, // exec_used
  B103: CATEGORY.insecureConfig, // set_bad_file_permissions
  B104: CATEGORY.insecureConfig, // hardcoded_bind_all_interfaces
  B105: CATEGORY.secrets, // hardcoded_password_string
  B106: CATEGORY.secrets, // hardcoded_password_funcarg
  B107: CATEGORY.secrets, // hardcoded_password_default
  B108: CATEGORY.insecureConfig, // hardcoded_tmp_directory
  B201: CATEGORY.insecureConfig, // flask_debug_true
  B301: CATEGORY.deserialization, // pickle
  B302: CATEGORY.deserialization, // marshal
  B303: CATEGORY.insecureCrypto, // md5
  B304: CATEGORY.insecureCrypto, // insecure ciphers
  B305: CATEGORY.insecureCrypto, // insecure cipher modes
  B306: CATEGORY.insecureConfig, // mktemp_q
  B307: CATEGORY.injection, // eval
  B308: CATEGORY.injection, // mark_safe
  B310: CATEGORY.ssrf, // urllib_urlopen
  B311: CATEGORY.insecureCrypto, // random
  B312: CATEGORY.insecureConfig, // telnetlib
  B313: CATEGORY.deserialization, // xml
  B321: CATEGORY.insecureConfig, // ftplib
  B324: CATEGORY.insecureCrypto, // hashlib weak hash
  B501: CATEGORY.insecureTransport, // request_with_no_cert_validation
  B502: CATEGORY.insecureTransport, // ssl_with_bad_version
  B503: CATEGORY.insecureTransport, // ssl_with_bad_defaults
  B506: CATEGORY.deserialization, // yaml_load
  B601: CATEGORY.injection, // paramiko_calls
  B602: CATEGORY.injection, // subprocess_popen_with_shell_equals_true
  B603: CATEGORY.injection, // subprocess_without_shell_equals_true
  B604: CATEGORY.injection, // any_other_function_with_shell_equals_true
  B605: CATEGORY.injection, // start_process_with_a_shell
  B606: CATEGORY.injection, // start_process_with_no_shell
  B607: CATEGORY.injection, // start_process_with_partial_path
  B608: CATEGORY.injection, // hardcoded_sql_expressions
  B609: CATEGORY.injection, // linux_commands_wildcard_injection
  B610: CATEGORY.injection, // django_extra_used
  B611: CATEGORY.injection, // django_rawsql_used
  B701: CATEGORY.injection, // jinja2_autoescape_false
};

const adapter = {
  id: TOOL.bandit,
  displayName: 'Bandit',
  command: 'bandit',
  versionArgs: ['--version'],
  license: 'Apache-2.0',
  homepage: 'https://github.com/PyCQA/bandit',
  install: {
    pip: 'pip install bandit',
    recommended: 'pip install bandit',
    url: 'https://bandit.readthedocs.io/en/latest/start.html',
  },

  buildInvocation(ctx) {
    return {
      command: 'bandit',
      args: [
        '-r', '.',
        '-f', 'json',
        '-q',
        '--exclude', '.git,node_modules,venv,.venv,env,build,dist,__pycache__,.tox',
      ],
      cwd: ctx.root,
      output: { type: 'stdout' },
    };
  },

  normalize(parsed) {
    const results = parsed?.results;
    if (!Array.isArray(results)) return [];

    return results.map((r) => {
      const testId = r.test_id || '';
      const category =
        TEST_CATEGORY[testId] ||
        inferCategory(`${r.test_name} ${r.issue_text}`, CATEGORY.other);

      const refs = [];
      if (r.more_info) refs.push(r.more_info);
      if (r.issue_cwe?.link) refs.push(r.issue_cwe.link);

      return createFinding({
        tool: TOOL.bandit,
        ruleId: testId ? `${testId} (${r.test_name})` : r.test_name || 'bandit',
        severity: normalizeSeverity(r.issue_severity, SEVERITY.medium),
        category,
        file: r.filename,
        line: r.line_number,
        message: r.issue_text || r.test_name || 'Bandit finding',
        confidence: mapConfidence(r.issue_confidence),
        aiCodegenRelevant: false,
        references: refs.length ? refs : undefined,
      });
    });
  },
};

export default adapter;
