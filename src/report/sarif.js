/**
 * SARIF 2.1.0 reporter.
 *
 * Emits the OASIS SARIF format consumed by GitHub code scanning (Security tab),
 * VS Code SARIF viewer, and other CI tooling. Rules carry a `security-severity`
 * score so GitHub renders the correct severity. Pure templating, no network.
 */

import { VERSION, PRODUCT } from '../version.js';
import { baselineFingerprint } from '../config/baseline.js';

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

function ruleFor(finding) {
  return {
    id: finding.ruleId,
    name: finding.ruleId,
    shortDescription: { text: `${finding.category} (${finding.tool})` },
    helpUri: Array.isArray(finding.references) && finding.references[0] ? finding.references[0] : undefined,
    properties: {
      tags: ['security', finding.category, ...(finding.aiCodegenRelevant ? ['ai-codegen'] : [])],
      'security-severity': SECURITY_SEVERITY[finding.severity] || '5.0',
      category: finding.category,
      producer: finding.tool,
    },
  };
}

function resultFor(finding, ruleIndex) {
  const uri = finding.file || '.';
  const location = {
    physicalLocation: {
      artifactLocation: { uri },
    },
  };
  if (finding.line != null) {
    location.physicalLocation.region = {
      startLine: finding.line,
      ...(finding.endLine ? { endLine: finding.endLine } : {}),
      ...(finding.column ? { startColumn: finding.column } : {}),
    };
  }

  return {
    ruleId: finding.ruleId,
    ruleIndex,
    level: SARIF_LEVEL[finding.severity] || 'warning',
    message: {
      text: `${finding.message}${finding.remediation ? `\n\nRemediation: ${finding.remediation}` : ''}`,
    },
    locations: [location],
    partialFingerprints: { 'clipeus/v1': baselineFingerprint(finding) },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      tool: finding.tool,
      aiCodegenRelevant: Boolean(finding.aiCodegenRelevant),
      ...(finding.agreedTools ? { agreedTools: finding.agreedTools } : {}),
    },
  };
}

/**
 * @param {object} scan  runScan() result.
 * @returns {string} pretty-printed SARIF JSON
 */
export function render(scan) {
  const rules = [];
  const ruleIndex = new Map();

  const results = scan.findings.map((f) => {
    if (!ruleIndex.has(f.ruleId)) {
      ruleIndex.set(f.ruleId, rules.length);
      rules.push(ruleFor(f));
    }
    return resultFor(f, ruleIndex.get(f.ruleId));
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: PRODUCT,
            informationUri: 'https://github.com/AvikSrivastava10/Clipeus',
            version: VERSION,
            rules,
          },
        },
        results,
        ...(scan.root ? { originalUriBaseIds: { SRCROOT: { uri: `file://${String(scan.root).replace(/\\/g, '/')}/` } } } : {}),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
