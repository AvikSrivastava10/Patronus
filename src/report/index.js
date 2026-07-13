/**
 * Reporting entry point. Selects the reporter for the requested format.
 */

import * as terminal from './terminal.js';
import * as json from './json.js';
import * as markdown from './markdown.js';

export const FORMATS = Object.freeze(['terminal', 'json', 'markdown']);

/**
 * @param {object} scan  runScan() result.
 * @param {object} [opts]
 * @param {'terminal'|'json'|'markdown'} [opts.format='terminal']
 * @param {boolean} [opts.verbose]
 * @returns {string}
 */
export function renderReport(scan, opts = {}) {
  const format = opts.format || 'terminal';
  const inner = { verbose: Boolean(opts.verbose) };
  switch (format) {
    case 'json':
      return json.render(scan, inner);
    case 'markdown':
      return markdown.render(scan, inner);
    case 'terminal':
    default:
      return terminal.render(scan, inner);
  }
}

export { terminal, json, markdown };
