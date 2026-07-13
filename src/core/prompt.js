/**
 * Minimal interactive prompt helpers built on node:readline/promises.
 *
 * Prompts are written to stderr (stdout stays reserved for report output). In
 * non-interactive contexts (no TTY, e.g. CI) prompts resolve to their default
 * without blocking.
 */

import readline from 'node:readline/promises';
import process from 'node:process';
import { chalk } from './logger.js';

export function isInteractive() {
  // Honor common non-interactive signals so `init` never blocks in CI or
  // scripted contexts. Defaults are used instead of prompting.
  if (process.env.PATRONUS_NONINTERACTIVE || process.env.CI) return false;
  return Boolean(process.stdin.isTTY && process.stderr.isTTY);
}

/**
 * Yes/no confirmation.
 * @param {string} question
 * @param {boolean} [defaultValue=false]
 * @returns {Promise<boolean>}
 */
export async function confirm(question, defaultValue = false) {
  if (!isInteractive()) return defaultValue;
  const hint = defaultValue ? 'Y/n' : 'y/N';
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = (await rl.question(`${chalk.cyan('?')} ${question} ${chalk.gray(`(${hint})`)} `)).trim().toLowerCase();
    if (!answer) return defaultValue;
    return answer === 'y' || answer === 'yes';
  } catch {
    return defaultValue;
  } finally {
    rl.close();
  }
}

/**
 * Free-text prompt with a default.
 * @param {string} question
 * @param {string} [defaultValue='']
 * @returns {Promise<string>}
 */
export async function ask(question, defaultValue = '') {
  if (!isInteractive()) return defaultValue;
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    const suffix = defaultValue ? chalk.gray(` (${defaultValue})`) : '';
    const answer = (await rl.question(`${chalk.cyan('?')} ${question}${suffix} `)).trim();
    return answer || defaultValue;
  } catch {
    return defaultValue;
  } finally {
    rl.close();
  }
}
