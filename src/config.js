import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { deepMerge, home } from './util.js';

export const DEFAULTS = {
  port: 8787,
  host: '127.0.0.1',
  upstreams: {
    openai: 'https://api.openai.com',
    anthropic: 'https://api.anthropic.com',
  },
  budget: { dailyUSD: 10, monthlyUSD: 100, warnAt: 0.8 },
  rate: { perMinute: 120 },
  loop: { repeats: 6, windowSec: 300 },
  // redact: replace secrets in outgoing prompts. block: refuse the request. off: do nothing.
  secrets: { mode: 'redact' },
  tools: {
    // risk levels: low, medium, high, critical
    approve: ['high'],
    block: ['critical'],
    approvalTimeoutSec: 90,
    allowTools: [],
    denyTools: [],
    allowCommands: [],
    denyCommands: [],
    workspace: [],
  },
  ask: 'both', // dashboard, terminal, both
  localIsFree: true, // models served from localhost (Ollama, LM Studio) cost nothing
};

export function ensureHome(dir = home()) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function loadToken(dir = home()) {
  ensureHome(dir);
  const file = join(dir, 'token');
  if (existsSync(file)) return readFileSync(file, 'utf8').trim();
  const token = randomBytes(24).toString('hex');
  writeFileSync(file, `${token}\n`, { mode: 0o600 });
  return token;
}

export function loadConfig(overrides = {}, dir = home()) {
  let fromFile = {};
  const file = join(dir, 'config.json');
  if (existsSync(file)) {
    try { fromFile = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { throw new Error(`Could not read ${file}: ${e.message}`); }
  }
  return deepMerge(deepMerge(DEFAULTS, fromFile), overrides);
}

export function writeDefaultConfig(dir = home()) {
  ensureHome(dir);
  const file = join(dir, 'config.json');
  if (existsSync(file)) return { file, created: false };
  writeFileSync(file, `${JSON.stringify(DEFAULTS, null, 2)}\n`);
  return { file, created: true };
}
