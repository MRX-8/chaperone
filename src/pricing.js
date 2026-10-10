import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// Approximate USD per million tokens [input, output]. Prices change, so treat these as estimates.
// Override or extend them in ~/.chaperone/prices.json, for example { "my-model": [1, 4] }.
const TABLE = [
  ['gpt-5-mini', 0.25, 2], ['gpt-5-nano', 0.05, 0.4], ['gpt-5', 1.25, 10],
  ['gpt-4.1-nano', 0.1, 0.4], ['gpt-4.1-mini', 0.4, 1.6], ['gpt-4.1', 2, 8],
  ['gpt-4o-mini', 0.15, 0.6], ['gpt-4o', 2.5, 10],
  ['o4-mini', 1.1, 4.4], ['o3-mini', 1.1, 4.4], ['o3', 2, 8],
  ['claude-haiku', 1, 5], ['claude-sonnet', 3, 15], ['claude-opus', 5, 25],
  ['gemini-2.5-flash', 0.3, 2.5], ['gemini-2.5-pro', 1.25, 10],
  ['deepseek', 0.28, 0.42],
];
export const FALLBACK = [5, 20];

let overrides = null;
export function loadPrices(dir) {
  overrides = {};
  const file = join(dir, 'prices.json');
  if (existsSync(file)) {
    try { overrides = JSON.parse(readFileSync(file, 'utf8')); } catch { overrides = {}; }
  }
}

export function priceFor(model = '') {
  const m = String(model).toLowerCase();
  if (overrides) {
    const key = Object.keys(overrides).filter((k) => m.startsWith(k.toLowerCase())).sort((a, b) => b.length - a.length)[0];
    if (key) return { rate: overrides[key], estimated: false };
  }
  const hit = TABLE.filter(([p]) => m.includes(p)).sort((a, b) => b[0].length - a[0].length)[0];
  if (hit) return { rate: [hit[1], hit[2]], estimated: false };
  return { rate: FALLBACK, estimated: true };
}

export function costFor(model, inputTokens = 0, outputTokens = 0) {
  const { rate, estimated } = priceFor(model);
  return { usd: (inputTokens * rate[0] + outputTokens * rate[1]) / 1_000_000, estimated };
}
