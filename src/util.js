import { createHash, randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const sha = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
export const rid = () => randomBytes(5).toString('hex');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const home = () => process.env.CHAPERONE_HOME || join(homedir(), '.chaperone');

const pad = (n) => String(n).padStart(2, '0');
export const dayKey = (d = new Date()) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
export const monthKey = (d = new Date()) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;

export const usd = (n) => (n < 0.01 && n > 0 ? '<$0.01' : `$${n.toFixed(2)}`);

// Characters that can hide text from a human reviewer: zero-width, bidi controls, soft hyphen.
export const INVISIBLE_RE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿­]/g;
export const hasInvisible = (s) => { INVISIBLE_RE.lastIndex = 0; return INVISIBLE_RE.test(s); };
export const escapeInvisible = (s) => String(s).replace(INVISIBLE_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

export function deepMerge(base, extra) {
  if (!extra || typeof extra !== 'object') return base;
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const [k, v] of Object.entries(extra)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base && typeof base[k] === 'object' && !Array.isArray(base[k])) out[k] = deepMerge(base[k], v);
    else if (v !== undefined) out[k] = v;
  }
  return out;
}

// All string values in a JSON-ish value, with a depth limit.
export function* strings(value, depth = 0) {
  if (depth > 6 || value == null) return;
  if (typeof value === 'string') { yield value; return; }
  if (Array.isArray(value)) { for (const v of value) yield* strings(v, depth + 1); return; }
  if (typeof value === 'object') for (const v of Object.values(value)) yield* strings(v, depth + 1);
}

export function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

export function truncate(s, n = 300) {
  s = String(s);
  return s.length > n ? `${s.slice(0, n)}... (${s.length - n} more chars)` : s;
}
