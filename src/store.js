import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { dayKey, monthKey, rid } from './util.js';

// Persistent state (kill switch, spend) plus the audit log (a flight recorder, one JSON object per line).
export class Store extends EventEmitter {
  constructor(dir) {
    super();
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.stateFile = join(dir, 'state.json');
    this.auditFile = join(dir, 'audit.jsonl');
    this.recent = [];
    this.state = {
      paused: false,
      pausedReason: '',
      day: dayKey(),
      dayUSD: 0,
      month: monthKey(),
      monthUSD: 0,
      totals: { requests: 0, blocked: 0, redactions: 0, approvals: 0, denied: 0, usd: 0 },
    };
    if (existsSync(this.stateFile)) {
      try { this.state = { ...this.state, ...JSON.parse(readFileSync(this.stateFile, 'utf8')) }; } catch { /* start fresh */ }
    }
    this.state.totals = { requests: 0, blocked: 0, redactions: 0, approvals: 0, denied: 0, usd: 0, ...this.state.totals };
    this.rollover();
  }

  rollover() {
    const d = dayKey();
    const m = monthKey();
    if (this.state.day !== d) { this.state.day = d; this.state.dayUSD = 0; }
    if (this.state.month !== m) { this.state.month = m; this.state.monthUSD = 0; }
  }

  save() {
    try { writeFileSync(this.stateFile, JSON.stringify(this.state), { mode: 0o600 }); } catch { /* disk full: keep running */ }
  }

  // Record something that happened. Never put prompt text or secrets in here.
  event(type, data = {}) {
    const ev = { id: rid(), ts: Date.now(), type, ...data };
    this.recent.push(ev);
    if (this.recent.length > 300) this.recent.shift();
    try { appendFileSync(this.auditFile, `${JSON.stringify(ev)}\n`, { mode: 0o600 }); } catch { /* ignore */ }
    this.emit('event', ev);
    return ev;
  }

  bump(key, n = 1) {
    this.state.totals[key] = (this.state.totals[key] || 0) + n;
  }

  setPaused(paused, reason = '') {
    this.state.paused = paused;
    this.state.pausedReason = paused ? reason : '';
    this.save();
    this.event(paused ? 'paused' : 'resumed', { summary: paused ? `Paused: ${reason}` : 'Resumed' });
  }

  readAudit(limit = 50) {
    if (!existsSync(this.auditFile)) return [];
    const lines = readFileSync(this.auditFile, 'utf8').trim().split('\n').filter(Boolean);
    return lines.slice(-limit).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }
}
