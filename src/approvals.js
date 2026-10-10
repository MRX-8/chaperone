import { EventEmitter } from 'node:events';
import { rid } from './util.js';

// Holds a risky action until a human says yes or no. Approvals are single use: they are never
// remembered, cached or applied to a later action.
export class Approvals extends EventEmitter {
  constructor(store, cfg) {
    super();
    this.store = store;
    this.cfg = cfg;
    this.pending = new Map();
  }

  request(info) {
    const id = rid();
    const timeoutMs = Math.max(1, this.cfg.tools.approvalTimeoutSec) * 1000;
    return new Promise((resolve) => {
      const entry = { id, createdAt: Date.now(), expiresAt: Date.now() + timeoutMs, ...info };
      const timer = setTimeout(() => this.resolve(id, false, 'timeout'), timeoutMs);
      entry.finish = (allow, by) => { clearTimeout(timer); resolve({ allow, by }); };
      this.pending.set(id, entry);
      this.store.bump('approvals');
      this.store.event('approval_requested', { approvalId: id, level: info.level, tool: info.tool, summary: `Waiting for your approval: ${info.tool} (${info.level} risk)`, command: info.summary, reasons: info.reasons });
      this.emit('requested', this.view(entry));
    });
  }

  resolve(id, allow, by = 'user') {
    const entry = this.pending.get(id);
    if (!entry) return false;
    this.pending.delete(id);
    if (!allow) this.store.bump('denied');
    this.store.event('approval_resolved', { approvalId: id, allow, by, tool: entry.tool, summary: `${allow ? 'Allowed' : 'Denied'} ${entry.tool} (${by === 'timeout' ? 'no answer in time' : by})` });
    entry.finish(allow, by);
    this.emit('resolved', { id, allow, by });
    return true;
  }

  view(e) {
    return { id: e.id, tool: e.tool, level: e.level, reasons: e.reasons, summary: e.summary, createdAt: e.createdAt, expiresAt: e.expiresAt, provider: e.provider, model: e.model };
  }

  list() { return [...this.pending.values()].map((e) => this.view(e)); }

  oldest() { return [...this.pending.values()].sort((a, b) => a.createdAt - b.createdAt)[0]; }

  // Deny everything that is waiting, for example when the kill switch is pulled.
  denyAll(by = 'kill-switch') { for (const id of [...this.pending.keys()]) this.resolve(id, false, by); }
}
