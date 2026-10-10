import { usd } from './util.js';

// Spend caps. The check happens before each request, so one in-flight request can overshoot a cap.
export class Budget {
  constructor(store, cfg) {
    this.store = store;
    this.cfg = cfg;
    this.warned = { day: '', month: '' };
  }

  check() {
    const s = this.store.state;
    this.store.rollover();
    const b = this.cfg.budget;
    if (b.dailyUSD > 0 && s.dayUSD >= b.dailyUSD) {
      return { ok: false, code: 'daily_budget', message: `Daily budget of ${usd(b.dailyUSD)} reached (${usd(s.dayUSD)} spent today).` };
    }
    if (b.monthlyUSD > 0 && s.monthUSD >= b.monthlyUSD) {
      return { ok: false, code: 'monthly_budget', message: `Monthly budget of ${usd(b.monthlyUSD)} reached (${usd(s.monthUSD)} spent this month).` };
    }
    return { ok: true };
  }

  add(cost, meta = {}) {
    const s = this.store.state;
    this.store.rollover();
    s.dayUSD += cost;
    s.monthUSD += cost;
    s.totals.usd += cost;
    const b = this.cfg.budget;
    if (b.dailyUSD > 0 && s.dayUSD >= b.dailyUSD * b.warnAt && this.warned.day !== s.day) {
      this.warned.day = s.day;
      this.store.event('budget_warn', { summary: `You have used ${Math.round((s.dayUSD / b.dailyUSD) * 100)}% of today's ${usd(b.dailyUSD)} budget.`, ...meta });
    }
    this.store.save();
  }

  snapshot() {
    this.store.rollover();
    const s = this.store.state;
    const b = this.cfg.budget;
    return { dayUSD: s.dayUSD, dailyCap: b.dailyUSD, monthUSD: s.monthUSD, monthlyCap: b.monthlyUSD };
  }
}

export class RateLimiter {
  constructor(perMinute) { this.limit = perMinute; this.hits = []; }

  hit(now = Date.now()) {
    if (!this.limit) return true;
    this.hits = this.hits.filter((t) => now - t < 60_000);
    if (this.hits.length >= this.limit) return false;
    this.hits.push(now);
    return true;
  }
}

// Spots a runaway agent: the same step repeating over and over.
export class LoopDetector {
  constructor(repeats, windowSec) { this.repeats = repeats; this.windowMs = windowSec * 1000; this.seen = new Map(); }

  hit(hash, now = Date.now()) {
    if (!this.repeats) return false;
    const list = (this.seen.get(hash) || []).filter((t) => now - t < this.windowMs);
    list.push(now);
    this.seen.set(hash, list);
    if (this.seen.size > 500) for (const [k, v] of this.seen) if (now - v[v.length - 1] > this.windowMs) this.seen.delete(k);
    return list.length >= this.repeats;
  }

  reset() { this.seen.clear(); }
}
