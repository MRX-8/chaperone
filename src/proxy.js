import http from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';

import { openai } from './providers/openai.js';
import { anthropic } from './providers/anthropic.js';
import { responses } from './providers/responses.js';
import { parseEvent, blockMessage } from './providers/common.js';
import { redactBody, redactText } from './secrets.js';
import { assessToolCall, decide } from './risk.js';
import { costFor } from './pricing.js';
import { RateLimiter, LoopDetector } from './budget.js';
import { safeJson, truncate, usd } from './util.js';

const here = dirname(fileURLToPath(import.meta.url));
const MAX_BODY = 25 * 1024 * 1024;
const SKIP_REQ = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding', 'expect', 'upgrade', 'keep-alive']);
const SKIP_RES = new Set(['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive']);

function detect(url) {
  const p = url.pathname;
  if (/\/messages$/.test(p)) return anthropic;
  if (/\/chat\/completions$/.test(p)) return openai;
  if (/\/responses$/.test(p)) return responses;
  return null;
}

function joinUrl(base, url) {
  const b = new URL(base);
  let basePath = b.pathname.replace(/\/+$/, '');
  let path = url.pathname;
  if (basePath.endsWith('/v1') && path.startsWith('/v1/')) path = path.slice(3);
  return `${b.origin}${basePath}${path}${url.search}`;
}

const isLocalHost = (base) => { try { return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(new URL(base).hostname); } catch { return false; } };

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('request body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const sendJson = (res, status, body) => {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store' });
  res.end(text);
};

export function createProxy({ cfg, store, budget, approvals, token }) {
  const rate = new RateLimiter(cfg.rate.perMinute);
  const loops = new LoopDetector(cfg.loop.repeats, cfg.loop.windowSec);
  let dashboard = '';
  try { dashboard = readFileSync(join(here, 'dashboard.html'), 'utf8'); } catch { dashboard = '<h1>Chaperone dashboard file is missing</h1>'; }

  // ---------------------------------------------------------------- guards and decisions
  const deny = (res, provider, status, code, message) => {
    store.bump('blocked');
    sendJson(res, status, (provider || openai).errorBody(message, code));
  };

  const decider = (info, keepalive, signal) => async (calls) => {
    for (const call of calls) {
      const a = assessToolCall(call, cfg);
      const d = decide(a, cfg);
      const shown = redactText(truncate(a.summary, 600)).text;
      store.event('tool_call', { tool: a.tool, level: a.level, decision: d, reasons: a.reasons, summary: shown, provider: info.provider, model: info.model });
      if (d === 'allow') continue;
      if (d === 'block') {
        store.bump('blocked');
        store.event('blocked', { tool: a.tool, level: a.level, reasons: a.reasons, summary: `Blocked ${a.tool}: ${a.reasons.join('; ')}` });
        return { allow: false, text: blockMessage(a, 'blocked this action by policy') };
      }
      const wait = approvals.request({ tool: a.tool, level: a.level, reasons: a.reasons, summary: shown, provider: info.provider, model: info.model }, signal);
      const timer = keepalive ? setInterval(keepalive, 10_000) : null;
      const r = await wait;
      if (timer) clearInterval(timer);
      if (!r.allow) {
        store.bump('blocked');
        store.event('blocked', { tool: a.tool, level: a.level, reasons: a.reasons, summary: `Denied ${a.tool} (${r.by})` });
        return { allow: false, text: blockMessage(a, r.by === 'timeout' ? 'did not get approval in time' : 'was told no by the user') };
      }
    }
    return { allow: true };
  };

  const account = ({ provider, model, usage, inputGuess, chars, local, started, status }) => {
    let input;
    let output;
    let guessed = false;
    if (usage) { input = usage.input; output = usage.output; } else { input = inputGuess; output = Math.ceil(chars / 4); guessed = true; }
    const cost = local ? { usd: 0, estimated: false } : costFor(model, input, output);
    budget.add(cost.usd, { model });
    store.event('call', {
      provider, model, input, output, usd: cost.usd, estimated: guessed || cost.estimated, ms: Date.now() - started, status,
      summary: `${model}: ${input}→${output} tokens, ${local ? 'local model, free' : `${cost.usd < 0.0001 ? '<$0.0001' : '$' + cost.usd.toFixed(4)}${guessed || cost.estimated ? ' (estimated)' : ''}`}`,
    });
  };

  // ---------------------------------------------------------------- proxying
  async function forward(req, res, url) {
    const started = Date.now();
    const provider = detect(url);
    const body = await readBody(req);
    store.bump('requests');

    if (store.state.paused) { store.event('blocked', { summary: 'Request refused: agent is paused', reasons: [store.state.pausedReason] }); return deny(res, provider, 503, 'paused', `This agent is paused. ${store.state.pausedReason || ''} Run "chaperone resume" or use the dashboard to resume.`.trim()); }
    if (!rate.hit()) { store.event('blocked', { summary: `Rate limit of ${cfg.rate.perMinute}/minute reached` }); return deny(res, provider, 429, 'rate_limit', `Too many requests (limit ${cfg.rate.perMinute} per minute).`); }
    const cap = budget.check();
    if (!cap.ok) { store.event('blocked', { summary: cap.message, reasons: [cap.code] }); return deny(res, provider, 429, cap.code, cap.message); }

    let json = null;
    let outBody = body;
    let model = 'unknown';
    let wantsStream = false;
    let inputGuess = 0;

    if (provider && body.length && /json/.test(req.headers['content-type'] || '')) {
      json = safeJson(body.toString('utf8'));
      if (json) {
        model = provider.model(json);
        wantsStream = provider.wantsStream(json);
        inputGuess = provider.estimateInput(json);

        if (loops.hit(provider.loopKey(json))) {
          store.setPaused(true, `Possible runaway loop: the same step repeated ${cfg.loop.repeats} times in ${Math.round(cfg.loop.windowSec / 60)} minutes.`);
          approvals.denyAll('loop');
          store.bump('blocked');
          return deny(res, provider, 429, 'loop', `Paused: the same step repeated ${cfg.loop.repeats} times. This looks like a runaway loop. Resume from the dashboard once you have checked it.`);
        }

        if (cfg.secrets.mode !== 'off') {
          const found = redactBody(json);
          if (found.length) {
            const kinds = [...new Set(found)].join(', ');
            if (cfg.secrets.mode === 'block') {
              store.event('blocked', { summary: `Refused a prompt containing ${found.length} secret(s): ${kinds}`, reasons: [kinds] });
              return deny(res, provider, 400, 'secret_in_prompt', `The prompt contains ${found.length} secret(s) (${kinds}) and was not sent.`);
            }
            store.bump('redactions', found.length);
            store.event('redacted', { summary: `Removed ${found.length} secret${found.length > 1 ? 's' : ''} from a prompt before it left your machine (${kinds})`, kinds });
          }
        }
        provider.prepare(json);
        outBody = Buffer.from(JSON.stringify(json));
      }
    }

    const base = provider === anthropic ? cfg.upstreams.anthropic : cfg.upstreams.openai;
    const local = cfg.localIsFree !== false && isLocalHost(base);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!SKIP_REQ.has(k)) headers[k] = v;
    headers['accept-encoding'] = 'identity';

    const ac = new AbortController();
    res.on('close', () => { if (!res.writableEnded) ac.abort(); });

    let up;
    try {
      up = await fetch(joinUrl(base, url), { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : outBody, signal: ac.signal });
    } catch (e) {
      if (ac.signal.aborted) return;
      store.event('error', { summary: `Could not reach ${new URL(base).host}: ${e.cause?.code || e.message}` });
      return sendJson(res, 502, (provider || openai).errorBody(`Could not reach the upstream API (${new URL(base).host}).`, 'upstream_unreachable'));
    }

    const outHeaders = {};
    up.headers.forEach((v, k) => { if (!SKIP_RES.has(k)) outHeaders[k] = v; });
    const ctype = up.headers.get('content-type') || '';
    const info = { provider: provider ? provider.name : 'other', model };

    // Errors and anything we do not understand pass straight through.
    if (!provider || !up.ok || (!/event-stream/.test(ctype) && !/json/.test(ctype))) {
      const buf = Buffer.from(await up.arrayBuffer());
      res.writeHead(up.status, { ...outHeaders, 'content-length': buf.length });
      res.end(buf);
      if (provider && !up.ok) store.event('upstream_error', { summary: `${info.provider} returned HTTP ${up.status}`, status: up.status });
      return;
    }

    // Streaming
    if (/event-stream/.test(ctype)) {
      res.writeHead(up.status, outHeaders);
      const keepalive = () => { if (!res.writableEnded) res.write(': chaperone is waiting for your approval\n\n'); };
      const gate = provider.gated ? provider.createGate({ write: (s) => res.write(s), decide: decider(info, keepalive, ac.signal) }) : null;
      let usage = null;
      let chars = 0;
      const decoder = new TextDecoder();
      let text = '';
      try {
        for await (const chunk of up.body) {
          text += decoder.decode(chunk, { stream: true }).replace(/\r\n/g, '\n');
          let i;
          while ((i = text.indexOf('\n\n')) !== -1) {
            const raw = text.slice(0, i);
            text = text.slice(i + 2);
            if (!raw.trim()) continue;
            const ev = parseEvent(raw);
            if (gate) await gate.push(ev);
            else {
              res.write(`${raw}\n\n`);
              const o = safeJson(ev.data);
              if (o) usage = provider.usage(o) || usage;
            }
          }
        }
        if (text.trim()) { const ev = parseEvent(text); if (gate) await gate.push(ev); else res.write(`${text}\n\n`); }
        if (gate) { await gate.finish(); usage = gate.usage; chars = gate.chars; }
      } catch (e) {
        if (!ac.signal.aborted) store.event('error', { summary: `Stream error: ${e.message}` });
      }
      res.end();
      account({ provider: info.provider, model, usage, inputGuess, chars, local, started, status: up.status });
      return;
    }

    // Plain JSON
    const text = await up.text();
    let out = safeJson(text);
    if (!out) { res.writeHead(up.status, { ...outHeaders, 'content-length': Buffer.byteLength(text) }); res.end(text); return; }
    const calls = provider.gated ? provider.calls(out) : [];
    if (calls.length) {
      const verdict = await decider(info, null, ac.signal)(calls);
      if (!verdict.allow) out = provider.blockJson(out, verdict.text);
    } else if (!provider.gated) {
      store.event('note', { summary: 'Responses API: spend, loop and secret protection active; tool-call approval is not available for this API yet.' });
    }
    const final = JSON.stringify(out);
    res.writeHead(up.status, { ...outHeaders, 'content-length': Buffer.byteLength(final) });
    res.end(final);
    account({ provider: info.provider, model, usage: provider.usage(out), inputGuess, chars: provider.outputChars(out), local, started, status: up.status });
  }

  // ---------------------------------------------------------------- control API and dashboard
  const tokenOk = (t) => {
    if (!t) return false;
    const a = Buffer.from(String(t));
    const b = Buffer.from(token);
    return a.length === b.length && timingSafeEqual(a, b);
  };

  const snapshot = () => ({
    paused: store.state.paused,
    pausedReason: store.state.pausedReason,
    spend: budget.snapshot(),
    totals: store.state.totals,
    pending: approvals.list(),
    recent: store.recent.slice(-120),
    policy: { approve: cfg.tools.approve, block: cfg.tools.block, secrets: cfg.secrets.mode, rate: cfg.rate.perMinute, loop: cfg.loop.repeats, approvalTimeoutSec: cfg.tools.approvalTimeoutSec },
    now: Date.now(),
  });

  async function control(req, res, url) {
    if (req.method === 'GET' && (url.pathname === '/_/' || url.pathname === '/_')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'", 'x-frame-options': 'DENY' });
      return res.end(dashboard);
    }
    const t = req.headers['x-chaperone-token'] || url.searchParams.get('t');
    if (!tokenOk(t)) return sendJson(res, 401, { error: 'Missing or wrong token. Open the dashboard link printed by "chaperone start".' });

    const origin = req.headers.origin;
    if (req.method === 'POST' && origin && !/^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(origin)) return sendJson(res, 403, { error: 'Cross-site request refused.' });

    if (req.method === 'GET' && url.pathname === '/_/api/state') return sendJson(res, 200, snapshot());

    if (req.method === 'GET' && url.pathname === '/_/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      res.write('retry: 2000\n\n');
      const push = (ev) => res.write(`data: ${JSON.stringify(ev)}\n\n`);
      store.on('event', push);
      const beat = setInterval(() => res.write(': ping\n\n'), 15_000);
      res.on('close', () => { store.off('event', push); clearInterval(beat); });
      return undefined;
    }

    if (req.method === 'POST' && url.pathname === '/_/api/pause') {
      const b = safeJson((await readBody(req)).toString('utf8')) || {};
      store.setPaused(true, b.reason || 'Paused from the dashboard');
      approvals.denyAll('kill-switch');
      return sendJson(res, 200, snapshot());
    }
    if (req.method === 'POST' && url.pathname === '/_/api/resume') {
      loops.reset();
      store.setPaused(false);
      return sendJson(res, 200, snapshot());
    }
    const m = url.pathname.match(/^\/_\/api\/approvals\/([a-f0-9]+)\/(allow|deny)$/);
    if (req.method === 'POST' && m) {
      const ok = approvals.resolve(m[1], m[2] === 'allow', 'dashboard');
      return sendJson(res, ok ? 200 : 404, ok ? snapshot() : { error: 'That approval is no longer pending.' });
    }
    if (req.method === 'POST' && url.pathname === '/_/api/budget') {
      const b = safeJson((await readBody(req)).toString('utf8')) || {};
      if (Number.isFinite(b.dailyUSD) && b.dailyUSD >= 0) cfg.budget.dailyUSD = b.dailyUSD;
      if (Number.isFinite(b.monthlyUSD) && b.monthlyUSD >= 0) cfg.budget.monthlyUSD = b.monthlyUSD;
      store.event('config', { summary: `Budget set to ${usd(cfg.budget.dailyUSD)}/day and ${usd(cfg.budget.monthlyUSD)}/month` });
      return sendJson(res, 200, snapshot());
    }
    return sendJson(res, 404, { error: 'Not found' });
  }

  // ---------------------------------------------------------------- server
  const allowedHosts = new Set(['127.0.0.1', 'localhost', '[::1]', ...(cfg.allowedHosts || [])]);

  const server = http.createServer(async (req, res) => {
    try {
      const host = String(req.headers.host || '').replace(/:\d+$/, '');
      if (!allowedHosts.has(host)) return sendJson(res, 403, { error: 'Unexpected Host header.' });
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/_' || url.pathname.startsWith('/_/')) return await control(req, res, url);
      if (url.pathname === '/health') return sendJson(res, 200, { ok: true, paused: store.state.paused });
      return await forward(req, res, url);
    } catch (e) {
      if (!res.headersSent) sendJson(res, e.status || 500, { error: { message: `Chaperone error: ${e.message}` } });
      else res.end();
      store.event('error', { summary: e.message });
    }
  });

  return {
    server,
    listen: (port = cfg.port, host = cfg.host) => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server.address()));
    }),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
