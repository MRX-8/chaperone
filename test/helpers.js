import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULTS } from '../src/config.js';
import { deepMerge } from '../src/util.js';
import { Store } from '../src/store.js';
import { Budget } from '../src/budget.js';
import { Approvals } from '../src/approvals.js';
import { createProxy } from '../src/proxy.js';
import { loadPrices } from '../src/pricing.js';

export const TOKEN = 'test-token-0123456789';

export function startMock(handler) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const rec = { method: req.method, url: req.url, headers: req.headers, body, json: (() => { try { return JSON.parse(body); } catch { return null; } })() };
      seen.push(rec);
      handler(rec, res);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `http://127.0.0.1:${server.address().port}`,
    seen,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  })));
}

export async function startStack(mock, overrides = {}) {
  loadPrices('/nonexistent');
  const dir = mkdtempSync(join(tmpdir(), 'chaperone-test-'));
  const cfg = deepMerge(DEFAULTS, {
    upstreams: { openai: mock.url, anthropic: mock.url },
    localIsFree: false,
    tools: { approvalTimeoutSec: 5 },
    ...overrides,
  });
  const store = new Store(dir);
  const budget = new Budget(store, cfg);
  const approvals = new Approvals(store, cfg);
  const proxy = createProxy({ cfg, store, budget, approvals, token: TOKEN });
  const addr = await proxy.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${addr.port}`;
  return {
    base, cfg, store, budget, approvals, dir,
    async stop() { await proxy.close(); rmSync(dir, { recursive: true, force: true }); },
    post: (path, body, headers = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer sk-test', ...headers }, body: JSON.stringify(body) }),
    api: (path, method = 'GET', body) => fetch(`${base}/_/api/${path}`, { method, headers: { 'x-chaperone-token': TOKEN, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }),
  };
}

// ---------------------------------------------------------------- response builders
export const sse = (items) => items.map((i) => (i === '[DONE]' ? 'data: [DONE]\n\n' : i.event ? `event: ${i.event}\ndata: ${JSON.stringify(i.data)}\n\n` : `data: ${JSON.stringify(i)}\n\n`)).join('');

export const oaiText = (text, usage = { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 }) => ({
  id: 'chatcmpl-1', object: 'chat.completion', created: 1, model: 'gpt-4o',
  choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }], usage,
});

export const oaiCall = (name, args, usage = { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 }) => ({
  id: 'chatcmpl-2', object: 'chat.completion', created: 1, model: 'gpt-4o',
  choices: [{ index: 0, message: { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name, arguments: JSON.stringify(args) } }] }, finish_reason: 'tool_calls' }], usage,
});

const chunk = (delta, finish = null) => ({ id: 'chatcmpl-3', object: 'chat.completion.chunk', created: 1, model: 'gpt-4o', choices: [{ index: 0, delta, finish_reason: finish }] });

export const oaiStreamText = (parts) => sse([
  chunk({ role: 'assistant', content: '' }),
  ...parts.map((p) => chunk({ content: p })),
  chunk({}, 'stop'),
  { id: 'chatcmpl-3', object: 'chat.completion.chunk', created: 1, model: 'gpt-4o', choices: [], usage: { prompt_tokens: 50, completion_tokens: 10, total_tokens: 60 } },
  '[DONE]',
]);

export const oaiStreamCall = (name, args) => {
  const json = JSON.stringify(args);
  const mid = Math.floor(json.length / 2);
  return sse([
    chunk({ role: 'assistant', content: null, tool_calls: [{ index: 0, id: 'call_9', type: 'function', function: { name, arguments: '' } }] }),
    chunk({ tool_calls: [{ index: 0, function: { arguments: json.slice(0, mid) } }] }),
    chunk({ tool_calls: [{ index: 0, function: { arguments: json.slice(mid) } }] }),
    chunk({}, 'tool_calls'),
    { id: 'chatcmpl-3', object: 'chat.completion.chunk', created: 1, model: 'gpt-4o', choices: [], usage: { prompt_tokens: 60, completion_tokens: 15, total_tokens: 75 } },
    '[DONE]',
  ]);
};

export const antText = (text) => ({ id: 'msg_1', type: 'message', role: 'assistant', model: 'claude-sonnet-4', content: [{ type: 'text', text }], stop_reason: 'end_turn', usage: { input_tokens: 200, output_tokens: 40 } });
export const antCall = (name, input) => ({ id: 'msg_2', type: 'message', role: 'assistant', model: 'claude-sonnet-4', content: [{ type: 'text', text: 'Running it.' }, { type: 'tool_use', id: 'toolu_1', name, input }], stop_reason: 'tool_use', usage: { input_tokens: 200, output_tokens: 40 } });

export const antStream = (name, input) => {
  const json = JSON.stringify(input);
  const mid = Math.floor(json.length / 2);
  return sse([
    { event: 'message_start', data: { type: 'message_start', message: { id: 'msg_3', type: 'message', role: 'assistant', model: 'claude-sonnet-4', content: [], usage: { input_tokens: 300, output_tokens: 1 } } } },
    { event: 'content_block_start', data: { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } } },
    { event: 'content_block_delta', data: { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'On it.' } } },
    { event: 'content_block_stop', data: { type: 'content_block_stop', index: 0 } },
    { event: 'content_block_start', data: { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 'toolu_9', name, input: {} } } },
    { event: 'content_block_delta', data: { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(0, mid) } } },
    { event: 'content_block_delta', data: { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(mid) } } },
    { event: 'content_block_stop', data: { type: 'content_block_stop', index: 1 } },
    { event: 'message_delta', data: { type: 'message_delta', delta: { stop_reason: 'tool_use', stop_sequence: null }, usage: { output_tokens: 60 } } },
    { event: 'message_stop', data: { type: 'message_stop' } },
  ]);
};

export const antStreamText = (text) => sse([
  { event: 'message_start', data: { type: 'message_start', message: { id: 'msg_4', type: 'message', role: 'assistant', model: 'claude-sonnet-4', content: [], usage: { input_tokens: 100, output_tokens: 1 } } } },
  { event: 'content_block_start', data: { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } } },
  { event: 'content_block_delta', data: { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } } },
  { event: 'content_block_stop', data: { type: 'content_block_stop', index: 0 } },
  { event: 'message_delta', data: { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 12 } } },
  { event: 'message_stop', data: { type: 'message_stop' } },
]);

export const json = (res, body, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
export const stream = (res, text) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end(text); };

export function parseSse(text) {
  return text.split('\n\n').filter((b) => b.trim() && !b.startsWith(':')).map((b) => {
    const event = (b.match(/^event: (.+)$/m) || [])[1] || null;
    const data = (b.match(/^data: (.+)$/m) || [])[1];
    return { event, data: data === '[DONE]' ? '[DONE]' : JSON.parse(data) };
  });
}

export const until = async (fn, ms = 2000) => {
  const t = Date.now();
  while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 15)); }
  throw new Error('timed out waiting for condition');
};
