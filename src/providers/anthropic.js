import { safeJson } from '../util.js';
import { loopHash, parseArgs } from './common.js';

// Anthropic Messages API.
export const anthropic = {
  name: 'anthropic',
  gated: true,

  errorBody: (message, code) => ({ type: 'error', error: { type: 'rate_limit_error', message: `Chaperone: ${message}`, code } }),
  model: (b) => b.model || 'unknown',
  wantsStream: (b) => b.stream === true,
  loopKey: (b) => loopHash(b.messages),
  estimateInput: (b) => Math.ceil(JSON.stringify([b.system, b.messages]).length / 4),
  prepare() {},

  usage(json) {
    const u = json && json.usage;
    if (!u) return null;
    return { input: (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0), output: u.output_tokens || 0 };
  },

  outputChars(json) {
    return (json.content || []).reduce((n, b) => n + (b.type === 'text' ? String(b.text || '').length : 0), 0);
  },

  calls(json) {
    return (json.content || []).filter((b) => b.type === 'tool_use').map((b) => ({ id: b.id, name: b.name, args: parseArgs(b.input) }));
  },

  blockJson(json, text) {
    const kept = (json.content || []).filter((b) => b.type !== 'tool_use');
    kept.push({ type: 'text', text });
    json.content = kept;
    json.stop_reason = 'end_turn';
    return json;
  },

  createGate({ write, decide }) {
    let buffering = false;
    const buf = [];
    const calls = new Map();
    let firstIndex = null;
    let inTokens = 0;
    let outTokens = 0;
    let chars = 0;
    const out = (ev) => write(`${ev.raw}\n\n`);
    const sse = (event, data) => write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

    async function settle() {
      if (!buffering) return;
      buffering = false;
      const list = [...calls.entries()].sort((a, b) => a[0] - b[0]).map(([, c]) => ({ id: c.id, name: c.name, args: parseArgs(c.json || c.input) }));
      const verdict = await decide(list);
      if (verdict.allow) {
        buf.forEach(out);
      } else {
        const index = firstIndex ?? 0;
        sse('content_block_start', { type: 'content_block_start', index, content_block: { type: 'text', text: '' } });
        sse('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'text_delta', text: verdict.text } });
        sse('content_block_stop', { type: 'content_block_stop', index });
        sse('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: outTokens } });
        sse('message_stop', { type: 'message_stop' });
      }
      buf.length = 0;
    }

    return {
      get usage() { return inTokens || outTokens ? { input: inTokens, output: outTokens } : null; },
      get chars() { return chars; },
      async push(ev) {
        const o = ev.data ? safeJson(ev.data) : null;
        if (!o) { if (buffering) buf.push(ev); else out(ev); return; }
        if (o.type === 'message_start' && o.message && o.message.usage) {
          const u = o.message.usage;
          inTokens = (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0);
          outTokens = u.output_tokens || 0;
        }
        if (o.type === 'message_delta' && o.usage && o.usage.output_tokens != null) outTokens = o.usage.output_tokens;
        if (o.type === 'content_block_delta' && o.delta && o.delta.type === 'text_delta') chars += String(o.delta.text || '').length;
        if (o.type === 'content_block_start' && o.content_block && o.content_block.type === 'tool_use') {
          buffering = true;
          if (firstIndex === null) firstIndex = o.index;
          calls.set(o.index, { id: o.content_block.id, name: o.content_block.name, input: o.content_block.input, json: '' });
        }
        if (buffering) {
          if (o.type === 'content_block_delta' && o.delta && o.delta.type === 'input_json_delta' && calls.has(o.index)) calls.get(o.index).json += o.delta.partial_json || '';
          buf.push(ev);
          if (o.type === 'message_stop') await settle();
          return;
        }
        out(ev);
      },
      async finish() { await settle(); },
    };
  },
};
