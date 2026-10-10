import { safeJson } from '../util.js';
import { loopHash, parseArgs } from './common.js';

// OpenAI Chat Completions, and the many services that copy it (OpenRouter, Ollama, Groq, Together, ...).
export const openai = {
  name: 'openai',
  gated: true,

  errorBody: (message, code) => ({ error: { message: `Chaperone: ${message}`, type: 'chaperone_blocked', code } }),
  model: (b) => b.model || 'unknown',
  wantsStream: (b) => b.stream === true,
  loopKey: (b) => loopHash(b.messages),
  estimateInput: (b) => Math.ceil(JSON.stringify(b.messages || '').length / 4),

  prepare(b) {
    if (b.stream === true) b.stream_options = { ...(b.stream_options || {}), include_usage: true };
  },

  usage(json) {
    const u = json && json.usage;
    return u ? { input: u.prompt_tokens || 0, output: u.completion_tokens || 0 } : null;
  },

  outputChars(json) {
    return (json.choices || []).reduce((n, c) => n + String((c.message && c.message.content) || '').length, 0);
  },

  calls(json) {
    const out = [];
    for (const c of json.choices || []) {
      const m = c.message || {};
      for (const tc of m.tool_calls || []) out.push({ id: tc.id, name: tc.function && tc.function.name, args: parseArgs(tc.function && tc.function.arguments) });
      if (m.function_call) out.push({ id: 'fn', name: m.function_call.name, args: parseArgs(m.function_call.arguments) });
    }
    return out;
  },

  blockJson(json, text) {
    for (const c of json.choices || []) {
      if (!c.message) continue;
      delete c.message.tool_calls;
      delete c.message.function_call;
      c.message.content = [c.message.content, text].filter(Boolean).join('\n\n');
      c.finish_reason = 'stop';
    }
    return json;
  },

  createGate({ write, decide }) {
    let buffering = false;
    const buf = [];
    const calls = new Map();
    let base = {};
    let usage = null;
    let chars = 0;
    let done = null;
    const out = (ev) => write(`${ev.raw}\n\n`);

    const collect = (delta) => {
      for (const tc of delta.tool_calls || []) {
        const i = tc.index ?? 0;
        const c = calls.get(i) || { id: '', name: '', args: '' };
        if (tc.id) c.id = tc.id;
        if (tc.function && tc.function.name) c.name += tc.function.name;
        if (tc.function && tc.function.arguments) c.args += tc.function.arguments;
        calls.set(i, c);
      }
      if (delta.function_call) {
        const c = calls.get(0) || { id: 'fn', name: '', args: '' };
        if (delta.function_call.name) c.name += delta.function_call.name;
        if (delta.function_call.arguments) c.args += delta.function_call.arguments;
        calls.set(0, c);
      }
    };

    async function settle() {
      if (!buffering) return;
      buffering = false;
      const list = [...calls.entries()].sort((a, b) => a[0] - b[0]).map(([, c]) => ({ id: c.id, name: c.name, args: parseArgs(c.args) }));
      const verdict = await decide(list);
      if (verdict.allow) {
        buf.forEach(out);
      } else {
        const chunk = (delta, finish) => `data: ${JSON.stringify({ id: base.id || 'chatcmpl-chaperone', object: 'chat.completion.chunk', created: base.created || Math.floor(Date.now() / 1000), model: base.model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
        write(chunk({ role: 'assistant', content: verdict.text }, null));
        write(chunk({}, 'stop'));
        for (const ev of buf) { const o = safeJson(ev.data); if (o && o.usage) write(`${ev.raw}\n\n`); }
      }
      buf.length = 0;
    }

    return {
      get usage() { return usage; },
      get chars() { return chars; },
      async push(ev) {
        if (ev.data === '[DONE]') { await settle(); out(ev); return; }
        const o = ev.data ? safeJson(ev.data) : null;
        if (!o) { if (buffering) buf.push(ev); else out(ev); return; }
        if (o.usage) usage = { input: o.usage.prompt_tokens || 0, output: o.usage.completion_tokens || 0 };
        if (!base.id) base = { id: o.id, model: o.model, created: o.created };
        const delta = o.choices && o.choices[0] && o.choices[0].delta;
        if (delta && typeof delta.content === 'string') chars += delta.content.length;
        if (delta && (delta.tool_calls || delta.function_call)) { buffering = true; collect(delta); }
        if (buffering) buf.push(ev); else out(ev);
      },
      async finish() { done = true; await settle(); return done; },
    };
  },
};
