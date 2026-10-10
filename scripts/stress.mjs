import { pathToFileURL } from 'node:url';
const H = await import(new URL('../test/helpers.js', import.meta.url).href);
const { startMock, startStack, oaiText, oaiCall, json } = H;
const mock = await startMock((req, res) => { setTimeout(() => json(res, req.json?.messages?.[0]?.content?.includes('tool') ? oaiCall('bash', { command: 'sudo true' }) : oaiText('ok')), Math.random() * 20); });
const s = await startStack(mock, { rate: { perMinute: 100000 }, loop: { repeats: 0, windowSec: 1 }, tools: { approvalTimeoutSec: 3 } });
s.approvals.on('requested', (v) => setTimeout(() => s.approvals.resolve(v.id, true, 'stress'), 5));
const post = (content) => s.post('/v1/chat/completions', { model: 'gpt-4o', messages: [{ role: 'user', content }] });

// 1. 100 parallel requests, a quarter need approval
const t0 = Date.now();
const results = await Promise.all(Array.from({ length: 100 }, (_, i) => post(i % 4 === 0 ? `tool ${i}` : `plain ${i}`).then(async (r) => ({ status: r.status, body: await r.json() }))));
const ok = results.filter((r) => r.status === 200).length;
const withCalls = results.filter((r) => r.body.choices?.[0]?.message?.tool_calls).length;
console.log(`parallel: ${ok}/100 ok, ${withCalls} approved tool calls, ${Date.now() - t0}ms, pending left ${s.approvals.list().length}, requests counted ${s.store.state.totals.requests}`);

// 2. client disconnects while an approval is pending
s.approvals.removeAllListeners('requested');
const ac = new AbortController();
const p = fetch(`${s.base}/v1/chat/completions`, { method: 'POST', signal: ac.signal, headers: { 'content-type': 'application/json', authorization: 'Bearer x' }, body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: 'tool abandoned' }] }) }).catch(() => 'aborted');
await new Promise((r) => setTimeout(r, 300));
const before = s.approvals.list().length;
ac.abort();
await p;
await new Promise((r) => setTimeout(r, 300));
console.log(`abandoned approval: pending before abort ${before}, after abort ${s.approvals.list().length} (should be 0)`);

// 3. big prompt
const big = 'x'.repeat(5_000_000);
const r = await post(big);
console.log(`5MB prompt: HTTP ${r.status}`);
await s.stop(); await mock.close();
