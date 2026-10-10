#!/usr/bin/env node
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ensureHome, loadConfig, loadToken, writeDefaultConfig } from '../src/config.js';
import { home, usd } from '../src/util.js';
import { Store } from '../src/store.js';
import { Budget } from '../src/budget.js';
import { Approvals } from '../src/approvals.js';
import { createProxy } from '../src/proxy.js';
import { loadPrices } from '../src/pricing.js';
import { scanPath, cloneRepo, VERDICT_TEXT } from '../src/scan.js';
import { attachTerminalApprovals, box, c, LEVEL_COLOR } from '../src/term.js';
import { runDemo } from '../src/demo.js';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));

const HELP = `${c.bold('Chaperone')} ${c.gray(`v${pkg.version}`)}  a guard between your AI agents and the internet

${c.bold('Usage')}
  chaperone start [options]            Start the guard (this is the default)
  chaperone demo                       Watch it stop a misbehaving agent, in about 20 seconds
  chaperone scan <folder|github-url>   Check a skill, plugin or MCP server before you install it
  chaperone status                     Show spend and what is waiting for you
  chaperone kill [reason]              Stop every agent request right now
  chaperone resume                     Let requests through again
  chaperone logs [-n 40]               Show the flight recorder
  chaperone init                       Write a config file you can edit

${c.bold('start options')}
  --port <n>                 Port to listen on (default 8787)
  --daily <usd>              Daily spend cap (default 10, 0 = no cap)
  --monthly <usd>            Monthly spend cap (default 100, 0 = no cap)
  --secrets <redact|block|off>   What to do when a prompt contains a key (default redact)
  --ask <dashboard|terminal|both>   Where to answer approval questions (default both)
  --upstream <url>           OpenAI-compatible provider (default https://api.openai.com)
  --anthropic-upstream <url> Anthropic API (default https://api.anthropic.com)
  --workspace <dir>          Folder your agent may write to (repeatable)

${c.bold('Then point your agent at it')}
  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
  export ANTHROPIC_BASE_URL=http://127.0.0.1:8787

Docs and limits: README.md. Chaperone is a safety net, not a sandbox.
`;

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split('=');
      const next = argv[i + 1];
      const takesValue = !['json', 'auto', 'keep', 'quiet', 'help', 'version'].includes(k);
      const v = inline ?? (takesValue && next !== undefined && !next.startsWith('--') ? argv[++i] : true);
      if (flags[k] !== undefined) flags[k] = [].concat(flags[k], v); else flags[k] = v;
    } else if (a === '-n') { flags.n = argv[++i]; } else if (a === '-h') flags.help = true; else if (a === '-v') flags.version = true;
    else rest.push(a);
  }
  return { flags, rest };
}

const fail = (msg, code = 1) => { console.error(`${c.red('error')} ${msg}`); process.exit(code); };
const num = (v, name) => { const n = Number(v); if (!Number.isFinite(n) || n < 0) fail(`--${name} needs a number`); return n; };

function overridesFrom(flags) {
  const o = {};
  if (flags.port) o.port = num(flags.port, 'port');
  if (flags.daily !== undefined || flags.monthly !== undefined) o.budget = {};
  if (flags.daily !== undefined) o.budget.dailyUSD = num(flags.daily, 'daily');
  if (flags.monthly !== undefined) o.budget.monthlyUSD = num(flags.monthly, 'monthly');
  if (flags.secrets) { if (!['redact', 'block', 'off'].includes(flags.secrets)) fail('--secrets must be redact, block or off'); o.secrets = { mode: flags.secrets }; }
  if (flags.ask) { if (!['dashboard', 'terminal', 'both'].includes(flags.ask)) fail('--ask must be dashboard, terminal or both'); o.ask = flags.ask; }
  if (flags.upstream || flags['anthropic-upstream']) {
    o.upstreams = {};
    if (flags.upstream) o.upstreams.openai = String(flags.upstream).replace(/\/+$/, '');
    if (flags['anthropic-upstream']) o.upstreams.anthropic = String(flags['anthropic-upstream']).replace(/\/+$/, '');
  }
  if (flags.workspace) o.tools = { workspace: [].concat(flags.workspace).map((p) => resolve(String(p))) };
  return o;
}

// ---------------------------------------------------------------- start
async function start(flags) {
  const dir = ensureHome();
  const token = loadToken(dir);
  loadPrices(dir);
  let cfg;
  try { cfg = loadConfig(overridesFrom(flags), dir); } catch (e) { fail(e.message); }
  const store = new Store(dir);
  const budget = new Budget(store, cfg);
  const approvals = new Approvals(store, cfg);
  const proxy = createProxy({ cfg, store, budget, approvals, token });
  let addr;
  try { addr = await proxy.listen(); } catch (e) { fail(e.code === 'EADDRINUSE' ? `Port ${cfg.port} is already in use. Is Chaperone already running? Try --port ${cfg.port + 1}.` : e.message); }

  const origin = `http://${cfg.host}:${addr.port}`;
  const caps = (n, label) => (n > 0 ? `${usd(n)}/${label}` : `no ${label} cap`);
  console.log(`\n${box([
    `${c.bold('Chaperone is watching')}  ${c.cyan(origin)}`,
    '',
    c.bold('Point your agent at it'),
    `  OpenAI-compatible   export OPENAI_BASE_URL=${origin}/v1`,
    `  Anthropic           export ANTHROPIC_BASE_URL=${origin}`,
    '',
    `${c.bold('Dashboard')}  ${c.cyan(`${origin}/_/#t=${token}`)}`,
    '',
    c.gray(`Limits: ${caps(cfg.budget.dailyUSD, 'day')}, ${caps(cfg.budget.monthlyUSD, 'month')}   Secrets: ${cfg.secrets.mode}`),
    c.gray(`Ask first: ${cfg.tools.approve.join(', ') || 'nothing'} risk   Block: ${cfg.tools.block.join(', ') || 'nothing'} risk`),
  ], c.cyan)}`);
  if (cfg.host !== '127.0.0.1') console.log(c.yellow(`warning: listening on ${cfg.host}. Anyone who can reach this port can send requests through your guard.`));
  if (!flags.quiet) console.log(c.gray('\nWaiting for your agent... (Ctrl+C to stop)\n'));

  if (cfg.ask !== 'dashboard') attachTerminalApprovals(approvals);

  const stamp = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false });
  store.on('event', (ev) => {
    if (flags.quiet) return;
    const line = (mark, text) => console.log(`${c.gray(stamp(ev.ts))} ${mark} ${text}`);
    if (ev.type === 'call') line(c.blue('•'), c.gray(ev.summary));
    else if (ev.type === 'redacted') line(c.yellow('◐'), ev.summary);
    else if (ev.type === 'blocked') line(c.red('✖'), ev.summary);
    else if (ev.type === 'tool_call' && ev.decision !== 'allow') line((LEVEL_COLOR[ev.level] || c.gray)('!'), `${ev.tool} is ${ev.level} risk: ${(ev.reasons || []).join('; ')}`);
    else if (ev.type === 'paused') line(c.red('■'), c.bold(ev.summary));
    else if (ev.type === 'resumed') line(c.green('▶'), 'Resumed');
    else if (ev.type === 'budget_warn') line(c.yellow('$'), ev.summary);
    else if (ev.type === 'error' || ev.type === 'upstream_error') line(c.red('!'), ev.summary);
  });

  const stop = async () => { console.log(`\n${c.gray('Stopping Chaperone...')}`); approvals.denyAll('shutdown'); await proxy.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

// ---------------------------------------------------------------- talk to a running instance
async function running(path, method = 'GET', body, flags = {}) {
  const dir = home();
  const file = join(dir, 'token');
  if (!existsSync(file)) fail('Chaperone has not been started on this machine yet. Run "chaperone start".');
  const cfg = loadConfig(overridesFrom(flags), dir);
  const url = `http://127.0.0.1:${cfg.port}/_/api/${path}`;
  try {
    const r = await fetch(url, { method, headers: { 'x-chaperone-token': readFileSync(file, 'utf8').trim(), 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    if (!r.ok) fail(`Chaperone answered HTTP ${r.status}.`);
    return await r.json();
  } catch (e) {
    if (e.name === 'Error' && /Chaperone answered/.test(e.message)) throw e;
    fail(`Chaperone is not running on port ${cfg.port}. Start it with "chaperone start".`);
  }
  return null;
}

async function status(flags) {
  const s = await running('state', 'GET', null, flags);
  const cap = (spent, limit) => (limit > 0 ? `${usd(spent)} of ${usd(limit)}` : `${usd(spent)} (no cap)`);
  console.log(`${s.paused ? c.red('PAUSED') : c.green('WATCHING')}${s.paused ? `  ${s.pausedReason}` : ''}`);
  console.log(`Today       ${cap(s.spend.dayUSD, s.spend.dailyCap)}`);
  console.log(`This month  ${cap(s.spend.monthUSD, s.spend.monthlyCap)}`);
  console.log(`Requests ${s.totals.requests}   Stopped ${s.totals.blocked}   Secrets removed ${s.totals.redactions}   Approvals asked ${s.totals.approvals}`);
  if (s.pending.length) { console.log(c.yellow(`\n${s.pending.length} waiting for you:`)); s.pending.forEach((p) => console.log(`  ${p.id}  ${p.level}  ${p.tool}`)); }
}

async function logs(flags) {
  const dir = home();
  const store = new Store(dir);
  const n = Number(flags.n) || 40;
  const rows = store.readAudit(n);
  if (!rows.length) return console.log('Nothing recorded yet.');
  for (const ev of rows) {
    const t = new Date(ev.ts).toLocaleString([], { hour12: false });
    const tag = ev.type.padEnd(18);
    console.log(`${c.gray(t)}  ${ev.type === 'blocked' || ev.type === 'paused' ? c.red(tag) : ev.type === 'redacted' || ev.type === 'approval_requested' ? c.yellow(tag) : c.gray(tag)}  ${ev.summary || ''}`);
  }
}

// ---------------------------------------------------------------- scan
async function scan(rest, flags) {
  const target = rest[0];
  if (!target) fail('Tell me what to scan: chaperone scan ./my-skill  or  chaperone scan https://github.com/owner/repo');
  let dir = resolve(target);
  let cleanup = () => {};
  if (/^https?:\/\//.test(target)) {
    console.error(c.gray(`Downloading ${target} ...`));
    try { const r = cloneRepo(target); dir = r.dir; cleanup = r.cleanup; } catch (e) { fail(e.message); }
  } else if (!existsSync(dir)) fail(`${target} does not exist.`);
  const report = scanPath(dir);
  cleanup();
  report.root = target;

  if (flags.json) { console.log(JSON.stringify(report, null, 2)); } else {
    const color = { clean: c.green, review: c.yellow, danger: c.red }[report.verdict];
    console.log(`\nScanned ${report.filesScanned} files in ${target}`);
    console.log(`${c.bold('Verdict')}  ${color(report.verdict.toUpperCase())}  ${c.gray(`risk score ${report.score}/100`)}`);
    console.log(`${VERDICT_TEXT[report.verdict]}\n`);
    const L = report.label;
    const yn = (v, bad = true) => (v ? (bad ? c.yellow('yes') : c.green('yes')) : c.green('no'));
    console.log(c.bold('What this could do'));
    const row = (label, v, extra = '') => console.log(`  ${label.padEnd(38)}${v}${extra}`);
    row('Reaches the internet', yn(L.network), report.hosts.length ? c.gray(`  (${report.hosts.slice(0, 6).join(', ')}${report.hosts.length > 6 ? ', ...' : ''})`) : '');
    row('Runs commands on your machine', yn(L.runsCommands));
    row('Touches passwords or keys', yn(L.readsSecrets));
    row('Keeps running after you quit', yn(L.persistence));
    row('Runs when you install it', yn(L.installHooks));
    row('Hides what its code does', yn(L.hidesCode));
    row('Has hidden text or orders for the AI', yn(L.hiddenInstructions || L.hiddenCharacters));
    if (report.findings.length) {
      console.log(`\n${c.bold(`Findings (${report.findings.length})`)}`);
      for (const f of report.findings.slice(0, 25)) {
        const sev = (LEVEL_COLOR[f.severity] || c.gray)(f.severity.toUpperCase().padEnd(8));
        console.log(`  ${sev} ${c.cyan(`${f.file}:${f.line}`)}  ${f.title}`);
        if (f.snippet) console.log(`           ${c.gray(f.snippet)}`);
        console.log(`           ${c.gray(f.why)}`);
      }
      if (report.findings.length > 25) console.log(c.gray(`  ...and ${report.findings.length - 25} more (use --json for all)`));
    }
    console.log(`\n${c.gray('This reads files only; it never runs them. A clean result is not a guarantee.')}`);
  }
  const failOn = flags['fail-on'] || 'danger';
  if (report.verdict === 'danger' || (failOn === 'review' && report.verdict === 'review')) process.exitCode = 2;
}

// ---------------------------------------------------------------- main
const { flags, rest } = parseArgs(process.argv.slice(2));
const cmd = rest[0] || 'start';
if (flags.version) { console.log(pkg.version); process.exit(0); }
if (flags.help || cmd === 'help') { console.log(HELP); process.exit(0); }

try {
  if (cmd === 'start') await start(flags);
  else if (cmd === 'demo') await runDemo({ interactive: !flags.auto && process.stdin.isTTY && process.stdout.isTTY, keepOpen: !!flags.keep });
  else if (cmd === 'scan') await scan(rest.slice(1), flags);
  else if (cmd === 'status') await status(flags);
  else if (cmd === 'kill') { await running('pause', 'POST', { reason: rest.slice(1).join(' ') || 'Stopped from the command line' }, flags); console.log(c.red('Paused. No agent request will get through until you run "chaperone resume".')); }
  else if (cmd === 'resume') { await running('resume', 'POST', null, flags); console.log(c.green('Resumed.')); }
  else if (cmd === 'logs') await logs(flags);
  else if (cmd === 'init') { const r = writeDefaultConfig(); console.log(r.created ? `Wrote ${r.file}. Edit it, then restart Chaperone.` : `${r.file} already exists.`); }
  else { console.log(HELP); process.exit(1); }
} catch (e) {
  fail(e.message);
}
