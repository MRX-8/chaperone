import { readdirSync, readFileSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { analyseShell, SENSITIVE_PATH } from './risk.js';
import { INVISIBLE_RE } from './util.js';

// Reads an agent skill, plugin or MCP server folder and says what it could do to you.
// It reads files as text and never runs anything.

const TEXT_EXT = new Set(['.md', '.txt', '.json', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.sh', '.bash', '.zsh', '.ps1', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.env', '.html', '.rb', '.go', '.rs', '.plist', '.service', '.mdx', '.lock']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target']);
const MAX_FILE = 1_000_000;
const MAX_FILES = 3000;

const POINTS = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const RANK = ['info', 'low', 'medium', 'high', 'critical'];

// [id, severity, regex, title, why, label]
const RULES = [
  ['pipe-to-shell', 'high', /\b(?:curl|wget|iwr)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i, 'Downloads and runs a script', 'Anything the server sends will run on your machine.', 'runsCommands'],
  ['base64-exec', 'high', /\bbase64\b[^\n]*(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b|(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)\(/i, 'Decodes hidden code and runs it', 'Hiding code in base64 is how malware avoids being read.', 'hidesCode'],
  ['exfil-host', 'high', /(?:webhook\.site|requestbin|pipedream\.net|pastebin\.com|paste\.ee|transfer\.sh|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|interact\.sh|oast\.\w+)/i, 'Talks to a drop-site often used to steal data', 'Legitimate tools rarely send data to anonymous webhooks.', 'network'],
  ['env-dump', 'medium', /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|\bprintenv\b/i, 'Collects all your environment variables', 'Environment variables usually hold your API keys.', 'readsSecrets'],
  ['dynamic-code', 'medium', /\beval\s*\(|\bnew\s+Function\s*\(|\bexec\s*\(\s*(?:compile|["'`])|\bpickle\.loads?\(/, 'Runs code it builds at runtime', 'What it does cannot be checked by reading the file.', 'runsCommands'],
  ['run-commands', 'low', /\b(?:child_process|execSync|spawnSync|spawn\s*\(|subprocess\.(?:run|Popen|call|check_output)|os\.system\s*\(|Runtime\.getRuntime\(\)\.exec)\b/, 'Runs shell commands', 'Fine for developer tools, but it means the code can do anything you can.', 'runsCommands'],
  ['network-call', 'low', /\b(?:fetch\s*\(|axios\b|requests\.(?:get|post|put)|urllib\.request|http\.request|https\.request|XMLHttpRequest|websocket)\b|\b(?:curl|wget)\s/i, 'Makes network requests', 'Check where it sends data.', 'network'],
  ['persistence', 'high', /\bcrontab\b|launchctl\s+(?:load|bootstrap)|systemctl\s+(?:--user\s+)?enable|LaunchAgents|authorized_keys|>>?\s*~?\/?\S*\.(?:bashrc|zshrc|profile|bash_profile)\b/, 'Installs itself to keep running or edits your login files', 'Skills should not need to survive a restart.', 'persistence'],
  ['sudo', 'medium', /\bsudo\b/, 'Asks for administrator rights', 'A skill rarely needs root.', 'runsCommands'],
  ['obfuscated-blob', 'medium', /[A-Za-z0-9+/]{240,}={0,2}/, 'Contains a long encoded blob', 'Could be hidden code or data.', 'hidesCode'],
  ['hex-escapes', 'medium', /(?:\\x[0-9a-fA-F]{2}){14,}/, 'Contains long hex-escaped text', 'A common way to hide strings from readers.', 'hidesCode'],
  ['injection', 'medium', /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|messages)|disregard\s+(?:the\s+)?(?:system|previous|above)|do\s+not\s+(?:tell|inform|mention|reveal|show)\s+(?:this\s+to\s+)?(?:the\s+)?user|without\s+(?:telling|asking|informing|notifying)\s+(?:the\s+)?user|you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)|<\s*\/?\s*system\s*>/i, 'Contains instructions aimed at the AI', 'Text like this can steer your agent without you noticing.', 'hiddenInstructions'],
  ['exfil-instruction', 'high', /(?:send|post|upload|forward|exfiltrate)\s+(?:the\s+)?(?:contents?|output|results?|files?|keys?|secrets?|tokens?|credentials?|env)[^\n]{0,60}\s+to\s+https?:\/\//i, 'Tells the agent to send data to a URL', 'A direct instruction to move your data off your machine.', 'hiddenInstructions'],
  ['protected-archive', 'high', /(?:(?:password|passphrase|pass)\s*(?:is|:|=)\s*\S+[^\n]{0,120}\.(?:zip|7z|rar)\b|\.(?:zip|7z|rar)\b[^\n]{0,120}(?:password|passphrase)\s*(?:is|:|=)?\s*\S+)/i, 'Asks you to open a password-protected archive', 'Passwords on downloads are a common way to slip malware past antivirus.', 'runsCommands'],
  ['fake-prereq', 'high', /(?:prerequisites?|requirements?|setup|before\s+(?:you\s+)?(?:use|using|running))[^\n]{0,80}(?:curl|wget|iwr|powershell|\.sh\b|\.exe\b|\.pkg\b|\.dmg\b)/i, 'Presents a download or script as a "prerequisite"', 'Fake setup steps were the main trick in recent malicious-skill campaigns.', 'runsCommands'],
  ['bare-ip', 'low', /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/, 'Connects to a raw IP address', 'Legitimate services use names.', 'network'],
];

const CODEY = new Set(['.sh', '.bash', '.zsh', '.ps1', '.md', '.mdx', '.txt', '.yml', '.yaml', '.service']);

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop();
    let entries = [];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); continue; }
      if (!e.isFile()) continue;
      const ext = extname(e.name).toLowerCase();
      const special = ['Dockerfile', 'Makefile', 'SKILL', 'skill'].includes(e.name);
      if (!TEXT_EXT.has(ext) && !special && ext !== '') continue;
      try { if (statSync(p).size > MAX_FILE) continue; } catch { continue; }
      out.push(p);
    }
  }
  return out;
}

export function scanPath(root) {
  const files = walk(root);
  const findings = [];
  const label = { network: false, runsCommands: false, readsSecrets: false, persistence: false, hidesCode: false, hiddenInstructions: false, installHooks: false, hiddenCharacters: false };
  const hosts = new Set();

  const add = (f) => findings.push(f);

  for (const file of files) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const rel = relative(root, file) || basename(file);
    const ext = extname(file).toLowerCase();
    const lines = text.split('\n');

    // invisible characters (can hide instructions or flip how code reads)
    INVISIBLE_RE.lastIndex = 0;
    const inv = text.match(INVISIBLE_RE);
    if (inv) {
      label.hiddenCharacters = true;
      const line = lines.findIndex((l) => { INVISIBLE_RE.lastIndex = 0; return INVISIBLE_RE.test(l); }) + 1;
      add({ file: rel, line, id: 'invisible-chars', severity: 'high', title: `Contains ${inv.length} invisible character${inv.length > 1 ? 's' : ''}`, why: 'Invisible text can hide instructions from you while the AI still reads them.', snippet: '' });
    }

    // install hooks
    if (basename(file) === 'package.json') {
      try {
        const pkg = JSON.parse(text);
        for (const k of ['preinstall', 'install', 'postinstall', 'prepare']) {
          const cmd = pkg.scripts && pkg.scripts[k];
          if (!cmd) continue;
          label.installHooks = true;
          const risky = /\b(?:curl|wget|sh|bash|node\s+-e|powershell)\b/i.test(cmd);
          add({ file: rel, line: 1, id: 'install-hook', severity: risky ? 'high' : 'medium', title: `Runs a command automatically on ${k}`, why: 'Install scripts run before you can read the code.', snippet: `${k}: ${cmd}`.slice(0, 160) });
        }
      } catch { /* not valid json */ }
    }

    lines.forEach((raw, i) => {
      const line = raw.length > 4000 ? raw.slice(0, 4000) : raw;
      if (raw.length > 1500 && !['.json', '.lock', '.md', '.txt', '.html'].includes(ext)) {
        add({ file: rel, line: i + 1, id: 'minified', severity: 'low', title: 'Very long single line (possibly minified or packed)', why: 'Hard to review by reading.', snippet: '' });
      }
      for (const [id, severity, re, title, why, tag] of RULES) {
        if (re.test(line)) {
          if (tag) label[tag] = true;
          add({ file: rel, line: i + 1, id, severity, title, why, snippet: line.trim().slice(0, 140) });
        }
      }
      if (SENSITIVE_PATH.test(` ${line}`)) {
        label.readsSecrets = true;
        add({ file: rel, line: i + 1, id: 'secret-paths', severity: 'high', title: 'Refers to credential or key files', why: 'SSH keys, cloud credentials and .env files are what attackers want.', snippet: line.trim().slice(0, 140) });
      }
      if (CODEY.has(ext) && /\b(?:rm|dd|mkfs|git|sudo|chmod|curl|wget|ssh|scp|crontab|eval)\b/.test(line)) {
        const a = analyseShell(line);
        if (a.level === 'critical' || (a.level === 'high' && !findings.some((f) => f.file === rel && f.line === i + 1 && RANK.indexOf(f.severity) >= 3))) {
          label.runsCommands = true;
          add({ file: rel, line: i + 1, id: `shell:${a.rules[0] || 'risky'}`, severity: a.level, title: `Shell command ${a.reasons[0] || 'looks risky'}`, why: 'Reading this line as a command, it is risky.', snippet: line.trim().slice(0, 140) });
        }
      }
      for (const m of line.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/gi)) hosts.add(m[1].toLowerCase());
    });
  }

  if (hosts.size) label.network = true;

  // merge duplicates on the same file/line/id
  const seen = new Set();
  const unique = findings.filter((f) => { const k = `${f.file}:${f.line}:${f.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  unique.sort((a, b) => RANK.indexOf(b.severity) - RANK.indexOf(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  let score = 0;
  const counted = new Map();
  for (const f of unique) {
    const n = (counted.get(f.id) || 0) + 1;
    counted.set(f.id, n);
    if (n <= 3) score += POINTS[f.severity];
  }
  score = Math.min(100, score);
  const worst = unique.length ? unique[0].severity : 'info';
  const verdict = worst === 'critical' || score >= 60 ? 'danger' : worst === 'high' || score >= 20 ? 'review' : 'clean';

  return { root, filesScanned: files.length, findings: unique, score, verdict, label, hosts: [...hosts].sort().slice(0, 25) };
}

export function cloneRepo(url) {
  const m = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(url);
  if (!m) throw new Error('Only plain https://github.com/owner/repo URLs are supported.');
  const dir = mkdtempSync(join(tmpdir(), 'chaperone-scan-'));
  try {
    execFileSync('git', ['clone', '--depth', '1', '--single-branch', '--no-tags', `https://github.com/${m[1]}/${m[2]}.git`, dir], { stdio: 'pipe', timeout: 120_000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`Could not download ${url}: ${String(e.stderr || e.message).trim().split('\n').pop()}`);
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export const VERDICT_TEXT = {
  clean: 'No red flags found. This does not prove it is safe, only that nothing obvious turned up.',
  review: 'Read the flagged lines before you install this.',
  danger: 'Do not install this until you understand every flagged line.',
};
