import { readdirSync, readFileSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import { join, relative, extname, basename, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { analyseShell } from './risk.js';
import { INVISIBLE_RE } from './util.js';

// Reads an agent skill, plugin or MCP server folder and says what it could do to you.
// It reads files as text and never runs anything.
//
// Precision matters more than coverage: a scanner that cries wolf on ordinary code gets ignored.
// So it looks at context. Prose is not code, docs and tests count for less than install scripts,
// and "uses the network" or "runs commands" are facts about a tool, not findings.

const TEXT_EXT = new Set(['.md', '.mdx', '.txt', '.rst', '.json', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.sh', '.bash', '.zsh', '.ps1', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.html', '.rb', '.go', '.rs', '.plist', '.service', '.mdc']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target', 'vendor', 'third_party', 'site-packages', '.tox', 'coverage']);
const SKIP_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Cargo.lock', 'composer.lock', 'Gemfile.lock', 'uv.lock', '.gitignore', '.dockerignore', '.npmignore', '.gitattributes', '.eslintignore', '.prettierignore']);
const MAX_FILE = 1_000_000;
const MAX_FILES = 4000;

const RANK = ['info', 'low', 'medium', 'high', 'critical'];
const rank = (s) => RANK.indexOf(s);
const cap = (s, max) => (rank(s) > rank(max) ? max : s);
const POINTS = { critical: 40, high: 20, medium: 6, low: 1, info: 0 };

// Rules that on their own point at an attack, not just at powerful code.
const SIGNATURES = new Set(['pipe-to-shell', 'shell-from-url', 'iex', 'base64-exec', 'exfil-drop-site', 'protected-archive', 'fake-prereq', 'persistence', 'exfil-instruction', 'invisible-chars', 'reverse-shell', 'install-hook-download', 'shell-critical']);

const AGENT_FACING = /(?:^|\/)(?:SKILL\.md|AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|mcp\.json|\.mcp\.json)$|\.mdc$|(?:^|\/)(?:\.claude|\.cursor|\.windsurf)\/|(?:^|\/)skills?\/[^/]+\/(?:[^/]+\.md|scripts\/.*)$/i;
const TESTY = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|examples?|demos?|docs?|documentation|benchmarks?|samples?|\.github)(?:\/|$)|\.(?:test|spec)\.[a-z]+$/i;
const NOISE_HOSTS = /(?:^|\.)(?:w3\.org|schema\.org|json-schema\.org|localhost|xmlns\.com|apache\.org|opensource\.org|creativecommons\.org|mozilla\.org|wikipedia\.org|readthedocs\.io|shields\.io)$/i;

const HOME_SECRETS = new RegExp([
  String.raw`(?:~|\$HOME|\$\{HOME\}|\/Users\/[^\/\s"']+|\/home\/[^\/\s"']+|\/root)\/\.(?:ssh|aws|gnupg|kube|netrc|npmrc|pypirc|docker\/config\.json|config\/(?:gcloud|gh))\b`,
  String.raw`\bid_(?:rsa|ed25519|ecdsa|dsa)\b`,
  String.raw`\/etc\/(?:shadow|sudoers)\b`,
  String.raw`Library\/Keychains`,
  String.raw`(?:Google\/Chrome|Firefox|BraveSoftware|Microsoft Edge)[^\s"']*(?:Login Data|Cookies|logins\.json|key[34]\.db)`,
].join('|'), 'i');

const NETWORK_VERB = /\b(?:curl|wget|fetch|axios|requests\.(?:get|post|put)|http\.request|https\.request|urlopen|upload|POST|nc\s|socat|scp)\b/i;
const NETWORK_ANY = /\b(?:fetch\s*\(|axios\b|requests\.(?:get|post|put|request|Session)|urllib|http\.request|https\.request|XMLHttpRequest|WebSocket|aiohttp|httpx|urlopen|net\.connect|\bcurl\s|\bwget\s)/;
const COMMAND_ANY = /\b(?:child_process|execSync|spawnSync|spawn\s*\(|subprocess\.|os\.system\s*\(|Runtime\.getRuntime\(\)\.exec|execFile|popen\s*\()/;

// [id, severity, regex, title, why, label, contexts]
// contexts: code (source files), sh (shell and CI scripts), fence (code blocks and `inline code` in docs), prose (docs text)
const RULES = [
  ['pipe-to-shell', 'high', /\b(?:curl|wget|iwr)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i, 'Downloads and runs a script', 'Anything the server sends will run on your machine.', 'runsCommands', ['sh', 'fence', 'code']],
  ['shell-from-url', 'high', /\b(?:ba|z)?sh\s+(?:-c\s+["']?\$\(|<\()\s*(?:curl|wget)/, 'Downloads and runs a script', 'Anything the server sends will run on your machine.', 'runsCommands', ['sh', 'fence', 'code']],
  ['iex', 'high', /\b(?:iex|Invoke-Expression)\b[^\n]*(?:iwr|Invoke-WebRequest|DownloadString|http)|(?:iwr|Invoke-WebRequest|DownloadString)[^\n]*\|\s*(?:iex|Invoke-Expression)/i, 'Downloads and runs PowerShell code', 'Anything the server sends will run on your machine.', 'runsCommands', ['sh', 'fence']],
  ['base64-exec', 'high', /\bbase64\b[^\n]*(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b|(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)\(/i, 'Decodes hidden code and runs it', 'Hiding code in base64 is how malware avoids being read.', 'hidesCode', ['sh', 'fence', 'code']],
  ['exfil-drop-site', 'high', /(?:webhook\.site|requestbin|pipedream\.net|pastebin\.com|paste\.ee|transfer\.sh|interact\.sh|(?<![a-z0-9])oast\.(?:fun|pro|live|site|online|me)\b|burpcollaborator)/i, 'Talks to an anonymous drop-site', 'Legitimate tools rarely send data to anonymous webhooks.', 'network', ['code', 'sh', 'fence', 'prose']],
  ['chat-webhook', 'low', /(?:discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com)/i, 'Posts to a chat webhook', 'Normal for notification features, but check what it sends.', 'network', ['code', 'sh']],
  ['env-dump', 'low', /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|\bprintenv\b/i, 'Collects all your environment variables', 'Environment variables usually hold your API keys.', 'readsSecrets', ['code', 'sh']],
  ['dynamic-code', 'low', /\bnew\s+Function\s*\(|\bpickle\.loads?\(|\bexec\s*\(\s*compile\(|(?<![\w.])eval\s*\(\s*(?:atob|decodeURI|unescape|Buffer)/, 'Runs code it builds at runtime', 'What it does cannot be checked by reading the file.', 'runsCommands', ['code']],
  ['persistence', 'high', /\bcrontab\s+-|launchctl\s+(?:load|bootstrap)|systemctl\s+(?:--user\s+)?enable|Library\/LaunchAgents|authorized_keys|>>?\s*~?\/?\S*\.(?:bashrc|zshrc|profile|bash_profile)\b/, 'Installs itself to keep running or edits your login files', 'Skills should not need to survive a restart.', 'persistence', ['sh', 'fence', 'code']],
  ['reverse-shell', 'high', /\bnc\b[^\n]*\s-e\b|\/dev\/tcp\/|\bbash\s+-i\s+>&/, 'Opens a remote shell', 'Gives someone else a command line on your machine.', 'runsCommands', ['sh', 'fence', 'code']],
  ['obfuscated-blob', 'medium', /[A-Za-z0-9+/]{400,}={0,2}/, 'Contains a long encoded blob', 'Could be hidden code or data.', 'hidesCode', ['code', 'sh']],
  ['hex-escapes', 'medium', /(?:\\x[0-9a-fA-F]{2}){16,}/, 'Contains long hex-escaped text', 'A common way to hide strings from readers.', 'hidesCode', ['code', 'sh']],
  ['injection', 'medium', /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|messages)|disregard\s+(?:the\s+)?(?:system|previous|above)\s+(?:prompt|instructions)|do\s+not\s+(?:tell|inform|mention|reveal|show)\s+(?:this\s+to\s+)?(?:the\s+)?user|without\s+(?:telling|asking|informing|notifying)\s+(?:the\s+)?user|you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)|<\s*\/?\s*system\s*>/i, 'Contains instructions aimed at the AI', 'Text like this can steer your agent without you noticing.', 'hiddenInstructions', ['prose', 'fence']],
  ['exfil-instruction', 'high', /(?:send|post|upload|forward|exfiltrate)\s+(?:the\s+)?(?:contents?|output|results?|files?|keys?|secrets?|tokens?|credentials?|env)[^\n]{0,60}\s+to\s+https?:\/\//i, 'Tells the agent to send data to a URL', 'A direct instruction to move your data off your machine.', 'hiddenInstructions', ['prose', 'fence']],
  ['protected-archive', 'high', /(?:(?:password|passphrase|pass)\s*(?:is|:|=)\s*\S+[^\n]{0,120}\.(?:zip|7z|rar)\b|\.(?:zip|7z|rar)\b[^\n]{0,120}(?:password|passphrase)\s*(?:is|:|=)?\s*\S+)/i, 'Asks you to open a password-protected archive', 'Passwords on downloads are a common way to slip malware past antivirus.', 'runsCommands', ['prose', 'fence']],
];

const FAKE_PREREQ = /(?:prerequisites?|requirements?|setup|before\s+(?:you\s+)?(?:use|using|running))[^\n]{0,80}(?:run|download|install|execute)[^\n]{0,80}(?:curl|wget|iwr|powershell|\.sh\b|\.exe\b|\.pkg\b|\.dmg\b|\.msi\b)/i;

const SHELL_TITLES = {
  rm: 'Deletes files recursively', 'git-force': 'Force-pushes', 'git-reset-hard': 'Discards uncommitted work', 'sql-drop': 'Drops database objects',
  'cloud-destroy': 'Deletes cloud infrastructure', publish: 'Publishes software', 'chmod-777': 'Makes files world-writable', 'system-copy': 'Changes system folders',
  keychain: 'Reads saved passwords', mkfs: 'Formats a disk', 'dd-device': 'Writes to a disk device', 'fork-bomb': 'Is a fork bomb', 'chmod-root': 'Changes permissions on the whole disk',
  'redirect-device': 'Writes to a disk device', exfiltration: 'Could send credentials off this machine', sudo: 'Asks for administrator rights', eval: 'Runs generated code with eval',
};

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
      if (!e.isFile() || SKIP_FILES.has(e.name)) continue;
      const ext = extname(e.name).toLowerCase();
      if (!TEXT_EXT.has(ext) && !['Dockerfile', 'Makefile'].includes(e.name) && ext !== '') continue;
      try { if (statSync(p).size > MAX_FILE) continue; } catch { continue; }
      out.push(p);
    }
  }
  return out;
}

function kindOf(rel, ext) {
  if (['.md', '.mdx', '.txt', '.rst'].includes(ext)) return 'doc';
  if (['.sh', '.bash', '.zsh', '.ps1', '.service', '.plist'].includes(ext) || /^(?:Dockerfile|Makefile)$/.test(basename(rel)) || /(?:^|\/)\.github\/workflows\//.test(rel)) return 'script';
  return 'code';
}

// Which lines of a doc are code (fenced blocks, indented commands, $ prompts) and which are prose.
function docLines(lines) {
  let fenced = false;
  return lines.map((line) => {
    if (/^\s*(```|~~~)/.test(line)) { fenced = !fenced; return { text: '', code: false, prose: '' }; }
    const inline = [...line.matchAll(/`([^`\n]{3,})`/g)].map((m) => m[1]).join('\n');
    const dollar = /^\s*\$\s+\S/.test(line) ? line.replace(/^\s*\$\s+/, '') : '';
    return { text: fenced ? line : [inline, dollar].filter(Boolean).join('\n'), code: fenced || !!inline || !!dollar, prose: fenced ? '' : line };
  });
}

export function scanPath(root) {
  const files = walk(root);
  const findings = [];
  const label = { network: false, runsCommands: false, readsSecrets: false, persistence: false, hidesCode: false, hiddenInstructions: false, installHooks: false, hiddenCharacters: false };
  const hosts = new Set();

  for (const file of files) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const rel = (relative(root, file) || basename(file)).split(sep).join('/');
    const ext = extname(file).toLowerCase();
    const kind = kindOf(rel, ext);
    const agent = AGENT_FACING.test(rel);
    const testy = TESTY.test(rel) && !agent;
    const lines = text.split('\n');
    const fileHasNetwork = NETWORK_ANY.test(text);

    // Docs and tests count for less than the files that actually run.
    const sevFor = (id, sev) => {
      if (id === 'invisible-chars') return sev;
      let s = sev;
      if (kind === 'doc' && !agent) s = cap(s, 'medium');
      if (testy) s = cap(s, 'medium');
      return s;
    };
    const add = (f) => findings.push({ ...f, severity: sevFor(f.id, f.severity) });

    INVISIBLE_RE.lastIndex = 0;
    const inv = text.match(INVISIBLE_RE);
    if (inv && !/\.(?:json|lock)$/.test(rel)) {
      label.hiddenCharacters = true;
      const line = lines.findIndex((l) => { INVISIBLE_RE.lastIndex = 0; return INVISIBLE_RE.test(l); }) + 1;
      add({ file: rel, line, id: 'invisible-chars', severity: 'high', title: `Contains ${inv.length} invisible character${inv.length > 1 ? 's' : ''}`, why: 'Invisible text can hide instructions from you while the AI still reads them.', snippet: '' });
    }

    if (basename(file) === 'package.json') {
      try {
        const pkg = JSON.parse(text);
        for (const k of ['preinstall', 'install', 'postinstall']) {
          const cmd = pkg.scripts && pkg.scripts[k];
          if (!cmd) continue;
          label.installHooks = true;
          if (/\b(?:curl|wget|powershell|base64)\b|node\s+-e|https?:\/\/|\|\s*(?:ba)?sh\b/i.test(cmd)) {
            add({ file: rel, line: 1, id: 'install-hook-download', severity: 'high', title: `Downloads or runs code automatically on ${k}`, why: 'Install scripts run before you can read the code.', snippet: `${k}: ${cmd}`.slice(0, 160) });
          }
        }
      } catch { /* not valid json */ }
    }

    const doc = kind === 'doc' ? docLines(lines) : null;

    lines.forEach((raw, i) => {
      const line = raw.length > 4000 ? raw.slice(0, 4000) : raw;
      const n = i + 1;
      const codeText = doc ? doc[i].text : line;
      const proseText = doc ? doc[i].prose : '';
      const isComment = kind !== 'doc' && /^\s*(?:#|\/\/|\*|<!--)/.test(line);

      for (const m of line.matchAll(/https?:\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/gi)) { if (!NOISE_HOSTS.test(m[1])) hosts.add(m[1].toLowerCase()); }

      if (kind !== 'doc') {
        if (NETWORK_ANY.test(line)) label.network = true;
        if (COMMAND_ANY.test(line)) label.runsCommands = true;
      }

      for (const [id, severity, re, title, why, tag, ctx] of RULES) {
        const target = ctx.includes('prose') && doc ? `${proseText}\n${codeText}` : (doc ? codeText : (isComment ? '' : line));
        const applies = doc
          ? (ctx.includes('fence') && doc[i].code) || (ctx.includes('prose') && proseText)
          : (ctx.includes(kind === 'script' ? 'sh' : 'code') && !isComment) || (id === 'exfil-drop-site');
        if (!applies || !target || !re.test(target)) continue;
        let sev = severity;
        if (id === 'env-dump' && fileHasNetwork) sev = 'medium';
        if (['injection', 'exfil-instruction', 'protected-archive'].includes(id) && !agent && kind === 'doc') sev = cap(sev, 'low');
        if (tag) label[tag] = true;
        add({ file: rel, line: n, id, severity: sev, title, why, snippet: line.trim().slice(0, 140) });
      }

      // The "fake prerequisite" trick matters when an AI will read the instructions.
      if (doc && agent && FAKE_PREREQ.test(line)) {
        label.runsCommands = true;
        add({ file: rel, line: n, id: 'fake-prereq', severity: 'high', title: 'Presents a download or script as a "prerequisite"', why: 'Fake setup steps were the main trick in recent malicious-skill campaigns.', snippet: line.trim().slice(0, 140) });
      }

      // Credentials: touching the places keys live, then reaching the network, is the pattern that matters.
      const secretText = doc ? `${codeText}\n${proseText}` : (isComment ? '' : line);
      if (secretText && HOME_SECRETS.test(secretText)) {
        label.readsSecrets = true;
        const sends = NETWORK_VERB.test(line) || (fileHasNetwork && kind === 'code');
        add({ file: rel, line: n, id: 'secret-paths', severity: sends && !testy && kind !== 'doc' ? 'high' : 'medium', title: 'Refers to credential or key files', why: 'SSH keys and cloud credentials are what attackers want.', snippet: line.trim().slice(0, 140) });
      }

      // Shell lines: scripts, and code blocks in docs.
      const shellText = kind === 'script' ? (isComment ? '' : line) : (doc && doc[i].code ? codeText : '');
      if (shellText && /\b(?:rm|dd|mkfs|git|sudo|chmod|chown|curl|wget|ssh|scp|eval|security|kubectl|terraform|aws|gcloud|docker|npm|printenv|cat)\b/.test(shellText)) {
        for (const piece of shellText.split('\n')) {
          const a = analyseShell(piece);
          if (a.level !== 'critical' && a.level !== 'high') continue;
          const ruleIds = a.rules.filter((r) => !['reads-secrets', 'network', 'remote-access', 'pipe-to-shell', 'shell-from-url', 'base64-exec', 'persistence', 'reverse-shell', 'iex'].includes(r));
          if (!ruleIds.length) continue;
          const id = ruleIds[0];
          const critical = a.level === 'critical';
          const agentOrScript = agent || kind === 'script';
          const sev = critical ? 'high' : agentOrScript ? 'medium' : 'low';
          if (critical) label.runsCommands = true;
          add({ file: rel, line: n, id: critical ? 'shell-critical' : `shell:${id}`, severity: sev, title: `Shell command: ${SHELL_TITLES[id] || a.reasons[0]}`, why: 'Reading this line as a command, it is risky.', snippet: piece.trim().slice(0, 140) });
        }
      }
    });
  }

  if (hosts.size) label.network = true;

  const seen = new Set();
  const unique = findings.filter((f) => { const k = `${f.file}:${f.line}:${f.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  unique.sort((a, b) => rank(b.severity) - rank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  // Score by distinct kinds of finding, so one noisy pattern repeated a hundred times cannot bury the page.
  const byId = new Map();
  for (const f of unique) { const e = byId.get(f.id) || { sev: f.severity, n: 0 }; e.n += 1; if (rank(f.severity) > rank(e.sev)) e.sev = f.severity; byId.set(f.id, e); }
  let score = 0;
  let signatures = 0;
  for (const [id, e] of byId) {
    score += POINTS[e.sev] + Math.min(e.n - 1, 3) * (e.sev === 'low' ? 0 : 1);
    if (SIGNATURES.has(id) && rank(e.sev) >= rank('high')) signatures += 1;
  }
  score = Math.min(100, score);
  const worst = unique.length ? unique[0].severity : 'info';
  const verdict = worst === 'critical' || signatures >= 2 || score >= 70 ? 'danger' : worst === 'high' || score >= 25 ? 'review' : 'clean';

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
