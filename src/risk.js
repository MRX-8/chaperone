import { escapeInvisible, hasInvisible, strings, truncate } from './util.js';

// Classifies the actions an AI agent is about to take. Rule based and deterministic:
// the model is never asked to judge itself, and the text shown for approval is the raw action.

export const LEVELS = ['low', 'medium', 'high', 'critical'];
const rank = (l) => LEVELS.indexOf(l);
const worse = (a, b) => (rank(b) > rank(a) ? b : a);

export const SENSITIVE_PATH = new RegExp([
  String.raw`(?:^|[\s"'=:(])(?:~|\$HOME|\$\{HOME\}|\/Users\/[^\/\s"']+|\/home\/[^\/\s"']+|\/root)?\/?\.(?:ssh|aws|gnupg|kube|netrc|npmrc|pypirc|docker\/config\.json|config\/(?:gcloud|gh|git\/credentials))(?![\w-])`,
  String.raw`\bid_(?:rsa|ed25519|ecdsa|dsa)\b`,
  String.raw`\/etc\/(?:shadow|sudoers)\b`,
  String.raw`(?<![\w.])\.env(?!\.(?:example|sample|template)\b)(?:\.[a-z]+)?(?![\w-])`,
  String.raw`Library\/Keychains`,
  String.raw`(?:Google\/Chrome|Firefox|BraveSoftware|Microsoft Edge)[^\s"']*(?:Login Data|Cookies|logins\.json|key[34]\.db)`,
].join('|'), 'i');

const ROOTISH = new Set(['/', '/*', '~', '~/', '~/*', '$HOME', '$HOME/', '$HOME/*', '${HOME}', '"$HOME"', '/usr', '/etc', '/var', '/bin', '/sbin', '/lib', '/home', '/Users', '/System', '/boot', '/opt']);
const WIPEISH = new Set(['.', '..', '*', './*', '../*', './', '../']);

function tokenise(segment) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(segment))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

function analyseRm(cmd) {
  const hits = [];
  for (const segment of cmd.split(/&&|\|\||[;\n|]/)) {
    const t = tokenise(segment.trim());
    const at = t.findIndex((x, i) => x === 'rm' && (i === 0 || ['sudo', 'doas', 'command', 'env', 'xargs'].includes(t[i - 1]) || t[i - 1]?.startsWith('-')));
    if (at === -1) continue;
    const args = t.slice(at + 1);
    const flags = args.filter((a) => a.startsWith('-')).join('');
    const targets = args.filter((a) => !a.startsWith('-'));
    const recursive = /(^|-)[a-zA-Z]*[rR]/.test(flags) || flags.includes('--recursive');
    if (!recursive) { hits.push(['medium', 'deletes files']); continue; }
    if (targets.some((x) => ROOTISH.has(x) || ROOTISH.has(x.replace(/\/+$/, '')))) hits.push(['critical', 'recursively deletes your home folder, system folders or the whole disk']);
    else if (targets.some((x) => WIPEISH.has(x))) hits.push(['high', 'recursively wipes the current folder']);
    else hits.push(['high', 'recursively deletes files']);
  }
  return hits;
}

// [id, level, regex, reason]
const SHELL_RULES = [
  ['mkfs', 'critical', /\bmkfs(?:\.\w+)?\b/, 'formats a disk'],
  ['dd-device', 'critical', /\bdd\b[^\n;|&]*\bof=\/dev\//, 'writes directly to a disk device'],
  ['redirect-device', 'critical', />\s*\/dev\/(?:sd|nvme|disk|hd)/, 'writes directly to a disk device'],
  ['fork-bomb', 'critical', /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, 'is a fork bomb'],
  ['chmod-root', 'critical', /\bchmod\b[^\n;|&]*-R[^\n;|&]*\s\/(?:\s|$)/, 'changes permissions on the whole disk'],

  ['pipe-to-shell', 'high', /\b(?:curl|wget|fetch|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|c)?sh\b/i, 'downloads a script and runs it without reading it'],
  ['shell-from-url', 'high', /\b(?:ba|z)?sh\s+(?:-c\s+["']?\$\(|<\()\s*(?:curl|wget)/, 'downloads a script and runs it without reading it'],
  ['iex', 'high', /\b(?:iex|Invoke-Expression)\b/i, 'runs downloaded or generated code'],
  ['base64-exec', 'high', /\bbase64\b[^\n]*(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b/, 'decodes hidden text and runs it'],
  ['eval', 'high', /\beval\s*["'`$(]/, 'runs generated code with eval'],
  ['sudo', 'high', /\bsudo\b/, 'runs with administrator rights'],
  ['git-force', 'high', /\bgit\s+push\b[^\n;|&]*(?:--force\b|--force-with-lease|\s-f\b)/, 'force-pushes and can overwrite shared history'],
  ['git-reset-hard', 'high', /\bgit\s+reset\s+--hard\b/, 'discards uncommitted work'],
  ['git-clean', 'high', /\bgit\s+clean\b[^\n;|&]*-[a-zA-Z]*f/, 'deletes untracked files'],
  ['git-branch-D', 'high', /\bgit\s+branch\b[^\n;|&]*\s-D\b/, 'force-deletes a branch'],
  ['sql-drop', 'high', /\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\b/i, 'drops database objects'],
  ['sql-truncate', 'high', /\bTRUNCATE\s+TABLE\b/i, 'empties a database table'],
  ['sql-delete-all', 'high', /\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)/i, 'deletes every row (no WHERE clause)'],
  ['keychain', 'high', /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b/, 'reads saved passwords from the keychain'],
  ['cloud-destroy', 'high', /\b(?:terraform\s+(?:destroy|apply\s+-auto-approve)|kubectl\s+delete|aws\s+s3\s+(?:rm|rb)|aws\s+ec2\s+terminate-instances|gcloud\b[^\n]*\bdelete|az\b[^\n]*\bdelete|docker\s+system\s+prune|docker\s+run\b[^\n]*--privileged)\b/, 'deletes or changes cloud or container infrastructure'],
  ['persistence', 'high', /\b(?:crontab|launchctl\s+(?:load|bootstrap|enable)|systemctl\s+(?:--user\s+)?enable)\b|(?:>>?|\btee\b(?:\s+-a)?)\s*\S*\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b|authorized_keys/, 'installs something that keeps running or changes login behaviour'],
  ['publish', 'high', /\b(?:npm\s+publish|twine\s+upload|gh\s+release\s+create|docker\s+push)\b/, 'publishes software publicly'],
  ['reverse-shell', 'high', /\bnc\b[^\n]*\s-e\b|\/dev\/tcp\/|\bbash\s+-i\s+>&/, 'opens a remote shell'],
  ['chmod-777', 'high', /\bchmod\b[^\n;|&]*\b777\b/, 'makes files world-writable'],
  ['remote-access', 'high', /(?<![.\w/-])(?:ssh|scp|sftp|rsync)\s/, 'connects to another machine'],
  ['system-copy', 'high', /\b(?:mv|cp)\b[^\n]*\s\/(?:etc|usr|bin|sbin|System|Library)\b/, 'changes system folders'],

  ['install', 'medium', /\b(?:pip3?|pipx)\s+install\b|\buv\s+pip\s+install\b|\b(?:npm|pnpm|yarn)\s+(?:install|i|add)\b|\bbrew\s+install\b|\b(?:apt|apt-get|yum|dnf)\s+install\b|\bcargo\s+install\b|\bgo\s+install\b|\bgem\s+install\b/, 'installs third-party software'],
  ['network', 'medium', /(?<![.\w/-])(?:curl|wget|nc|ncat|socat)(?![\w.-])/, 'makes a network request'],
  ['git-push', 'medium', /\bgit\s+push\b/, 'pushes code to a remote'],
  ['kill', 'medium', /\b(?:kill\s+-9|pkill|killall)\b/, 'force-stops processes'],
  ['chmod', 'medium', /\b(?:chmod|chown)\b/, 'changes file permissions'],
];

const NETWORK_TOOL = /(?<![.\w/-])(?:curl|wget|nc|ncat|socat|scp|rsync|ssh|sftp|ftp)(?![\w.-])|https?:\/\//i;
const ENV_DUMP = /\b(?:printenv|env|set)\b\s*(?:\||>|$)|\bcat\s+\S*\.env\b/;

export function analyseShell(command, cfg = {}) {
  const cmd = String(command);
  let level = 'low';
  const reasons = [];
  const rules = [];
  const add = (l, id, why) => { level = worse(level, l); if (!reasons.includes(why)) reasons.push(why); rules.push(id); };

  for (const [l, why] of analyseRm(cmd)) add(l, 'rm', why);
  for (const [id, l, re, why] of SHELL_RULES) if (re.test(cmd)) add(l, id, why);

  const readsSecrets = SENSITIVE_PATH.test(cmd);
  if (readsSecrets) add('high', 'reads-secrets', 'touches credential or key files');
  if ((readsSecrets || ENV_DUMP.test(cmd)) && NETWORK_TOOL.test(cmd)) add('critical', 'exfiltration', 'could send credentials or secrets off this machine');
  if (hasInvisible(cmd)) add('high', 'invisible-chars', 'contains invisible characters that can hide what it really does');

  const t = cfg.tools || {};
  for (const src of t.denyCommands || []) { try { if (new RegExp(src, 'i').test(cmd)) add('critical', 'deny-list', 'matches your deny list'); } catch { /* bad regex */ } }
  if (rank(level) < rank('critical')) {
    for (const src of t.allowCommands || []) {
      try { if (new RegExp(src, 'i').test(cmd)) { level = 'low'; reasons.length = 0; reasons.push('matches your allow list'); break; } } catch { /* bad regex */ }
    }
  }
  return { level, reasons, rules };
}

const tokens = (name) => String(name).toLowerCase().replace(/([a-z])([A-Z])/g, '$1_$2').split(/[^a-z0-9]+/).filter(Boolean);
const hasAny = (toks, words) => words.some((w) => toks.includes(w));

const SHELL_WORDS = ['bash', 'sh', 'shell', 'zsh', 'powershell', 'terminal', 'cmd', 'command', 'exec', 'execute', 'subprocess'];
const WRITE_WORDS = ['write', 'edit', 'create', 'append', 'patch', 'replace', 'save', 'mkdir', 'touch', 'rename', 'move', 'mv'];
const DELETE_WORDS = ['delete', 'remove', 'rm', 'unlink', 'rmdir', 'trash', 'erase', 'drop', 'truncate', 'wipe', 'destroy'];
const COMMS_VERBS = ['send', 'post', 'publish', 'reply', 'forward', 'share', 'tweet'];
const COMMS_NOUNS = ['email', 'mail', 'message', 'sms', 'dm', 'whatsapp', 'slack', 'tweet', 'text', 'status', 'comment', 'post', 'newsletter'];
const MONEY_WORDS = ['transfer', 'payment', 'pay', 'purchase', 'buy', 'checkout', 'wire', 'withdraw', 'refund', 'charge', 'order', 'subscribe'];
const DESTRUCTIVE_NOUNS = ['account', 'user', 'database', 'db', 'repo', 'repository', 'bucket', 'email', 'emails', 'inbox', 'mailbox', 'workspace', 'project', 'table', 'records', 'calendar', 'drive'];

const EXFIL_HOSTS = /(?:webhook\.site|requestbin|pipedream\.net|pastebin\.com|paste\.ee|transfer\.sh|ngrok(?:-free)?\.(?:io|app|dev)|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com|oast\.|interact\.sh|burpcollaborator)/i;

const pathValues = (args) => {
  const out = [];
  const walk = (o, key, depth) => {
    if (depth > 4 || o == null) return;
    if (typeof o === 'string') { if (/(path|file|filename|filepath|target|dest|destination|src|source|dir|directory|folder)/i.test(key || '')) out.push(o); return; }
    if (Array.isArray(o)) { o.forEach((v) => walk(v, key, depth + 1)); return; }
    if (typeof o === 'object') for (const [k, v] of Object.entries(o)) walk(v, k, depth + 1);
  };
  walk(args, '', 0);
  return out;
};

const expandHome = (p) => p.replace(/^~(?=\/|$)/, '/home/user').replace(/^\$HOME/, '/home/user');
const inWorkspace = (p, roots) => roots.some((r) => { const root = expandHome(r).replace(/\/+$/, ''); const q = expandHome(p); return q === root || q.startsWith(`${root}/`); });

export function describe(name, args) {
  const cmd = commandOf(args);
  const body = cmd !== null ? cmd : JSON.stringify(args ?? {}, null, 2);
  return `${name}: ${escapeInvisible(truncate(body, 4000))}`;
}

function commandOf(args) {
  if (args && typeof args === 'object') {
    for (const k of ['command', 'cmd', 'script', 'shell', 'bash']) if (typeof args[k] === 'string') return args[k];
    if (Array.isArray(args.command)) return args.command.join(' ');
  }
  return null;
}

export function assessToolCall(call, cfg = {}) {
  const name = String(call.name || 'unknown');
  const args = call.args ?? {};
  const t = cfg.tools || {};
  const toks = tokens(name);
  const result = { level: 'low', category: 'unknown', reasons: [], rules: [], tool: name, summary: describe(name, args) };
  const add = (l, cat, why, id) => {
    result.level = worse(result.level, l);
    if (rank(l) >= rank(result.level)) result.category = cat;
    if (!result.reasons.includes(why)) result.reasons.push(why);
    if (id) result.rules.push(id);
  };

  if ((t.allowTools || []).includes(name)) { result.reasons.push('on your allow list'); return result; }
  if ((t.denyTools || []).includes(name)) { add('critical', 'policy', 'on your deny list', 'deny-tool'); return result; }

  // Shell-like: a tool named after a shell or any argument that carries a command.
  const cmd = commandOf(args);
  if (cmd !== null || hasAny(toks, SHELL_WORDS)) {
    const text = cmd !== null ? cmd : [...strings(args)].join('\n');
    const a = analyseShell(text, cfg);
    if (a.level !== 'low' || a.reasons.length) {
      a.reasons.forEach((r) => add(a.level, 'shell', `Command ${r}`, null));
      result.rules.push(...a.rules);
      result.level = worse(result.level, a.level);
      if (a.level === 'low') result.reasons = a.reasons;
    }
    if (result.category === 'unknown') result.category = 'shell';
  }

  // File tools.
  const paths = pathValues(args);
  if (paths.length) {
    const isDelete = hasAny(toks, DELETE_WORDS);
    const isWrite = hasAny(toks, WRITE_WORDS) || isDelete;
    for (const p of paths) {
      const sensitive = SENSITIVE_PATH.test(` ${p}`);
      const system = /^\/(?:etc|usr|bin|sbin|boot|System|Library)(?:\/|$)/.test(p);
      const rc = /\.(?:bashrc|zshrc|profile|bash_profile|zprofile)$|authorized_keys$/.test(p);
      if (isWrite && (rc || /\/etc\//.test(p))) add('critical', 'file', `Writes ${isDelete ? 'over or removes' : 'to'} a startup or system file (${p})`, 'file-system-write');
      else if (sensitive) add(isWrite ? 'critical' : 'high', 'file', `${isWrite ? 'Changes' : 'Reads'} a credential or key file (${p})`, 'file-sensitive');
      else if (isWrite && system) add('high', 'file', `Changes a system folder (${p})`, 'file-system');
      else if (isWrite && (t.workspace || []).length && /^(\/|~|\$HOME)/.test(p) && !inWorkspace(p, t.workspace)) add(isDelete ? 'high' : 'medium', 'file', `${isDelete ? 'Deletes' : 'Writes'} outside your workspace (${p})`, 'file-outside');
      else if (isDelete) add('medium', 'file', `Deletes ${p}`, 'file-delete');
    }
  }

  // Network tools.
  const urls = [...strings(args)].filter((s) => /^https?:\/\//i.test(s));
  if (urls.length) {
    for (const u of urls) {
      let host = '';
      try { host = new URL(u).hostname; } catch { /* ignore */ }
      if (EXFIL_HOSTS.test(u)) add('high', 'network', `Sends data to a drop-site or webhook (${host})`, 'net-exfil-host');
      else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) add('medium', 'network', `Connects to a bare IP address (${host})`, 'net-ip');
    }
    const method = String(args.method || '').toUpperCase();
    if (args.body != null || args.data != null || (method && method !== 'GET' && method !== 'HEAD')) add('medium', 'network', 'Sends data to an external server', 'net-post');
  }

  // Messaging, money and destructive account actions.
  if (hasAny(toks, COMMS_VERBS) && hasAny(toks, COMMS_NOUNS)) add('high', 'comms', 'Sends a message or posts publicly in your name', 'comms');
  else if (toks.includes('tweet')) add('high', 'comms', 'Posts publicly in your name', 'comms');
  if (hasAny(toks, MONEY_WORDS)) add('high', 'money', 'Moves money or makes a purchase', 'money');
  if (hasAny(toks, DELETE_WORDS) && hasAny(toks, DESTRUCTIVE_NOUNS)) add('high', 'data', 'Deletes data or an account', 'delete-data');

  if (hasInvisible(JSON.stringify(args))) add('high', result.category, 'Contains invisible characters that can hide what it really does', 'invisible-chars');

  return result;
}

export function decide(assessment, cfg = {}) {
  const t = cfg.tools || {};
  if ((t.block || []).includes(assessment.level)) return 'block';
  if ((t.approve || []).includes(assessment.level)) return 'ask';
  return 'allow';
}
