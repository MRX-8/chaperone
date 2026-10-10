// Finds credentials in text so they can be redacted before a prompt leaves the machine.
// Heuristic by design: it will miss some secrets and occasionally flag harmless text.

const PLACEHOLDER = /^(?:your|my|<|\$\{|\{\{|x{3,}|\*{3,}|\.{3,}|example|changeme|placeholder|redacted|insert|todo|none|null|undefined|process\.env|os\.environ|env\[)/i;

// [type, regex (must use the d flag), capture group to redact (0 = whole match)]
const RULES = [
  ['anthropic_key', /sk-ant-[A-Za-z0-9_-]{20,}/gd, 0],
  ['openai_key', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/gd, 0],
  ['aws_access_key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gd, 0],
  ['aws_secret_key', /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gid, 1],
  ['github_token', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/gd, 0],
  ['slack_token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/gd, 0],
  ['stripe_key', /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/gd, 0],
  ['google_api_key', /\bAIza[0-9A-Za-z_-]{35}\b/gd, 0],
  ['private_key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/gd, 0],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gd, 0],
  ['database_password', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/]+:([^\s@/]{3,})@/gd, 1],
  ['bearer_token', /\bBearer\s+([A-Za-z0-9._~+/=-]{24,})/gd, 1],
  ['password_assignment', /(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']?([^\s"',;]{8,})/gid, 1],
];

export function scanText(text) {
  if (typeof text !== 'string' || text.length < 8 || text.length > 4_000_000) return [];
  const found = [];
  for (const [type, re, group] of RULES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const span = m.indices[group];
      if (!span) continue;
      const value = text.slice(span[0], span[1]);
      if (PLACEHOLDER.test(value)) continue;
      found.push({ type, start: span[0], end: span[1] });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  // Drop overlaps, keeping the earliest and then the longest match.
  found.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let edge = -1;
  for (const f of found) {
    if (f.start >= edge) { out.push(f); edge = f.end; }
  }
  return out;
}

export function redactText(text) {
  const findings = scanText(text);
  if (!findings.length) return { text, findings };
  let out = '';
  let last = 0;
  for (const f of findings) {
    out += text.slice(last, f.start) + `[REDACTED:${f.type}]`;
    last = f.end;
  }
  out += text.slice(last);
  return { text: out, findings };
}

const SKIP_KEYS = new Set(['model', 'role', 'type', 'id', 'tool_call_id', 'tool_use_id', 'name', 'stop_sequences']);

// Redact string values inside the parts of a request body that carry prompt content. Mutates `body`.
export function redactBody(body, keys = ['messages', 'system', 'input', 'prompt', 'contents']) {
  const all = [];
  const walk = (node, parent, key, depth) => {
    if (depth > 8 || node == null) return;
    if (typeof node === 'string') {
      if (SKIP_KEYS.has(key)) return;
      const { text, findings } = redactText(node);
      if (findings.length) { parent[key] = text; all.push(...findings.map((f) => f.type)); }
      return;
    }
    if (Array.isArray(node)) { node.forEach((v, i) => walk(v, node, i, depth + 1)); return; }
    if (typeof node === 'object') for (const k of Object.keys(node)) walk(node[k], node, k, depth + 1);
  };
  for (const k of keys) if (body && body[k] != null) walk(body[k], body, k, 0);
  return all;
}
