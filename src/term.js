import readline from 'node:readline';

const on = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const c = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), green: wrap('32'), yellow: wrap('33'), blue: wrap('34'), cyan: wrap('36'), gray: wrap('90'),
  redBg: wrap('41;97'), amberBg: wrap('43;30'),
};

export const LEVEL_COLOR = { low: c.gray, medium: c.blue, high: c.yellow, critical: c.red };

export function box(lines, color = (s) => s) {
  const width = Math.min(Math.max(...lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').length), 20), 100);
  const bar = '─'.repeat(width + 2);
  return [color(`┌${bar}┐`), ...lines.map((l) => color('│ ') + l + ' '.repeat(Math.max(0, width - l.replace(/\x1b\[[0-9;]*m/g, '').length)) + color(' │')), color(`└${bar}┘`)].join('\n');
}

// Lets you answer approvals in the terminal as well as in the dashboard.
export function attachTerminalApprovals(approvals, { stdin = process.stdin, out = console.log } = {}) {
  if (!stdin.isTTY) return () => {};
  const rl = readline.createInterface({ input: stdin, terminal: false });
  const onRequested = (v) => {
    const lines = [
      `${c.bold('APPROVAL NEEDED')}  ${(LEVEL_COLOR[v.level] || c.gray)(v.level.toUpperCase())}  ${v.tool}`,
      ...v.reasons.map((r) => `  - ${r}`),
      '',
      ...String(v.summary).split('\n').slice(0, 12).map((l) => `  ${c.cyan(l)}`),
      '',
      `${c.bold('Allow once?')} [y/N]  (answer here or in the dashboard, no answer in ${Math.round((v.expiresAt - v.createdAt) / 1000)}s means no)`,
    ];
    out(`\n${box(lines, c.yellow)}`);
  };
  const onResolved = (r) => out(`${r.allow ? c.green('  allowed') : c.red('  denied')} (${r.by})`);
  rl.on('line', (line) => {
    const e = approvals.oldest();
    if (!e) return;
    const a = line.trim().toLowerCase();
    approvals.resolve(e.id, a === 'y' || a === 'yes', 'terminal');
  });
  approvals.on('requested', onRequested);
  approvals.on('resolved', onResolved);
  return () => { approvals.off('requested', onRequested); approvals.off('resolved', onResolved); rl.close(); };
}
