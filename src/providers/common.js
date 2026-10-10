import { safeJson, sha } from '../util.js';

// Parses one server-sent event block (the text between blank lines).
export function parseEvent(raw) {
  let event = null;
  const data = [];
  for (const line of raw.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
  }
  return { event, data: data.join('\n'), raw };
}

export function parseArgs(text) {
  if (text == null || text === '') return {};
  if (typeof text === 'object') return text;
  const parsed = safeJson(text);
  return parsed && typeof parsed === 'object' ? parsed : { _raw: String(text) };
}

export const loopHash = (messages) => sha(JSON.stringify((Array.isArray(messages) ? messages : []).slice(-2)));

export const blockMessage = (assessment, why) => {
  const reasons = assessment.reasons.length ? ` ${assessment.reasons.join('; ')}.` : '';
  return `[Chaperone ${why}: the "${assessment.tool}" action was not run (risk: ${assessment.level}).${reasons} Do not retry the same action. Tell the user what you were trying to do and ask them how to proceed.]`;
};
