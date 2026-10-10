import { loopHash } from './common.js';

// OpenAI Responses API. Budget, loop and secret protection apply. Tool-call gating does not yet:
// calls are passed through and Chaperone says so in the log.
export const responses = {
  name: 'responses',
  gated: false,

  errorBody: (message, code) => ({ error: { message: `Chaperone: ${message}`, type: 'chaperone_blocked', code } }),
  model: (b) => b.model || 'unknown',
  wantsStream: (b) => b.stream === true,
  loopKey: (b) => loopHash(Array.isArray(b.input) ? b.input : [b.input]),
  estimateInput: (b) => Math.ceil(JSON.stringify(b.input || '').length / 4),
  prepare() {},

  usage(json) {
    const u = (json && json.response && json.response.usage) || (json && json.usage);
    return u ? { input: u.input_tokens || 0, output: u.output_tokens || 0 } : null;
  },
  outputChars() { return 0; },
  calls() { return []; },
  blockJson(json) { return json; },
};
