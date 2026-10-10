# What is built, what is verified, what is still on you

## Built and tested (57 automated tests, all passing)

- Local proxy for OpenAI Chat Completions and Anthropic Messages, streaming and non-streaming
- Secret detection and redaction (13 detection rules: cloud keys, tokens, private keys, JWTs, database passwords, password-style assignments)
- Tool-call risk engine (shell, file, network, messaging, money, account deletion) with allow and deny lists
- Approval queue: dashboard, terminal, API; single use; timeout means no; kill switch cancels waiting approvals
- Spend caps, rate limit, loop breaker; a spend estimator with an editable price table
- Streaming rewrite: a blocked tool call becomes a well-formed text reply for both providers
- Audit log with no prompts and no secrets
- Dashboard (live feed, approvals, spend meters, kill switch)
- Skill and plugin scanner with a plain-English permission summary and CI exit code
- `demo`, `status`, `kill`, `resume`, `logs`, `init`
- Landing page, README, launch kit

## Verified by me by running it

- The full test suite
- `chaperone demo` end to end
- A real `chaperone start` against a mock provider, with the dashboard in a browser: I approved one request and denied another and checked what each waiting client received
- The landing page on desktop and a phone-width viewport (no horizontal overflow)

## Not verified. You need to do these

- **Run it against real agents** (Claude Code, an OpenAI-SDK agent, an open-source agent) and real providers. Only mock servers have been used.
- **Publish to npm and create the GitHub repo.** The commands in the README and on the site will not work until you do. I did not publish anything or create any account.
- **Plug in a waitlist endpoint** and your real URLs (`site/index.html` has TODO markers).
- **Check the name** for trademarks and domains. `chaperone-ai` was free on npm; other names were taken.
- **Windows.** Untested.
- **Responses API approval and MCP.** Not built. Stated openly in the README.

## Things I am unsure about

- Whether people will pay. The demand evidence was forum chatter and a lot of it unverified.
- How the rules perform on real agent traffic. Expect false positives; tune `src/risk.js` from real use.
- Price table accuracy. Prices change. Treat spend numbers as estimates.
- Competitive position. OpenClaw already ships exec approvals, and open-source approval gates and enterprise gateways exist. The bet is the cross-agent, outside-the-agent design.
