# Chaperone

**A guard between your AI agents and the internet.** It caps spend, strips leaked keys from prompts, holds dangerous actions for your approval, and records everything. One URL change, no code, **zero dependencies**.

```bash
npx chaperone-ai demo      # watch it stop a misbehaving agent, about 20 seconds
```

Chaperone is a safety net, not a sandbox. Read [what it does not do](#what-it-does-not-do) before you rely on it.

## Why

Agents hold your API keys, your files and sometimes your credit card. The things that go wrong are mundane and expensive:

- a stuck loop retries the same call all night, on your key
- file contents, `.env` lines and tokens are pasted into a prompt that is sent to a third party
- one proposed command is `rm -rf ~`, `git push --force` or `curl ... | bash`
- an add-on you installed was poisoned. Koi Security audited 2,857 ClawHub skills and found 341 malicious ones ([The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html))

Settings inside an agent can be talked out of by that same agent. Chaperone is a **separate process**: the agent cannot switch it off, edit its rules or see its approval queue.

## Quick start

```bash
npx chaperone-ai start --daily 5        # cap spend at $5 a day

# in the terminal where your agent runs:
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

Run your agent as usual. Open the dashboard link Chaperone prints. Your provider key stays in your agent; Chaperone forwards it and never stores it.

Requires Node 20 or newer.

```
 your agent  ──►  Chaperone (127.0.0.1:8787)  ──►  OpenAI / Anthropic / OpenRouter / Ollama ...
                  │  spend cap · loop breaker · rate limit
                  │  strip secrets from the prompt
                  │  read tool calls in the reply  ──►  low: pass
                  │                                     high: wait for you (dashboard or terminal)
                  │                                     critical: block
                  └  flight recorder (local file, no prompt text, no secrets)
```

## What it protects

| Risk | What Chaperone does |
|---|---|
| Runaway spend | Daily and monthly caps. Once reached, the next request is refused. Local models (localhost upstreams) are free and not counted. |
| Runaway loop | The same step repeating N times pauses the agent. Resume from the dashboard or `chaperone resume`. |
| Secrets in prompts | Cloud keys, tokens, private keys, JWTs, database passwords and `password=`-style assignments are replaced with `[REDACTED:type]` before the request leaves your machine (or the request is refused, with `--secrets block`). |
| Dangerous actions | Every tool call in a model reply is rated low, medium, high or critical. Critical is blocked. High waits for your yes or no. Approvals are single use. |
| Hidden text | Zero-width and bidirectional characters in an action are flagged, and shown escaped in the approval prompt. |
| Emergency | `chaperone kill` or the dashboard button stops every request and denies everything waiting. |
| Poisoned add-ons | `chaperone scan <folder or GitHub URL>` reads a skill, plugin or MCP server and says what it could do. It never runs the code. |
| Evidence | An audit log (`~/.chaperone/audit.jsonl`, file mode 600) of every call, block and decision. Prompts and secrets are never written to it. |

What gets rated: shell commands (recursive deletes, pipe-to-shell, `sudo`, force-push, SQL drops, credential files, persistence, cloud teardown, exfiltration), file tools (credential and system paths, writes outside your workspace), network tools (drop-sites and webhooks), and messaging, payment and account-deletion tools. See [`src/risk.js`](src/risk.js).

The text you approve is the **raw action**, not a summary written by the model.

## Commands

```
chaperone start [--port 8787] [--daily 10] [--monthly 100] [--secrets redact|block|off]
                [--ask dashboard|terminal|both] [--upstream URL] [--anthropic-upstream URL]
                [--workspace DIR ...]
chaperone demo
chaperone scan <folder | https://github.com/owner/repo> [--json] [--fail-on review|danger]
chaperone status | kill [reason] | resume | logs [-n 40] | init
```

`scan` exits with code 2 on a dangerous verdict, so it works as a CI check.

### Other providers

Anything that speaks the OpenAI Chat Completions format works with `--upstream`: for example `--upstream https://openrouter.ai/api` or a local server at `http://localhost:11434`.

## Configuration

`chaperone init` writes `~/.chaperone/config.json`. Everything is optional:

```jsonc
{
  "port": 8787,
  "budget": { "dailyUSD": 10, "monthlyUSD": 100, "warnAt": 0.8 },
  "rate": { "perMinute": 120 },
  "loop": { "repeats": 6, "windowSec": 300 },
  "secrets": { "mode": "redact" },          // redact | block | off
  "tools": {
    "approve": ["high"],                    // levels that need your yes
    "block": ["critical"],                  // levels refused outright
    "approvalTimeoutSec": 90,               // no answer means no
    "allowTools": [],                       // tool names always allowed
    "denyTools": [],
    "allowCommands": ["^npm test$"],        // regexes; cannot override critical
    "denyCommands": ["^make deploy"],
    "workspace": ["/Users/me/project"]      // writes outside this get flagged
  },
  "ask": "both"                             // dashboard | terminal | both
}
```

Prices come from a small built-in table. Override or extend in `~/.chaperone/prices.json`, for example `{ "my-model": [1, 4] }` (USD per million input and output tokens).

## What it does not do

Please read this. Security tools that oversell get people hurt.

- **It only sees traffic sent through it.** An agent with direct internet access, or a second API key, can go around it. For hard enforcement, run your agent somewhere its only way out is Chaperone (a container or firewall rule).
- **It judges what the model asks to do, with rules.** They are heuristics. They catch the common destructive and exfiltration patterns, will sometimes flag harmless commands, and will miss a clever sequence of individually harmless steps.
- **It does not limit what an approved command does.** If you allow it, it runs with your permissions.
- **Coverage.** Blocking and approval work for the Chat Completions and Anthropic Messages APIs, streaming and non-streaming. The OpenAI Responses API gets spend, loop and secret protection but **not** tool-call approval yet. **MCP traffic is not covered yet.** For streaming replies, a tool call is buffered until it completes so it can be judged. Only the first choice is gated when `n > 1`.
- **Costs are estimates.** Caps are checked before each request, so one in-flight request can run past a cap.
- **Tested against mock providers.** The suite replays the documented API formats (57 tests). It has not yet been verified against each agent. Expected to work, unverified: Claude Code (`ANTHROPIC_BASE_URL`), OpenAI SDKs and CLIs (`OPENAI_BASE_URL`), Aider, Open WebUI, custom scripts. Please report what breaks.
- **A clean `scan` is not a guarantee.** It reads files for known bad patterns.

## Privacy and security design

- No telemetry, no account, no network calls other than the ones you route through it.
- Binds to `127.0.0.1`. Rejects unexpected `Host` headers (DNS rebinding) and cross-site `Origin`s.
- The dashboard and control API need a random token, stored in `~/.chaperone/token` (mode 600).
- No runtime dependencies, so there is nothing to supply-chain.
- The audit log holds metadata and redacted command text only.

## How it compares

- **Built-in approvals in a single agent** (for example OpenClaw's exec approvals) are good and you should use them. Chaperone adds a layer that works across agents and that the agent cannot reconfigure.
- **LLM gateways** (LiteLLM, Portkey, Helicone and similar) are built for apps and teams: routing, logging, budgets. Chaperone is aimed at the person running agents, with approval of tool calls and secret stripping as the focus.
- **Approval-gate libraries** put approval inside your agent code. Chaperone needs no code changes.

## Roadmap

MCP gateway, tool-call approval for the Responses API, Windows testing, signed policy packs, a shared team dashboard with exportable audit trail.

## Develop

```bash
npm test          # node:test, no dependencies
node bin/chaperone.js demo
```

MIT licence. Not affiliated with OpenAI, Anthropic or OpenClaw.
