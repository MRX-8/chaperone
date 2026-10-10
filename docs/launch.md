# Launch kit

The goal of the first two weeks is **evidence**, not hype: real people running Chaperone with a real agent, and numbers you can show anyone without embarrassment.

## Before you post anything (about one day)

- [ ] **Run it with a real agent.** Do this yourself, then write the results into the README's compatibility note. Do not claim a tool works until you have seen it work. Try at least: Claude Code (`ANTHROPIC_BASE_URL`), an OpenAI SDK script (`OPENAI_BASE_URL`), and one open-source agent you can run locally. Note anything that breaks and fix it.
- [ ] **Reserve the name.** `chaperone-ai` was free on npm when checked (Oct 2026). `chaperone` and several similar names are taken. Check the GitHub org and a domain too. The name is a placeholder: do a trademark search before you invest in the brand.
- [ ] **Create the GitHub repo** and replace `MRX-8` in `site/index.html`.
- [ ] **Publish to npm**: `npm login` then `npm publish --access public`. (Until you do, `npx chaperone-ai ...` will not work. I did not publish it for you.)
- [ ] **Deploy `site/`** to any static host (Cloudflare Pages is free). Set `ENDPOINT` in the page script to a form service (Formspree, Buttondown, a Google Form) and `FALLBACK_EMAIL`.
- [ ] **Record a 20-second screen capture** of `npx chaperone-ai demo` next to the dashboard. This is your most shareable asset.
- [ ] Put your real name and photo on the repo. People trust a person.

## What to measure

Chaperone has no telemetry on purpose, so measure what is public:

| Signal | Where |
|---|---|
| Interest | GitHub stars, site visits |
| Real use | npm weekly downloads, issues opened, people who message you with a bug |
| Demand for the paid product | waitlist signups (ask which agents they run) |
| Depth | number of people who ran it with a real agent for 3+ days |

**Suggested 14-day targets** (my guesses, not benchmarks): 300 stars, 1,000 npm downloads, 50 waitlist emails, 10 people who ran it with a real agent, 3 conversations about team use.

**Decide in advance.** If after 14 days you have far fewer than half of those and no one outside your friends is using it, the market is telling you something. The backup idea from the research (a tool for answering AI-written data-access requests) is the fallback. Do not keep building in silence.

## Show HN

Post on a weekday morning US Eastern. Be present for the first 3 hours.

**Title options**
- `Show HN: Chaperone – a local guard for AI agents (spend caps, secret stripping, approvals)`
- `Show HN: I put a proxy between my AI agent and the internet so it can't rm -rf me`

**Body**

> I run coding agents and I got tired of hoping their built-in settings would save me. Chaperone is a small local proxy you put between any agent and its model API (one base-URL change). It:
>
> - caps daily and monthly spend, and breaks runaway loops
> - strips API keys, tokens and private keys from prompts before they leave your machine
> - reads the tool calls in the model's reply: critical ones (`rm -rf ~`, exfiltrating `~/.aws`) are blocked, high-risk ones (`curl | bash`, force-push, `sudo`) wait for a yes/no in a local dashboard
> - has a kill switch and a local audit log
> - includes `chaperone scan` which reads a skill/plugin/MCP folder and says what it could do (motivated by the 341 malicious ClawHub skills Koi Security found)
>
> It is a separate process on purpose: approval prompts inside an agent can be argued out of by the same agent.
>
> What it is not: a sandbox. It only sees traffic that goes through it, the rules are heuristics, MCP isn't covered yet, and the Responses API gets spend/secret protection but not approval. It's tested against mock providers; I'm looking for people to try it against the agents they really run and tell me what breaks. Node 20+, zero dependencies, MIT.
>
> `npx chaperone-ai demo` shows it stopping a misbehaving agent in about 20 seconds.

**First comment (post it yourself)**
> Design notes: the approval screen shows the raw command, not an LLM summary, so a model can't talk you into approving something by describing it kindly. Approvals are single use. If nobody answers, the answer is no. Streaming tool calls are buffered until complete so they can be judged. Happy to answer anything about how the SSE rewriting works.

Expect these replies and answer honestly: "How is this different from LiteLLM / OpenClaw's exec approvals?" (see README "How it compares"), "Can't the agent just bypass the proxy?" (yes, if it has other network access; say so), "Regex rules are easy to evade" (agreed; it is a net, not a wall; policy packs and sandboxing are complementary).

## X / Bluesky thread

1. My AI agent has my API keys and my files. The only thing between it and `rm -rf ~` was a setting inside the agent. So I built a chaperone. [20s screen capture]
2. It's a local proxy. One URL change and every request your agent makes passes through it.
3. It caps spend and breaks runaway loops. [screenshot of dashboard spend bar]
4. It strips keys from prompts before they leave your machine. [screenshot of "provider saw [REDACTED:aws_access_key]"]
5. It reads the tool calls in the model's reply. Critical = blocked. Risky = held for your yes/no.
6. Why outside the agent: a hijacked agent can be told to change its own settings. A separate process can't be.
7. Also: `chaperone scan` reads a skill before you install it. Koi Security found 341 malicious skills out of 2,857 on ClawHub. [scan screenshot]
8. Open source, MIT, zero dependencies, no telemetry. Honest limits are in the README. `npx chaperone-ai demo` [link]

## Subreddits and forums

Check each community's self-promotion rules first, and lead with the problem, not the product.

- r/ClaudeAI, r/LocalLLaMA, r/selfhosted, r/commandline, r/netsec (read the rules; netsec is strict)
- The Discord or GitHub Discussions of the agents you tested with
- Hacker News "Ask HN: how do you stop your agent from doing something dumb?" threads, as a helpful comment with a link, not a drive-by ad

## After launch

- Reply to every issue within a day. Fix what real users hit.
- Write one honest post-mortem of what the rules caught and missed in your own use. That kind of post travels in security circles.
- Add every false positive and false negative to the test suite.
