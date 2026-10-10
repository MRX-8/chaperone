# Outreach: users and investors

## Part 1: your first 20 users

Real users are worth more than any pitch. Find people who have *already* felt the pain.

**Where to find them**
- X/Bluesky search: `agent bill`, `my agent deleted`, `runaway agent`, `OpenClaw API costs`, `Claude Code rm -rf`, `agent leaked my key`
- GitHub issues in agent repos mentioning cost blow-ups, accidental deletions or leaked keys
- Hacker News and Reddit threads about the Koi Security / ClawHub malicious-skills reports
- Discords for the agents you tested with

**Message (adapt each one, mention their specific post)**

> Saw your post about [the thing that went wrong]. I built a small open-source proxy that sits between an agent and its model API: spend caps, strips keys from prompts, holds risky commands for a yes/no. One base-URL change, no code. Would you try it on [their agent] for a day and tell me what breaks? I'll fix whatever you hit. `npx chaperone-ai demo` shows what it does in 20 seconds. [repo link]

Rules: one person at a time, no copy-paste blasts, no asking for stars. Ask for *feedback*. Offer to help them set it up.

**What to learn from each person**
1. Which agent, which provider, how do they run it?
2. Did it work first time? Where did it get in the way?
3. What did it flag that was wrong? What did it miss?
4. Would they pay for something on top? What exactly (team policies, alerts, audit export)?

## Part 2: investors, honestly

**What really happened at Lagos Life.** Vatar raised $500K at a $10M valuation within about a day of incorporating, nine days after launch ([Techpoint](https://techpoint.africa/news/lagos-life-10m-valuation/), [TechCity](https://www.techcityng.com/lagos-life-game-explained/)). Investors were operator angels the founder could message directly (Flutterwave's CEO, Mono's, Terra's). They paid for millions of users in days plus $170K+ earned or contracted, from a team of co-founders. That is the exception: a Techstars mentor with about 6,000 deals of experience says to plan on 3–6 months and roughly 200 investor conversations ([Techstars](https://www.techstars.com/blog/founder-advice/founders-your-pre-seed-round-probably-won-t-take-1-3-months)).

So the realistic aim is **a first small cheque or a programme place within a few weeks of showing real numbers**, not "immediately".

### Deadlines (checked Oct 9, 2026; confirm each yourself)

| Programme | Terms (reported) | Deadline | Notes |
|---|---|---|---|
| a16z speedrun SR008 | up to $1M, $500K for 10% on a SAFE plus later money ([apply](https://speedrun.a16z.com/apply)) | priority window **Oct 12 – Nov 1**, applications rolling | Likely SF relocation. Solo eligibility not confirmed. |
| Y Combinator W27 | $500K: $125K for 7% plus a $375K uncapped SAFE ([deal](https://www.ycombinator.com/deal)) | **Nov 2, 8pm PT**, decisions by Dec 11 ([apply](https://www.ycombinator.com/apply)) | Needs a US, Canada, Cayman or Singapore company. In-person SF. Its current requests-for-startups list includes AI-native compliance infrastructure and proving you are human. |
| ERA (NYC) | $150K for 6% SAFE | **Nov 2**, starts Jan 11 | Worldwide applicants, in-person. Solo policy unconfirmed. |
| Techstars London / Chicago | $220K ($20K for 5% plus $200K uncapped SAFE) | **Nov 18**, starts Mar 8, 2027 | Solos accepted if they show team support. |
| Hustle Fund | rolling | rolling | Reports "1–2 meetings to a yes" ([site](https://www.hustlefund.vc/)). Has an angel network. |
| Antler | UK £125K for 8.5% (US terms unverified) | rolling | Slowest to cash. |

Many figures above came from secondary summaries. Read each programme's own page before you rely on a number.

**Incorporate first.** Most of these need a company. A Delaware C-corp is the usual route (Vatar incorporated in Delaware four days after launch). Use a service such as Stripe Atlas or Clerky and check current fees yourself.

### Who to message directly

Operator angels reach for what they know. For this product that means **people who run or build AI agents, devtools and security products**: founders and security leads at agent companies, devtools founders with exits, and the authors of the agent-security research you cited. Find them through who writes and speaks about agent security. Send **one** short message each, with a link and a number.

**Template** (fill every bracket with a real number or delete the sentence)

> Hi [name], I'm [you]. I read your [post / talk] on [agent security topic]. I built Chaperone, an open-source local guard that sits between any AI agent and its model API: spend caps, secret stripping, approval for risky actions, kill switch, plus a scanner for skills and MCP servers. Because it runs outside the agent, the agent can't turn it off.
>
> It's [N] days old: [N] GitHub stars, [N] npm installs, [N] people running it with [agents], [N] on the waitlist for a team version. [One true, specific sentence about a user.]
>
> I'm raising a small pre-seed to [what the money does]. Would you take 15 minutes this week? Demo: `npx chaperone-ai demo`. Repo: [link].

**Never** invent traction, name investors who have not committed, or imply an endorsement. A false number ends the conversation and your reputation with it.

### Pitch outline (6 slides)

1. **Problem.** Agents now act with your keys and files. Show the ClawHub number (341 of 2,857) and one real incident from your own testing.
2. **Product.** The 20-second demo as a GIF.
3. **Why outside the agent.** The diagram from the landing page.
4. **Traction.** Only real numbers, dated. Include what users said and what broke.
5. **Why us, why now.** What you built in how many days; agents going mainstream; recent attacks. Be honest about being early.
6. **Plan and ask.** Open-source core, then a paid team layer (shared policies, alerts, audit export). What the money buys in 6 months.

### Questions to expect

- *"OpenClaw already has exec approvals. And LiteLLM has budgets."* True. Approvals inside one agent can be reconfigured by that agent; gateways are built for apps and teams, not for individuals' agents or approval of tool calls. The bet is a cross-agent, agent-independent control point.
- *"Why wouldn't a big security vendor just build this?"* They may, and several are buying agent-security startups. Your edge is being first with developers, open source, and the threat data from scans. Say that this is a hypothesis.
- *"How does it make money?"* Open-source core, paid team features. Say you have not proven willingness to pay yet and show the waitlist.
- *"Why you?"* Be specific about what you shipped and how fast.
