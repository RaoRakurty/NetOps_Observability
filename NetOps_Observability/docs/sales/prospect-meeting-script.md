# Correlix — First Prospect Meeting Script

> Audience: a network/IT leader who already runs a commercial monitoring
> stack — typically a classic up/down monitoring suite plus an outside-in
> synthetic/path-monitoring SaaS. Goal of the meeting: NOT a sale — a
> 30-day run-alongside pilot. Positioning (agreed 2026-07-06): **"The RCA engine
> for networks that can't leave the building."**

---

## 1. Opening — start with their pain, not our product (2 min)

Don't open with slides. Open with a question:

> "Before I show you anything — think back to your last serious outage.
> How long did it take you to know **whose problem it was**? Was it the
> ISP, the WAN, the firewall, wireless, something in the data center, or
> the app team's side? And how many people were on that bridge call while
> you figured it out?"

Let them answer. Whatever they say, that's your meeting. Then:

> "That gap — between 'something is broken' and 'here's what caused it,
> and here's the evidence' — is the only problem Correlix exists to solve."

## 2. The one-sentence pitch (30 sec)

> "Correlix is a self-hosted network observability platform. It ingests
> everything your network already emits — syslog, SNMP, flows, streaming
> telemetry, wireless, and your AWS and Azure side — correlates it all,
> and when something breaks it doesn't hand you two hundred alerts. It
> hands you **one root cause, with the evidence attached, and it names
> who owns the fix** — the ISP, the WAN, the LAN, or the cloud. It files
> the ticket in ServiceNow or Jira itself and closes it when the issue
> clears. And it runs entirely inside your building. Your data never
> leaves."

Memorable line to land: **"Two hundred alerts. One cause. Evidence attached."**

## 3. Position against what they already run (5 min)

**Rule: never trash their tools. Compliment them, then draw the line
Correlix sits on.** They chose those tools; insulting them insults the buyer.

### Their classic monitoring suite (up/down, thresholds, SNMP polling)

> "Your monitoring suite is genuinely good at telling you **what** is red — up/down,
> interface utilization, thresholds. Where teams struggle is the morning
> a core link degrades and forty downstream things go red at once. Now a
> human has to stare at forty alerts and reverse-engineer the cause.
> That's exactly where Correlix starts: it takes that flood, correlates
> it against the topology and the timeline, and says 'these forty alerts
> are one incident, the root cause is *here*, and here's the log and
> metric evidence.' Your monitoring tells you what. We tell you **why,
> and whose.**"

### Their synthetic / outside-in path monitoring (SaaS)

> "Synthetic path monitoring looks at your network **from the outside
> in** — probes telling you the path across the internet is degraded.
> That's valuable, and we're not here to replace it. Correlix is the
> **inside-out** view: your real devices, real logs, real traffic, real
> config changes. Your probes tell you users in Denver see 300ms to a
> SaaS app. Correlix tells you it's because the primary tunnel flapped
> at 9:42 after a config push on your edge router — with the timeline to
> prove it. Also: those services run in someone else's cloud — your
> telemetry goes somewhere you don't control. Correlix runs on your hardware, in your building,
> air-gapped if you want. For a lot of shops that's not a preference,
> it's a compliance requirement."

### The disarming line (use it early)

> "I'm not asking you to rip anything out. Your routers and switches can
> send syslog and flow exports to more than one place. Point a copy at
> Correlix, run it next to what you have, and let the next real incident
> be the judge. If we don't tell you something your current tools didn't,
> you've lost nothing."

## 4. Three stories to tell (pick per audience, ~2 min each)

**The blame-game story (for ops leaders).**
> "Every network team knows 'mean time to innocence' — proving it wasn't
> the network takes longer than fixing it. Correlix's root-cause view
> draws the actual failure path and puts the cause at a named handoff
> point: this is ISP-side, this is WAN, this is inside your LAN. You
> walk into the war room with evidence, not a hunch. And when we're not
> certain, we say 'possibly because of X' — we'd rather be honest than
> confidently wrong. Ops people learn fast whether a tool lies to them."

**The tool-sprawl story (for budget owners).**
> "Most stacks doing this today are four or five products: a monitor, a
> log tool, a flow analyzer, a dashboard, maybe an AIOps add-on — each
> licensed, each with its own console, none talking to each other.
> Correlix is one install, one URL, one login: discovery, logs, metrics,
> flows, topology, wired *and* wireless, cloud, correlation, and the AI
> assistant in a single pane. One command installs the whole thing on a
> Linux VM. And it doesn't add a queue to your team's day — it opens the
> ticket in your ServiceNow or Jira, deduped, and auto-resolves it when
> the alert clears."

**The AI-without-the-leak story (for security-conscious shops).**
> "Everyone's bolting AI onto network ops, and it all phones home to
> someone's cloud. Correlix's assistant, Iris, works over *your* incident
> data and can run against an LLM you host yourself — so you get the
> 'ask the network a question in plain English' experience without a
> single packet of your incident history leaving the premises."

## 5. Differentiators cheat-sheet (customer language)

| What they hear | What it means for them |
|---|---|
| Root cause, not alert floods | Correlated incidents with a named cause + evidence, not 200 reds |
| Names the owner | ISP vs WAN vs LAN vs cloud — ends the blame game, cuts bridge-call time |
| Runs in your building | On-prem / air-gapped / sovereign. Nothing leaves. (SaaS tools can't say this) |
| One platform, one port | Logs + metrics + flows + topology + wireless + cloud + RCA + AI behind a single URL |
| Hybrid, not just on-prem | AWS + Azure ingestion: flow logs, health, change events correlated with the on-prem side |
| Works with your ITSM | Auto-opens deduped tickets in ServiceNow/Jira, auto-resolves on clear; Slack/PagerDuty/email too |
| Honest AI | Says "possibly caused by X" when uncertain; assistant can use YOUR on-prem LLM |
| 30-minute start | One installer command on a VM; devices just add a second export target |
| Multi-tenant by design | For MSPs: hard isolation per customer, one platform |

## 6. Objection handling

**"We already pay for monitoring tools."**
> "Keep them. This isn't rip-and-replace — it's the correlation layer
> they don't have. Run Correlix alongside for 30 days at no cost; if it
> doesn't shorten your next incident, we shake hands and part friends."

**"Another tool for my team to learn?"**
> "It's one URL, and the point is your team looks at *less*, not more —
> one incident view instead of five consoles. And the assistant means
> junior engineers can ask questions in plain English instead of
> learning a query language."

**"How mature is this? Who else uses it?"** — Be honest; honesty here wins the deal:
> "It's a young product, and that's exactly why this pilot is a good
> deal for you: you get founder-level attention, your feature requests
> actually land, and you pay nothing to find out. And we validate the
> RCA engine the hard way — scripted fault injection, break the network
> on purpose and check the engine named the right cause — not marketing
> claims. Your pilot incidents make that evidence base stronger, which
> is part of why the pilot is free."

**"What about scale / what if it goes down?"**
> "It monitors itself, and we ship an independent external watchdog —
> because a monitoring tool that can't report its own death is a trap.
> For the pilot, scale isn't the question anyway — accuracy on your
> real incidents is. Prove that first, size later."

## 7. The ask — close on the pilot, not the sale (2 min)

> "Here's what I'd like to do. Give me a Linux VM and pick ten or twenty
> devices — a site, a branch, whatever hurts most. One command installs
> the stack; your devices add a second syslog/flow target; nothing about
> your current tooling changes. We run for 30 days. The next time
> something breaks, you put Correlix's incident view next to what your
> current tools showed you, and *you* tell *me* which one you'd rather
> be looking at at 2 a.m. If it's not us, you've spent one VM and an
> hour of config."

Then stop talking. Let them respond.

**Closing line:**
> "Every tool you own tells you *that* something broke. Correlix tells
> you *why*, *whose it is*, and *proves it* — without your data ever
> leaving the building."

---

## Coach's notes — what NOT to say (honesty guardrails)

- **No accuracy numbers.** No published precision/recall figures exist —
  never quote any. Say "validated by scripted fault injection," which is
  true, and stop there.
- **Wireless: built, not hardware-proven.** The wireless stack (Cisco
  Catalyst 9800) shipped 2026-07-26 validated against vendor docs; live
  validation on physical hardware hasn't run yet. Pitch "wired and
  wireless in one view"; if they want to pilot ON wireless specifically,
  say "newest capability, let's make your environment the proving
  ground" — don't claim battle-tested. Remediation actions exist but ship
  disabled; don't demo-promise auto-fix.
- **No customer name-drops.** We don't have referenceable customers; the
  young-product honesty play (§6) converts better than a bluff.
- **No hard scale claims.** The 5k-device/50k-flows load proof (Phase 3)
  isn't published. Say "pilot scale is proven; we're publishing full
  scale numbers."
- **Don't over-promise HA/clustering** — multi-node Kafka and Helm
  packaging are on the roadmap, not shipped. If asked: "single-node
  today, clustered profile on the near-term roadmap."
- **Never name a competitor, and never bash one over a past breach**
  unprompted. If *they* raise supply-chain trust, the on-prem/air-gapped
  story answers it without naming anyone.
- Pricing: don't invent numbers. "Pilot is free; commercial terms we'll
  shape together" until licensing ships.
