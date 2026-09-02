# RCA hero demo — 10-minute script

**Audience:** a network/IT leader or a NOC lead, live, on the lab stack.
**Claim being demonstrated:** *two hundred alerts, one cause, evidence attached,
and it names who owns the fix.*
**Runtime:** 10 minutes of talking, ~6 minutes of injected incident.

The demo answers the six operator questions, in order, off one screen:

> **What broke? · Why does Correlix believe that? · What is affected? ·
> Who owns it? · What evidence supports the conclusion? · Is it recovering?**

> **Honesty rule.** This demo runs on **generated** telemetry pushed through the
> real ingest paths — not on a fixture loader, and not on a customer's data. Say
> so once, at the top. The engine's verdict on this data is the engine's real
> verdict; nothing on screen is scripted. If the verdict comes back
> *not confirmed*, **that is the demo** — see Act 2.
>
> The RCA page renders a **"Synthetic data · example case"** watermark whenever
> what it is showing is the product's built-in example case rather than a real
> correlation object. A case produced by this demo is a **real object** built
> from generated telemetry, so it carries no watermark — and if you ever see
> that watermark during a demo, you are showing the example, not your injection.
> Never hide it; say what it means.

Files in this pack:

| file | use |
|---|---|
| `SCRIPT.md` (this file) | the run of show |
| [`REHEARSAL.md`](REHEARSAL.md) | pass/fail checklist + timing column — run it before every live demo |
| [`RESET.md`](RESET.md) | how to get back to a clean state between runs |

**Screenshots: none in this pack yet.** When they are captured, put them in
`docs/demos/rca-hero/img/` as `act<N>-<slug>.png` (e.g. `act2-header.png`) and
reference them inline at the marked `<!-- SCREENSHOT -->` points below. Capture
at 1600×1000 in light theme, with the browser chrome cropped. Do not screenshot
anything carrying a real customer hostname.

---

## Pre-flight (T-15 min, before the audience joins)

Run [`REHEARSAL.md`](REHEARSAL.md) end to end. The short form:

```bash
cd NetOps_Observability

# 1. stack healthy — all services up, :8000 answering
scripts/install-correlix.sh status

# 2. a token for the checks below
TOKEN=$(curl -sS -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<password>"}' | jq -r .token)
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/health | jq

# 3. demo data loaded — panels have depth, so nothing renders empty
python3 scripts/seed_demo_data.py            # flows, resource metrics, tunnels, findings
python3 scripts/demo_fill.py --once          # one backfill + one healthy tick, all lanes

# 4. confirm the panels filled before you present
#    Analytics → Device Monitoring · Interface Performance
#    Explore → Flows · Logs
```

The `--once` tick prints one count per lane. **`syslog`, `traps`, `probes` and
`metrics` must all be non-zero** — those are the demo path. `traceroute=0` is
tolerable: that lane writes to the Valkey cache (compose service `redis`) and
only feeds the Flow Trace panel, which this script does not open.

Then park the browser on **`#/overview/home`** (Command Center) with the RCA
page (`#/investigate/rca`) open in a second tab. Log in **before** the audience
joins — never demo the login screen.

**Two things to check that ruin a demo if missed:**

- Root filesystem ≥ 10 GiB free. Below OpenSearch's flood-stage watermark the
  router silently discards evidence documents and the incident renders thin.
- The lab clock is sane. Event time comes from the emitted timestamp; a skewed
  host puts the symptoms outside the correlation window.

---

## Act 0 — frame it (0:00 – 1:00)

Do not open with the product. Open with the problem:

> "Think about your last serious outage. How long did it take to know *whose*
> problem it was — the ISP, the WAN, the LAN, the firewall, the app team? And
> how many people were on the bridge while you figured that out?"

Then, one sentence:

> "That gap — between 'something is broken' and 'here's the cause, here's the
> evidence, here's who owns it' — is the only problem this product solves.
> I'm going to break this lab network now, and we'll watch it answer."

State the honesty rule: *generated telemetry, real pipeline, real engine, real
verdict.*

---

## Act 1 — inject the outage (1:00 – 3:00)

**The canonical fault story.** The enterprise outage chain is defined once, in
`scripts/enterprise_outage_chain.py`, and imported by both harnesses (the digital
twin and the scale mini-ladder) so the demo and the qualification can never drift
into telling different stories. Its phases, in causal order, with the
seconds-after-cause bands the module declares:

| phase | offset after the cause | what the network emits |
|---|---|---|
| `uplink_down` | 0 s — **the cause** | `%LINK-3-UPDOWN` / `%LINEPROTO-5-UPDOWN` on the core uplink |
| `ospf_neighbor_down` | 1–3 s | `%OSPF-5-ADJCHG` — the IGP notices |
| `ospf_interface_flap` | 2–10 s | a second core port starts flapping |
| `bgp_session_flap` | 5–15 s | `%BGP-5-ADJCHANGE`, `%BGP-5-NBR_RESET`, `%BGP-3-NOTIFICATION` |
| `route_churn` | 10–60 s | withdraw/announce burst, `%BGP-4-MAXPFX` |
| `access_layer` | 20–90 s | `%SPANTREE-5-TOPOTRAP`, `%SW_MATM-4-MACFLAP_NOTIF` |
| `recovery` | 150–300 s | link back up — **unless the draw makes it a hard outage** (a share of stories never recover, by design) |

Every mnemonic is vendor-standard Cisco IOS-XE / NX-OS, not invented, and each
event type carries its **measured** promotion outcome in the module's coverage
table — so a harness can never emit a plausible-looking line the parser cannot
actually read and then score the engine for missing it.

**`enterprise_outage_chain.py` has no CLI.** It is a shared library, not a
runnable script. Two ways to drive a demo from it:

### (a) `demo_fill.py --degrade` — the default for a customer demo

Fastest, no lab topology required, and it drives four lanes at once.

```bash
# 5 minutes of degraded telemetry across the 5-device demo fabric:
#   syslog  -> host :5514   %BGP-5-ADJCHANGE (Established -> Idle, severity warning)
#                           %LINEPROTO-5-UPDOWN (changed state to down, severity err)
#   traps   -> Vector :8688 linkDown / bgpBackwardTransition (decoded JSON)
#   probes  -> Vector :8689 STAMP loss + RTT departure on the WAN target
#   metrics -> VictoriaMetrics: bgp_peer_state 6 -> 1, error/CRC counters climbing
python3 scripts/demo_fill.py --duration 300 --step 30 --degrade
```

**Be precise about what this is.** It emits the *head* of the chain — the cause
and the BGP/link-state phase — plus trap, probe and metric evidence for the same
devices. It does **not** replay the full seven-phase chain: there is no OSPF
adjacency, route-churn, STP or MAC-flap phase in this generator. That is fine
for a demo (the multi-lane evidence is the point), but do not describe it as the
enterprise outage chain to an audience that will later read the code.

Leave it running in a visible terminal — the per-tick line
(`tick (degraded): syslog=… traps=… probes=… metrics=…`) is good theatre: the
audience watches evidence being emitted while the UI reacts.

`--only syslog,probes,metrics` narrows the lanes; `--step` sets the tick
interval. Ctrl-C stops it early; it is time-boxed by `--duration` regardless.

### (b) `twin.py run` — for a technical audience that will ask "is this scored?"

```bash
python3 scripts/lab/twin/twin.py run --scenario <scenario.yaml> --duration-minutes 10
python3 scripts/lab/twin/twin.py score --runid <runid>      # accuracy vs ground truth
python3 scripts/lab/twin/twin.py teardown --runid <runid>
```

The twin runs a **labelled** scenario against the live stack and scores the
engine against machine-readable ground truth afterwards — the honest answer to
"how do you know it's right?". The shipped example scenarios are
`docs/design/examples/twin-scenario-example.yaml` (DX seam flap with cloud-side
withdrawal, plus a negative control that must NOT merge) and
`twin-scenario-fidelity.yaml`. **Driving the full `enterprise_outage` story
template requires authoring a scenario that uses it — author and rehearse it
ahead of time, never live.**

### What appears, and roughly when

Quote the *shape*, never a specific latency you have not just measured on this
host:

- **within ~30 s** — lines land in **Explore → Logs**; the interface and
  BGP-peer-state series bend in **Analytics → Device Monitoring**.
- **within ~1 min** — an incident appears on **Command Center**
  (`#/overview/home`) and in **Operations → Incidents**.
- **as evidence accumulates** — the correlation object **versions**: it does not
  appear once and freeze. Say this out loud; it is the differentiator.

<!-- SCREENSHOT: act1-injection.png — terminal tick output beside Command Center -->

**Do not narrate the wait in silence.** While it lands, say what is happening:
every one of those lines goes to Kafka, into OpenSearch for search, and — only
if it clears the admission rule — into the correlation engine as evidence.
Informational chatter stays searchable and stays *out* of the RCA. That is why
you get one incident and not two hundred alerts.

Worth naming, because a technical audience will test it: the `%BGP-5-ADJCHANGE`
line is emitted at severity **warning** and `%LINEPROTO-5-UPDOWN` at **err** — at
or above the engine's warning floor — and both also carry typed adjacency /
link-state markers. Either route alone would admit them. See
`docs/INGESTION.md` §"What reaches correlation".

---

## Act 2 — Command Center → the incident → the six questions (3:00 – 6:00)

**Command Center** (`#/overview/home`) is the landing zone: the operator's
triage view. Point out that the fault is **one row**, not a wall — then open it.

Land on the RCA page (`#/investigate/rca`) and open the case. The header answers
all six questions above the fold. Read them **in this order**, out loud:

| # | question | where it is answered on the header |
|---|---|---|
| 1 | **What broke?** | The case title, and the **Root cause** row in the aside. When the verdict is confirmed it names the object (`device ↔ peer`). When it is not, it says so honestly: *"Not confirmed — possibly because of X"*, or *"Not identified — no cause hypothesis has supporting evidence yet"*. It never renders a bare dead end. |
| 2 | **Why does Correlix believe that?** | The status pills — four independent dimensions: the **verdict** (`✓ CONFIRMED` / `NOT CONFIRMED` / `● RECOVERED` / `✕ RULED OUT`), **Confidence**, **Incident** lifecycle, **Analysis** state — plus the **Decision** callout beneath them. The full reasoning is one section down in *Executive RCA summary*, including **Ruled out** (competing causes the evidence does not support) and the *"How was this verified?"* disclosure that carries the engine's verbatim gate reasons. |
| 3 | **What is affected?** | The **Affected** row — devices, peer, impacted applications, derived from the engine's own blast radius. When nothing is known it reads **"Not yet determined"**, never `0`. Unknown is not zero. |
| 4 | **Who owns it?** | The **Owner** row when confirmed, **Possible owner** with "— unconfirmed" when not, and **"Not yet narrowed — NOC triage"** when the seam has not been narrowed at all. It names the *seam's responsible party* — ISP, carrier, cloud provider, app team — never a generic "NOC" when the engine has an attribution. |
| 5 | **What evidence supports it?** | The **Evidence** row: *N symptoms · M independent sources · duration*. Below it, the evidence-summary strip: one time-density bar per symptom, so repetition renders as **ink**, not as a count posing as evidence. The raw observation count trails, deliberately de-emphasized. |
| 6 | **Is it recovering?** | The **Incident** pill — *Active* / *Recovering* / *Recovered*. Note the deliberate split: the verdict pill carries the **analysis**, the incident pill carries the **lifecycle**. "Recovered" is an incident state and never an analysis state. |

Also on the header: *Detected at*, the short *RCA ID* (you will need it in Act 4),
and the **⤓ Export PDF** button.

<!-- SCREENSHOT: act2-header.png — the six-question header, full width -->

**If the verdict comes back *not confirmed* — do not apologise. Lean in.**
This is the strongest moment in the demo:

> "It won't claim a cause it can't support. It has one modality here, so it
> tells me exactly what would confirm it. Every other tool you've been shown
> today would have guessed."

Show the *Ruled out* list and the "what's missing" evidence lines. An engine
that says *"still analyzing"* rather than naming an unsupported cause is a
product property, not a shortfall.

---

## Act 3 — the causality path, the evidence, the owner (6:00 – 8:00)

Scroll to **Network path & causality** — the path is the hero of the page.

- The typed source → destination path renders with the **break in red** on the
  attributed device. One hero, never two: when the seam itself is the suspect,
  the red sits **on the seam boundary** and no device is marked.
- Ownership is a line on that path — the seam's responsible party
  ("Lumen (DIA #12345) · ISP / carrier"), not a generic assignment. Seam types
  are the five finals: DX · VPN · SDWAN · DIA (displayed as "ISP") ·
  CLOUD_BACKBONE.
- Where the path is not fully discovered, it says **"path not fully
  discovered"** and draws the undiscovered spans as dotted gaps rather than
  inventing hops.

Then, briefly:

- **Impact & blast radius** — the same affected set the header summarised.
- **Evidence matrix / confidence ladder** — which observations were used, from
  which observer, and what each contributed. Point at **two independent
  sources** if you have them; that is the gate between *suspected* and
  *confirmed*.
- **Timelines** — the chronological "what happened when", real timestamps only.

<!-- SCREENSHOT: act3-path.png — the broken-red causality path with the owner line -->

The line to land here:

> "It didn't group these because they happened at the same time. It grouped them
> because they share a topology object. Co-occurrence is a coincidence;
> grounding is a cause."

---

## Act 4 — recovery, the PDF, the ticket (8:00 – 10:00)

**Recovery.** If the injected story drew a recovering variant, the **Incident**
pill flips *Active → Recovering → Recovered* while you are on the page, and the
*Time impact* panel shows the phase split (detect → correlate → **isolate**, the
hero stage → owner → recover). Say plainly which stages are **proven** and which
are **engine-inferred**: where no ITSM recovery signal is linked, recovery is
inferred from the incident window closing with no further symptoms, and the
product labels it an approximation, not a measurement.

Fleet-level, one click: **Analytics → Recovery Scorecard**
(`#/analytics/scorecard`) — median recovery time and where incident time is
spent. Be honest that recovery and ticket-closure timing read **"Not measured"**
until recovery / ITSM evidence is connected. Do not skip that panel; a tool that
admits what it cannot measure is the entire pitch.

**PDF export.** Back on the RCA page, click **⤓ Export PDF**. The report carries
the same graph the page drew — not a redrawn approximation — plus the verdict,
evidence, ruled-out causes and the timeline.

> "That's the postmortem, already written, at the moment you needed it — not
> three days later from someone's memory."

**Ticket.** Scroll to the ticket card. Two outcomes, both worth showing:

- **Confirmed** → *"Open incident: customer impact is confirmed"*, with the
  recommended priority and the assignment set to the **seam owner**.
- **Not confirmed** → *"Not opened — impact not confirmed. Auto-ticketing holds
  until independent evidence confirms customer impact."*

That hold is the anti-noise property: the product will not manufacture a ticket
to look busy. With ServiceNow or Jira wired (Administration → Ticketing &
Automation) the ticket mirrors both ways and closes when the incident clears.

**Close (last 20 seconds).** Return to the header and re-read the six answers,
fast:

> "What broke. Why it believes that. What's affected. Who owns it. What evidence
> supports it. Whether it's recovering. One screen, six answers, evidence
> attached — and it runs entirely inside your building."

Then stop talking.

---

## After the demo

1. Run [`RESET.md`](RESET.md) before the next run.
2. Fill in [`REHEARSAL.md`](REHEARSAL.md)'s timing column with what this run
   actually took — that sheet is the *demo effectiveness* instrument
   (`docs/runbooks/pilot-playbook.md` §4, metric 5).
3. Anything the audience asked that the product could not answer → a
   **feature request** (`.github/ISSUE_TEMPLATE/feature-request.yml`).
   Anything it answered *wrongly* → **RCA verdict feedback**.
