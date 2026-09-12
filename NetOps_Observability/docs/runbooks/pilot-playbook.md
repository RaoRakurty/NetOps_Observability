# Design-partner pilot playbook

**What this is.** The end-to-end plan for a four-week design-partner pilot: what
to agree before anything is installed, what happens each week, how each of the
ten Project 2 success metrics is measured (and which of them have no instrument
yet), what "done" looks like, and what the partner sends back.

**What this is not.** It is not the go-live gate.
[`first-customer-acceptance.md`](first-customer-acceptance.md) is that — the
data-reliability contract (retention, cold tier, read budgets, external alert
delivery, backups + a proven restore, off-host DR, disk sizing). A pilot uses
that checklist as its **week-4 exit gate**; it does not replace it.

> **Honesty rule for this document.** Where a number does not exist yet, it says
> **"not yet measured"** and names the instrument that will produce it. No
> figure appears here that was not measured on a real run. The same rule applies
> to what you tell the partner.

---

## 1. Scope

### 1.1 What a pilot proves

One thing: that when the partner's network breaks, Correlix hands the operator
**one root cause with evidence attached and a named owner**, faster and more
often correctly than what they run today. Everything below serves that.

The six questions the RCA surface must answer, in order — they are the shape of
the whole pilot, the demo, and the week-4 review:

> **What broke? · Why does Correlix believe that? · What is affected? ·
> Who owns it? · What evidence supports the conclusion? · Is it recovering?**

### 1.2 What is in and out

| in scope | out of scope for a pilot |
|---|---|
| One site or one WAN edge, 10–200 real devices | Fleet-wide rollout |
| Syslog · SNMP traps + polling · flows · active probes | gNMI streaming (opt-in, not pilot default) |
| Real incidents observed and graded by the partner's own NOC | Replacing the incumbent tool |
| Verdict feedback on every RCA the partner reads | Custom signature authoring |
| Ticketing integration in **mirror** mode (ServiceNow / Jira) | Automated remediation |

**Run alongside, never in place of.** The partner keeps their existing alerting
for the duration. Correlix is graded on the RCA, not on being the pager.

### 1.3 Security posture to agree before install

Scaffold-grade defaults are documented, not hidden. Agree in writing:

- SNMP discovery defaults to `10.0.0.0/8` — **narrow it** before pointing at a
  real network (`ENABLE_SNMP_DISCOVERY`, discovery subnet in
  Infrastructure → Discovery & NMS).
- The OpenSearch security plugin is disabled in the appliance profile; the stack
  is single-host and expected to sit behind the partner's own perimeter.
- Copilot / Iris AI is **off** unless `FEATURE_COPILOT=true` and
  `COPILOT_API_KEY` are set. If the partner will not send prompt context to an
  external provider, leave it off; every RCA surface works without it.
- Secrets are generated per install (`scripts/install.py`); rotation is
  `python3 scripts/install.py --reset-env`.

---

## 2. Prerequisites

### 2.1 Sizing — the reference box

> **Reference box (`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` §1):**
> 4 cores (Intel Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM, 77 GB disk, full
> Docker-Compose stack on one host.
>
> **Owner-recommended capacity wording, verbatim
> ([`../HOSTING_SIZING_GUIDE.md`](../HOSTING_SIZING_GUIDE.md) §1) — use this
> sentence and no other:**
>
> *"Validated on the reference configuration at 2,500 devices and ~1,000 eps;
> actual device capacity depends on event rate, topology density, incident
> cardinality, evidence workload, and tenant distribution."*

Device count is a **proxy**; what the host constrains is events per second. A
pilot at 10–200 devices is far inside the envelope, so sizing is a
**retention** question, not a throughput one — see
[`first-customer-acceptance.md`](first-customer-acceptance.md) §9b
(`TAG:F55-DISK`): size the disk to `sum(daily ingest × retention days)` across
the six stores, plus headroom for OpenSearch snapshots and ClickHouse cold
export. The lab's 77 GB volume has filled once; do not treat it as a floor for a
partner who wants 90-day retention.

Never promote a capacity tier. The four labels are
`VALIDATED` / `MEASURED STRETCH` / `OUTSIDE ENVELOPE` /
`SATURATION CHARACTERIZATION` (`HOSTING_SIZING_GUIDE.md` §3); a claim without
one of them is unbacked. The one-pager to hand a partner is
[`../sales/capacity-and-qualification-one-pager.md`](../sales/capacity-and-qualification-one-pager.md).

### 2.2 Host

- Linux host with **Docker + the Compose v2 plugin** (the installer rejects
  legacy `docker-compose`).
- `python3` on the host (the installer is Python).
- One TCP port for the UI — `:8000` by default (`BASE_PORT`, or
  `install-correlix.sh install --ui-port N`).
- Root-fs headroom: keep ≥ 10 GiB free. This is not cosmetic — OpenSearch's
  flood-stage watermark silently discards documents when the disk crosses it
  (`CORRELIX_REFERENCE_CAPACITY_V1.md` §8(e); it cost a scale leg 291,296
  evidence documents).

### 2.3 Network prerequisites — what must reach the host

Ports are host ports; each is overridable in `.env`. Source
[`../INGESTION.md`](../INGESTION.md) §Ports.

| lane | protocol | host port (env) | direction |
|---|---|---|---|
| Syslog | UDP **and** TCP | `SYSLOG_PORT` (**5514**; `514` on rootful Linux) | devices → host |
| NetFlow v5/v9 | UDP | `NETFLOW_PORT` (**2055**) | devices → host |
| IPFIX | UDP | `IPFIX_PORT` (**4739**) | devices → host |
| sFlow | UDP | `SFLOW_PORT` (**6343**) | devices → host |
| SNMP traps | UDP | `SNMP_TRAP_PORT` (**162** → container 1162) | devices → host |
| SNMP polling | UDP 161 | — | **host → devices** |
| UI / API | TCP | `BASE_PORT` (**8000**) | operators → host |

Also agree:

- **Source interface / management IP per device.** Correlix attributes evidence
  by device identity; a device whose syslog source address does not match its
  registered management address will land as an unattributed sender. Pin
  `logging source-interface` (or the vendor equivalent) to the same loopback the
  SNMP profile polls.
- **Prefer TCP syslog** where the platform supports it. UDP syslog and NetFlow
  are lossy by design; a lossy link shows up as gaps in the evidence and is the
  single most common cause of a pilot's "why did it not correlate?".
- **NTP on every device.** Event time comes from the RFC5424 timestamp, not from
  ingest time. A device with a skewed clock will place its symptoms outside the
  correlation window.
- Firewall/ACL exceptions for the rows above, both directions where listed.

### 2.4 Access and accounts

- One platform-owner login for the pilot engineer, one operator login per NOC
  shift. Administration → Identity & Access.
- An API key for scripted checks (Administration → API Access → *Generate key*),
  or use `POST /api/auth/login` for a short-lived bearer token — see
  [`../API_ACCESS.md`](../API_ACCESS.md).
- A **dedicated** external notification topic/channel for product alerts. It must
  not be the stack watchdog's topic — watchdog independence is deliberate
  (`first-customer-acceptance.md` §4).

---

## 3. Week-by-week plan

Throughout: every command below is run from the project root
(`NetOps_Observability/`) unless stated otherwise. The installer script is
`scripts/install-correlix.sh` in a source checkout and `./install-correlix.sh`
at the root of an extracted offline bundle — it detects which context it is in.
Commands below use the source-checkout path. `$TOKEN` is a bearer token:

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<password>"}' | jq -r .token)
```

### W0 — install, and the first synthetic RCA

**Goal:** the partner sees a real RCA on the product, on their own host, before
a single production device is pointed at it. This de-risks week 1: if the
synthetic RCA is right, every later failure is a data-plumbing question.

1. **Install.**

   ```bash
   # appliance / bundle (customer distribution) — interactive setup console,
   # run from the extracted bundle directory (the one holding SHA256SUMS):
   ./install-correlix.sh
   # or non-interactively:
   ./install-correlix.sh install --ui-port 8000

   # source checkout (pilot engineer's own box):
   python3 scripts/install.py
   ```

   Record the wall clock: **start the timer at the first command, stop it at
   first successful login.** That number is the deployment-friction baseline
   (§4 metric 9). The installer can emit machine-readable stage markers —
   `python3 scripts/install.py --progress-json` prints one `@CX@ {...}` JSON line
   per stage across its 15 pinned stages (`prereq … bootstrap-grafana`) — but it
   does **not** yet aggregate them into a timing report. Until it does, record
   the wall clock by hand.

2. **Verify the stack.**

   ```bash
   scripts/install-correlix.sh status                 # all services + :8000 probe
   curl -sS -H "Authorization: Bearer $TOKEN" \
        http://localhost:8000/api/health | jq
   ```

3. **Load demo data and drive one synthetic incident.**

   ```bash
   # base panels: flows, resource metrics, tunnels, findings
   python3 scripts/seed_demo_data.py

   # every pipeline, healthy steady state (one backfill + one tick)
   python3 scripts/demo_fill.py --once

   # a degraded incident (BGP/link syslog + probe loss + flapping counters)
   python3 scripts/demo_fill.py --duration 300 --degrade
   ```

   `demo_fill.py` pushes through the **real** ingest paths — syslog to host
   `:5514`, SNMP traps to Vector `:8688`, probe events to `:8689`, metrics to
   VictoriaMetrics — so this exercises the pipeline, not a fixture loader.
   (`--only syslog,probes,metrics` narrows it; `ALL` = `syslog, traps, probes,
   metrics, traceroute, base`.)

4. **Watch it land.** `#/overview/home` (Command Center) → `#/investigate/rca`.
   **Record the timestamp of the first correlation object.** Install-start →
   that timestamp is the *time to customer value* measurement (§4 metric 1).

5. **Agree the demo story.** Walk the partner through
   [`../demos/rca-hero/SCRIPT.md`](../demos/rca-hero/SCRIPT.md) on this synthetic
   incident, so both sides share the vocabulary before real data arrives.

**W0 exit:** stack healthy, one RCA rendered, install wall clock recorded, six
questions walked once.

### W1 — real device onboarding, one lane at a time

Onboard **in this order**. Each lane is independently verifiable, and a later
lane's failure is much easier to see once the earlier ones are green. Do not
start a lane until the previous one verifies.

Before any lane: register the devices (Infrastructure → Devices, or
`POST /api/devices`) so evidence has an identity to attach to. An unregistered
sender still indexes, but attribution is weaker.

#### Lane 1 — Syslog

Configure per [`../INGESTION.md`](../INGESTION.md) §Device configuration
examples (Cisco IOS/IOS-XE, Junos, rsyslog are all there verbatim). Point at
`MONITOR_HOST` port **5514** (or 514 on rootful Linux).

Verify:

```bash
# lines are arriving and are attributed to real hosts
curl -sS -G -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8000/api/logs/search' \
  --data-urlencode 'signal=syslog' \
  --data-urlencode 'query=*' \
  --data-urlencode 'size=20' | jq '.[0:3]'

# a specific device, a specific mnemonic (query_string / Lucene syntax)
curl -sS -G -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8000/api/logs/search' \
  --data-urlencode 'signal=syslog' \
  --data-urlencode 'query=host:core-router-01 AND "%BGP-5-ADJCHANGE"' \
  --data-urlencode 'size=20' | jq

# which per-tenant indices exist at all
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/logs/indices | jq
```

In the UI: **Explore → Logs** (`#/explore/logs`) takes the same query string.

**Set expectations here, once.** Search and correlation are two different
admissions — see [`../INGESTION.md`](../INGESTION.md) §"What reaches
correlation". Every line is indexed and searchable; the engine promotes to
evidence only lines the device stamped **warning-or-worse**, or lines carrying a
**known typed symptom marker** at any severity. Informational chatter staying
out of RCA is the design, not a gap. A partner who sees logs but no incidents is
usually looking at exactly that.

#### Lane 2 — SNMP traps, then SNMP polling

**Traps** to host UDP **162** (`SNMP_TRAP_PORT`, mapped to 1162 in-container).
Verify:

```bash
curl -sS -G -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8000/api/logs/search' \
  --data-urlencode 'signal=snmptrap' \
  --data-urlencode 'query=*' \
  --data-urlencode 'size=20' | jq '.[0:3]'
```

UI: **Investigate → Troubleshooting** → SNMP traps.

**Polling**: create the credential profile in Administration → SNMP Profiles
(v2c community or v3 USM), attach it to the devices, then confirm in
Administration → Data Sources that the collector is polling and in
**Analytics → Device Monitoring** / **Interface Performance** that the series
are filling. Polling is host → device UDP/161; a firewall that permits traps but
not polls is a common first-week snag.

#### Lane 3 — Flows

NetFlow **2055**, IPFIX **4739**, sFlow **6343** — config snippets in
[`../INGESTION.md`](../INGESTION.md). Verify:

```bash
curl -sS -G -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8000/api/logs/search' \
  --data-urlencode 'signal=flows' \
  --data-urlencode 'query=*' \
  --data-urlencode 'size=20' | jq '.[0:3]'
```

UI: **Explore → Flows** (`#/explore/flows`).

Note two things for the partner: flows are deliberately excluded from an "all"
log search (they outnumber logs ~1000:1 and would drown them) — use the explicit
`signal=flows` filter. And exporters subsample: the `sampling_rate` field is
preserved and aggregations must multiply by it.

#### Lane 4 — Active probes

Probes are the second **independent vantage point**, and independence is what
moves a verdict from *suspected* to *confirmed*. Configure the synthetic /
STAMP targets that matter to the partner (the paths their users complain about),
then confirm probe evidence is attaching on an RCA case and that
**Investigate → Flow Trace / WAN Paths** render.

#### W1 checkpoint

- Each lane verified by its own command above.
- At least one real correlation object exists from **real** device evidence.
- Ticketing wired in mirror mode (Administration → Ticketing & Automation) if
  the partner wants it — mirror only, no auto-resolve, for the pilot.
- External alert channel delivering (`scripts/verify-critical-alert-channel.sh
  --send`) and **seen on a subscribed device** — delivery to a server is not
  receipt.

### W2–W3 — live incidents and verdict feedback

This is the pilot. Two weeks of the partner's real incidents.

**The operating loop, per incident:**

1. The NOC works the incident as they normally would, with their existing tools.
2. In parallel, someone opens the Correlix RCA for it (`#/investigate/rca`, or
   from Command Center) and reads the six-question header **before** the root
   cause is known internally. Record the time.
3. When the truth is known, the reader grades the verdict:
   **correct / wrong / partially correct**, plus *which part* was wrong and
   *what they expected instead*.
4. Anything surprising, missing, or wrong gets filed — see §6.

**Recording the grade.** The verdict-feedback API is in the tree (Project 2 P7):

| endpoint | what it does |
|---|---|
| `POST /api/correlations/{id}/feedback` | record one operator verdict (audited, tenant-scoped, append-only) |
| `GET /api/correlations/{id}/feedback` | that case's verdicts, newest first |
| `GET /api/correlations/feedback/summary?days=N` | the windowed correct/wrong/partial counts and **false-positive rate** for the caller's tenant, broken out by template |

The contract, and therefore what to capture:

| field | values |
|---|---|
| `correlation_id` | from the RCA header ("RCA ID") or the URL |
| `verdict` | `correct` · `wrong` · `partial` |
| `wrong_part` | `cause` · `owner` · `affected` · `evidence` · `recovery` — must be **empty** on a `correct` verdict |
| `reason` | free text: what the operator expected instead |
| `correlation_version` | which version of the object was actually judged (objects re-version as evidence arrives; an honest null beats a guessed "latest") |

`top_hypothesis` and `verdict_tier` are copied server-side at write time, so the
false-positive rate stays attributable to a template even after the object
re-versions or ages out.

**Check what your build exposes.** The API is in the tree but the in-app control
on the RCA header may not be in the frontend image you deployed. Where it is not,
post the same fields with `curl`, or use the **RCA verdict feedback** issue form
(`.github/ISSUE_TEMPLATE/rca-verdict-feedback.yml`) — it mirrors the contract
1:1, so nothing has to be re-collected later.

**Weekly (both weeks):** a 30-minute call. Count of RCAs read, the
correct/wrong/partial split, the two worst misses, and anything blocking.

### W4 — review and decision

1. **Run the acceptance gate.** Every hard gate in
   [`first-customer-acceptance.md`](first-customer-acceptance.md): retention,
   cold tier, read budgets, alert delivery, chaos-fixture policy, release gate,
   projection reliability, backups + a restore actually performed, §9 off-host
   DR and disk sizing. This is the go/no-go for anything beyond the pilot.
2. **Compile the ten metrics** (§4) — each with its instrument and its reading,
   or the words "not yet measured".
3. **Review meeting**, structured as the six questions: for the pilot's real
   incidents, how often did Correlix answer each one, correctly, and how fast?
4. **Decision:** continue / expand / stop, recorded with reasons.

---

## 4. The ten success metrics — instrument and where the number is read

The metrics are the owner-enumerated list in
`docs/projects/02-PRODUCTIZATION-DESIGN-PARTNERS.md`. Device count is
deliberately **not** among them.

| # | metric | instrument | where the number is read | state today |
|---|---|---|---|---|
| 1 | **Time to customer value** | Installer wall clock + the timestamp of the first correlation object | Start the clock at the first install command, stop at first login; then the first RCA's "Detected at" on `#/investigate/rca`. `python3 scripts/install.py --progress-json` emits per-stage `@CX@` markers across the 15 pinned stages. The aggregated timing report **`data/install-timing.json` does not exist yet** (P4, shipping wave). | **not yet measured** — record the wall clock by hand this pilot |
| 2 | **Time to useful RCA** | `scripts/scale-rca-latency.py --ground-truth <run_dir>` on a qualification leg (emits `time_to_first_correct` / `time_to_useful`), or the per-case `GET /api/correlations/{id}/time-metrics` on a live incident | Run dir of a `release-qualify.py` leg (`ttur.tsv`, `ttur-scope.json`, the tool's JSON via `--json`); per-case, the RCA **Time impact** panel | Defined and measured once (`docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md`) but **100 % censored** on the V1 workload — every story there is single-modality, so the ≥ 2-independent-source clause can never be met. **Not measurable on V1**; a pilot's real, multi-modality incidents are the first chance to measure it |
| 3 | **Operator comprehension** | The six-question checklist, read off the RCA header, per incident, by an operator who did not build the system | `#/investigate/rca` → a case. Header must answer, above the fold: **Root cause** · **Owner / Possible owner** · **Affected** · **Evidence** (symptoms · independent sources · duration) · the verdict + incident-lifecycle pills (Active / Recovering / Recovered) · **Decision**. Score 6/6, or name which question the operator could not answer | measured per incident during W2–W3; no aggregate instrument |
| 4 | **Pilot deployment success** | [`first-customer-acceptance.md`](first-customer-acceptance.md) — every gate, run on the partner's deployment | The checklist itself; sign-off line into the deployment record | binary, at W4 |
| 5 | **Demo effectiveness** | [`../demos/rca-hero/REHEARSAL.md`](../demos/rca-hero/REHEARSAL.md) pass/fail lines + the timing column | The rehearsal sheet, filled per run | measured per rehearsal |
| 6 | **False-positive RCA rate** | `GET /api/correlations/feedback/summary?days=N` — returns `correct` / `wrong` / `partial` counts, `n`, `false_positive_rate` and a per-template breakdown for the caller's tenant, fed by `POST /api/correlations/{id}/feedback` | The endpoint directly. `false_positive_rate` is **null until there is data** — it is not zero, and must never be reported as zero | instrument **exists in the tree**; the number is **not yet measured** — it needs a pilot's graded verdicts, and the in-app control may not be in your deployed frontend image (post via `curl` or the issue form until it is) |
| 7 | **Customer-reported time saved** | MTTR from the **Recovery Scorecard**, compared against the partner's own historical MTTR for comparable incidents | `#/analytics/scorecard` → *Median recovery time*. Where no ITSM recovery signal is linked, recovery is **engine-inferred** (the incident window closed with no further symptoms) and the page marks it an approximation, not a measurement — quote it that way | partially available; honest about which incidents are inferred |
| 8 | **Incident-resolution improvement** | Same scorecard, the phase split: Correlate · Isolate · Recover · Resolve; plus per-case `/time-metrics` | `#/analytics/scorecard`. Recovery and ticket-closure timing render **"Not measured"** until recovery / ITSM evidence is connected — connect ticketing in W1 if this metric matters to the partner | partially available |
| 9 | **Deployment friction** | The install timing above **plus the support-bundle count** — how many times the partner had to run `support-bundle.sh` and send diagnostics to get unstuck | Timing from §W0 (by hand). Bundle count: one per `correlix-support-*.tar.zst` the partner sends; each carries its own UTC stamp and `MANIFEST` | install timing **not yet measured**; bundle count measurable from week 0 |
| 10 | **Design-partner retention** | The W4 renewal decision, recorded with reasons | The §W4 decision line | binary, at W4 |

**Never invent a number for a metric marked "not yet measured".** Say what the
instrument will be and when it ships.

---

## 5. What to send back

### 5.1 The support bundle — one command

```bash
# customer bundle install:
./install-correlix.sh support-bundle

# source checkout:
python3 scripts/support-bundle.sh
```

Output: `correlix-support-<host>-<UTCstamp>.tar.zst`, written `0600` into the
current directory. Flags: `--out DIR`, `--since 24h` (how far back to read
container logs — `30m`, `7d` or an RFC3339 timestamp also work), `--no-logs`
(smallest, fastest bundle).

It collects compose state, the **resolved compose config with every secret
redacted**, `.env` **key names only**, host disk/memory/kernel, `/admin/version`,
`/api/health` + `/api/health/score`, correlation consumer-group lag,
ClickHouse part/row summaries, OpenSearch cluster health and index sizes,
active alerts, the watchdog log, and per-container logs — plus a `MANIFEST`
with a sha256 per file and a status row per collector, so a **partial bundle is
never silent**.

Every collector is a **read**. Nothing in the bundle changes the stack; the
Kafka `--describe` reports lag and never commits or resets an offset, and the
store queries carry an execution-time ceiling.

Full contents and the two-pass redaction guarantee:
[`support-bundle.md`](support-bundle.md).

**Read the `MANIFEST` before you send it.** Redaction covers secrets by key
pattern *and* by literal value from the stack's own `.env`, but device
hostnames and management addresses are not secrets and are not redacted —
agree up front whether those may leave the partner's estate. Never send an
archive nobody has opened.

### 5.2 Per incident, alongside the bundle

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/correlations/$CID"              > case.json
curl -sS -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/correlations/$CID/timeline"     > timeline.json
curl -sS -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/correlations/$CID/time-metrics" > time-metrics.json
curl -sS -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/correlations/$CID/feedback"     > feedback.json
```

Plus the **RCA PDF** (RCA page → *⤓ Export PDF*), the verdict grade, and what
the truth turned out to be.

## 6. Escalation

| what happened | first response | escalate as |
|---|---|---|
| Stack down / a service will not come healthy | `scripts/install-correlix.sh status`, then `logs <service>`; check root-fs free ≥ 10 GiB | **design-partner bug**, severity *stack down*, with the §5 bundle |
| Logs arrive, no incidents form | Confirm against §"What reaches correlation" — are the lines warning-or-worse or carrying a typed marker? Query `corr_ingest_prefilter_total` in **Explore → Metrics** (VictoriaMetrics scrapes every correlation replica) | **design-partner bug** only if a *typed* symptom was declined; otherwise a **feature request** for the missing symptom class |
| An RCA verdict is wrong, partly wrong, or over-claims | Do not tune anything. Capture the four fields | **RCA verdict feedback** — this is the highest-value input a design partner produces |
| A device type / vendor mnemonic is not understood | Attach three real example lines | **feature request** (parser coverage) |
| Missing capability the partner needs to adopt | — | **feature request** |
| Anything touching credentials, tenant isolation, or data leaving the estate | **Stop.** Do not file publicly. Contact the pilot engineer directly | out-of-band, same day |

Issue forms live in `.github/ISSUE_TEMPLATE/` at the repository root:
`design-partner-bug.yml`, `rca-verdict-feedback.yml`, `feature-request.yml`.

**Response expectations to agree with the partner:** stack-down same business
day; wrong verdict triaged within the weekly call; feature requests ranked at
the W4 review. Set these explicitly — an unstated SLA is the fastest way to lose
a design partner.

---

## 7. Exit criteria

A pilot **succeeds** when all of these are true:

1. **Acceptance gate green.** Every hard gate in
   [`first-customer-acceptance.md`](first-customer-acceptance.md), including
   §9's off-host DR and disk sizing, signed into the deployment record.
2. **All four lanes live** on real devices, each verified by its own command
   (§W1), for at least 14 consecutive days.
3. **≥ 10 real incidents graded** by the partner's own operators, with the four
   feedback fields captured for each.
4. **Six-question comprehension:** on ≥ 80 % of graded incidents, an operator
   who did not build the system answered all six questions from the RCA header
   alone.
5. **No unexplained loss.** No period where evidence was silently dropped;
   any gap has a named cause (UDP loss, device clock, disk watermark, a lane
   that was down) recorded in the deployment record.
6. **Every metric in §4 has either a reading or the words "not yet measured"
   plus its instrument.** A blank is a failed review, not a passed one.
7. **A renewal decision is recorded** with reasons — including "no", which is a
   valid and useful pilot outcome.

A pilot **fails honestly** if the partner's incidents were too few or too
uniform to grade the engine. Say so and extend; do not manufacture incidents to
fill the metric table.

---

## Cross-references

- [`first-customer-acceptance.md`](first-customer-acceptance.md) — the go-live gate (W4)
- [`../INGESTION.md`](../INGESTION.md) — ports, device config, what reaches correlation
- [`../HOSTING_SIZING_GUIDE.md`](../HOSTING_SIZING_GUIDE.md) — capacity language, the four zones and four tiers
- [`../scale/CORRELIX_REFERENCE_CAPACITY_V1.md`](../scale/CORRELIX_REFERENCE_CAPACITY_V1.md) — the reference box and the qualified numbers
- [`../sales/capacity-and-qualification-one-pager.md`](../sales/capacity-and-qualification-one-pager.md) — the partner-facing capacity page
- [`../demos/rca-hero/SCRIPT.md`](../demos/rca-hero/SCRIPT.md) — the 10-minute RCA demo
- [`release-qualification.md`](release-qualification.md) — `scripts/release-qualify.py`, the V1 rerun
- [`../API_ACCESS.md`](../API_ACCESS.md) — API keys, tokens, OpenAPI
- [`backup-restore.md`](backup-restore.md) — the restore drill the acceptance gate requires
