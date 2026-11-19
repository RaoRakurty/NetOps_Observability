---
title: Iris skills and chaining
description: The 25 compiled-in troubleshooting methods, where each one applies, and how one hop hands off to the next inside a bounded budget.
page_type: concept
sidebar_position: 4
---

# Iris skills and chaining

A **skill** is one troubleshooting method, written as data rather than as code.
It states when it applies, which governed read-only tools to gather with, what
to look for in the result, and where to go next. Iris selects one skill for a
question, runs its gather plan, and may hand off to another skill inside a
bounded budget.

## The 25 skills

Skills are organised by the layer they own. `method` is reserved for the entry
method, `osi-bisection`, which selects among the others instead of owning a
layer.

| Skill | Layer | Symptom kinds |
|---|---|---|
| `osi-bisection` | method | unknown, general, triage |
| `interface-down` | physical | physical, reachability, adjacency |
| `optics-degraded` | physical | physical, errors, degradation |
| `qos-congestion` | physical | congestion, queueing |
| `mac-flap` | l2 | l2, instability, duplicate |
| `stp-topology` | l2 | l2, instability, broadcast |
| `fhrp-lag-redundancy` | l2 | failover, aggregation |
| `ospf-adjacency` | igp | igp, adjacency, routing |
| `isis-adjacency` | igp | igp, adjacency, routing |
| `l3-reachability` | igp | reachability, routing |
| `bgp-session-down` | bgp | bgp, adjacency, routing, reachability |
| `bgp-prefix-missing` | bgp | bgp, routing, policy, reachability |
| `sdwan-overlay` | wan_overlay | overlay, tunnel, wan |
| `tunnel-vpn` | wan_overlay | tunnel, vpn, overlay |
| `evpn-vxlan-overlay` | wan_overlay | evpn, vxlan |
| `path-seam-handoff` | path_seam | path, loss, latency, ownership |
| `dns-resolution` | services | resolution, resolver |
| `ntp-clock` | services | clock, synchronization |
| `platform-health` | platform | reload, crash |
| `upgrade-readiness` | platform | upgrade, change |
| `app-edge-5xx` | application | application, errors, latency |
| `security-exposure-context` | security | security, posture, exposure |
| `scope-contrast` | analysis | contrast, scope |
| `network-design-read` | analysis | design, resilience |
| `log-confirmation` | logs | confirmation, logs, timing |

`upgrade-readiness` is read-only: it reports ready, not ready (with each
reason) or cannot tell for a device and a target release. Iris never upgrades
or changes a device. See [Change assistance](/iris-ai/change-assistance).

## Where a skill applies

A skill can say where it applies, tested against what Correlix has discovered
about the device in scope. For example, `ospf-adjacency` applies to a device
with OSPF, `isis-adjacency` to one with IS-IS, `sdwan-overlay` to an SD-WAN
overlay member and `evpn-vxlan-overlay` to a data-centre leaf or spine.

A fact has three states, never two:

| State | Meaning | What Iris does |
|---|---|---|
| holds | Correlix observed it (for example, the device reports OSPF neighbours) | runs the skill |
| fails | Correlix read the source that would show it, and it is not there | does not run the skill; says why and moves to a method that fits |
| unknown | nothing that would show it was read | runs the skill and says what could not be established |

Unknown is the common case, and it is never treated as absent. Some facts are
only ever observed, never concluded absent:

- **Protocols.** OSPF, IS-IS and BGP are seen from the neighbours the device
  itself reports. IS-IS is established absent only when the device reports
  IS-IS administratively off and has no IS-IS neighbours. OSPF is established
  absent only when the device reports **both** OSPFv2 and OSPFv3 off and has no
  OSPF neighbours. BGP is never concluded absent.
- **Telemetry lanes.** Syslog, SNMP traps and flows are marked seen when the
  device sent on that lane in the last 24 hours. A quiet lane stays unknown:
  silence is not proof that the lane is not configured.

Facts are worked out by the server from your own inventory and telemetry. The
model never supplies one.

## How it works

Each skill is one `SKILL.md` file compiled into the backend. Its frontmatter
declares `when_to_use` phrases, `symptom_kinds`, the `tools` it may call, the
`gather` plan, what to `look_for`, and its `decisions`, which include the
`next=` hand-offs it may take. The prose below the frontmatter is the method
itself.

Three properties follow from that shape:

- **The plan is inspectable before a model runs.** A network engineer can review
  a method without reading Go.
- **A method cannot claim a capability the platform lacks.** The loader fails on
  any tool, argument, entity or `next=` target that does not exist, which fails
  CI, so the methods cannot drift away from the product.
- **A skill cannot widen what the caller may run.** Skills are compiled in and
  cannot be uploaded. Every gather step is re-gated at execution against the
  caller's principal. Every tool reads; none changes a device. The only tools that send anything are the active probes (ping, traceroute, DNS and HTTP tests from Correlix's own collector), and they run only as authored method steps when the probe switch is on — never at a model's choice (see [Investigations](/iris-ai/investigations)). In a gather
  step, a bare identifier binds from the server-resolved entity of that name,
  never from model text; a step whose entity is unavailable is skipped honestly
  rather than guessed at.

How a skill is chosen depends on whether the AI add-on is on:

- **AI add-on on.** One quick model call reads the question and picks the
  answer path (and the skill, where the path takes one) from a closed list the
  server writes. It selects a method, never data: the chosen skill still runs
  behind the same tools, checks and evidence rules. A question asked again is
  answered from a cache without a model call.
- **AI add-on off, or the model unavailable.** Iris picks the skill from the
  question's wording. The same question picks the same skill, and the reason is
  shown. Skills never pre-empt an answer that already has a better direct path,
  such as a product question or a shift hand-off.

### Chaining

An investigation runs up to **4 rounds** in one turn. The next skill is chosen
in this order:

1. **An authored machine condition.** A `next=` line may carry a condition from
   a closed vocabulary, evaluated against facts the server derived from the
   evidence so far: signature ids that fired, tool outcomes, evidence kinds,
   verdict tiers, collection-note tokens and typed device-state facets. The
   first rule that holds wins, in authored order.
2. **A closed model choice.** If no rule fires, the model may name one skill,
   and only from that skill's own declared `next=` targets. Anything else is
   refused and audited.
3. **Stop.** No rule fired and no valid proposal, or the target was already
   visited, or a budget is exhausted.

No fact is ever taken from model text. Entities are resolved once per turn under
the caller's tenant, so a skill selected in round 3 cannot resolve a new device
or widen the scope.

### The budget

| Bound | Value |
|---|---|
| Rounds per turn | 4 |
| Tool calls per round | 6 |
| Tool calls per turn | 16 |
| Wall clock per turn | 45 seconds |
| Reserve kept for narration | 8 seconds |

The reserve exists so a turn narrates what it already has instead of dying
mid-investigation with nothing to show. **Every budget stop is disclosed** as a
collection note and lifted into the answer's missing-evidence list, so the
honesty is structural rather than left to the narrative.

## The honest limits

- A chain of one hop draws no breadcrumb: the skill chip already says which
  method ran.
- A skill answer reasons over several tool results at once, which makes it the
  most fabrication-prone surface in the product. It is always routed to the
  strongest tier and always passes the grounding verifier.
- If the skill set fails to load, the layer is disabled and the failure is
  logged loudly. Every other answer path keeps working, and no method is
  silently degraded.

## Related

- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Investigation memory](/iris-ai/memory)
- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
