---
title: Iris skills and chaining
description: The 13 compiled-in troubleshooting methods, what a skill declares, and how one hop hands off to the next inside a bounded budget.
page_type: concept
sidebar_position: 4
---

# Iris skills and chaining

A **skill** is one troubleshooting method, written as data rather than as code.
It states when it applies, which governed read-only tools to gather with, what
to look for in the result, and where to go next. Iris selects one skill for a
question, runs its gather plan, and may hand off to another skill inside a
bounded budget.

## The 13 skills

Skills are organised by the layer they own. `method` is reserved for the entry
method, `osi-bisection`, which selects among the others instead of owning a
layer.

| Skill | Layer | Symptom kinds |
|---|---|---|
| `osi-bisection` | method | unknown, general, triage |
| `interface-down` | physical | physical, reachability, adjacency |
| `optics-degraded` | physical | physical, errors, degradation |
| `mac-flap` | l2 | l2, instability, duplicate |
| `stp-topology` | l2 | l2, instability, broadcast |
| `ospf-adjacency` | igp | igp, adjacency, routing |
| `isis-adjacency` | igp | igp, adjacency, routing |
| `bgp-session-down` | bgp | bgp, adjacency, routing, reachability |
| `bgp-prefix-missing` | bgp | bgp, routing, policy, reachability |
| `path-seam-handoff` | path_seam | path, loss, latency, ownership |
| `app-edge-5xx` | application | application, errors, latency |
| `security-exposure-context` | security | security, posture, exposure |
| `log-confirmation` | logs | confirmation, logs, timing |

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
  caller's principal, and every tool is read-only by construction. In a gather
  step, a bare identifier binds from the server-resolved entity of that name,
  never from model text; a step whose entity is unavailable is skipped honestly
  rather than guessed at.

Skill selection is deterministic. The same question picks the same skill, and
the picker's reason is returned so it can be shown and tested. Skills never
pre-empt intents that already have a better deterministic answer, such as a
product question or a shift hand-off.

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
