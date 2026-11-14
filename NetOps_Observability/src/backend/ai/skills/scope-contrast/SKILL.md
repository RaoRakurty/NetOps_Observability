---
name: scope-contrast
layer: analysis
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/kepner-tregoe-network-troubleshooting/SKILL.md
when_to_use: some users, others can, others are fine, while others, some users but not others, only some users, some sites but not others, only some sites, only one site, only one building, works for some, works from some, works for some users, half the users, only affects, who is not affected, what is not affected, what is affected and what is not, partial outage
symptom_kinds: contrast, scope
tools: get_rca_verdict, get_affected_entities, get_blast_radius, get_case_timeline, get_recent_changes
gather:
  - get_rca_verdict(correlation_id)
  - get_affected_entities(correlation_id)
  - get_blast_radius(correlation_id)
  - get_case_timeline(correlation_id)
  - get_recent_changes(device, window=24h)
look_for:
  - What IS affected, stated narrowly — the exact service or object and the exact failure. Cannot resolve is not cannot reach; drops are not errors; one direction is not both.
  - The nearest comparable thing that is NOT affected — the sibling site on the same transport, the user on the same switch, the second path to the same service. The unaffected neighbour rules out more causes than any affected one.
  - What separates the two sides — a site, a transport, a seam, a VLAN, a path, a software version. Name the difference; the cause lives in it.
  - When it started and when it was last known good, and what changed on the affected side at that moment. A change that merely came first is a candidate, never a conviction.
  - How much is affected and whether it is spreading or steady.
  - Any explanation that fits the affected side but contradicts the unaffected side is wrong, however familiar. Prefer the one that fits both with the fewest assumptions.
decisions:
  - next=path-seam-handoff when verdict:phrase=handoff the engine places the boundary at a handoff, so the contrast continues at that seam and its owner
  - next=osi-bisection when verdict:tier=undetermined the engine has no conclusion yet, so the contrast feeds a layer-by-layer bisection
  - next=log-confirmation when tool:get_affected_entities=not_found no incident is in scope to read the affected set from, so the devices' own messages are the evidence left
  - verdict=state what is affected and the nearest comparable thing that is not, the difference that separates them, when it started and what changed then, and the one explanation that fits both sides with the fewest assumptions
  - escalate=the owner of whatever sits on the boundary — the seam's owner, the transport's provider or the change's author — with both sides of the contrast attached
---

# Who is affected, and who is not

A fault list says what is broken. The most useful line in an investigation is
the one that says what is NOT broken but could have been.

**Draw the boundary before naming a cause.** State the affected object and its
exact failure narrowly. Then find the closest thing that should show the same
failure and does not: the site next door on the same circuit, the second user on
the same switch, the backup path to the same service.

**The difference is the lead.** Whatever separates the affected side from the
unaffected side — a seam, a transport, a VLAN, a path, a version — is where the
cause sits. A change on the affected side at the moment the failure started is
the strongest lead, and still only a candidate until evidence confirms it.

**Test every explanation against both sides.** An explanation that accounts for
what is broken but contradicts what is not broken is wrong. Keep the one that
fits both with the fewest assumptions.

**Engine first.** The engine's own scope — the affected entities and the blast
radius — is the starting contrast. With no incident in scope there is no
affected set to read, and the investigation says so.

Method re-expressed from NetClaw's structured problem-analysis guidance (Apache-2.0, see NOTICE).
