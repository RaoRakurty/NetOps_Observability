---
name: dns-resolution
layer: services
version: 2
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/kepner-tregoe-network-troubleshooting/references/domain-signatures.md
when_to_use: ping by ip works, works by ip, works by address, name resolution, not resolving, cannot resolve, can't resolve, does not resolve, doesn't resolve, dns not resolving, dns not working, dns failure, dns failing, dns down, dns is down, dns timeout, dns slow, nxdomain, resolver not answering, resolver down
symptom_kinds: resolution, resolver
tools: get_probe_results, run_dns_test, get_rca_verdict, search_logs, get_recent_changes
gather:
  - get_probe_results(kind=dns)
  - run_dns_test()
  - get_rca_verdict(correlation_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - Whether a name resolves at all, measured — the workspace's DNS probes, their last result and how many recent runs succeeded. Correlix's prober is one vantage, not every user's machine.
  - HOW a failing probe fails. A resolver that does not answer is a path or resolver-health problem; a resolver that answers that the name does not exist is a record or zone problem. They have different owners.
  - A fresh lookup taken now from Correlix's own collector, when the workspace has turned active probes on — it confirms whether the recorded failure is still happening. Off, that step is skipped and says so; the recorded runs still stand.
  - Which resolver the probe uses — a pinned resolver or the prober's own. Pinned failing while others pass points at that resolver, not at name resolution in general.
  - The contrast that names the layer — reaching the service by address works while reaching it by name does not. That boundary sits at name resolution, not at the network path.
  - A probe that resolves cleanly while users still fail moves the question past name resolution, into the service itself.
  - A record, zone or resolver change shortly before the first failure — correlated by time, never proven by it.
decisions:
  - next=path-seam-handoff when state:dns=timeout the resolver is not answering at all, so the path to the resolver is the next check before any record theory
  - next=app-edge-5xx when state:dns=resolving the probes resolve their names, so the fault sits past name resolution in the service itself
  - next=log-confirmation when state:dns=failing the resolver answers with an error, so its own and the devices' messages must say why
  - verdict=name each DNS probe with its last result and how it failed — no answer, or the name does not exist — say which resolver it used, and for a name that does not exist name the record or zone change that preceded it
  - escalate=the DNS service owner for an internal resolver, or the DNS provider for an external zone, with the failing names, the failure class and the first failing time attached
---

# Name resolution

"It works by IP but not by name" draws the boundary for you: the network path
carries traffic, so the fault sits at name resolution. Measure it rather than
assume it.

**Read the probes first.** The workspace's DNS probes say whether names resolve
from Correlix's own prober, and how often. One prober is one vantage — a
passing probe means the resolver answered the prober, not that every user's
resolver did.

**The failure class decides the owner.** A resolver that never answers is
unreachable or unhealthy: check the path to it before any theory about records.
A resolver that answers "no such name" is working — the record or the zone
changed. Another resolver error needs the resolver's own words.

**Clean resolution moves the question on.** When the probes resolve and users
still fail, name resolution is not the fault; the service behind the name is.

**No probe, no measurement.** When the workspace declares no DNS probe, say that
name resolution is not measured here and that a probe can be added — never infer
the result.

Method re-expressed from NetClaw's domain-signature notes for DNS (Apache-2.0, see NOTICE).
