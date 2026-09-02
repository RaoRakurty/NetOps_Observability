---
name: security-exposure-context
layer: security
version: 1
when_to_use: exposure, security finding, vulnerability, cve, hardening, posture, compliance, misconfiguration, weak cipher, open port, risk on this device, attack surface
symptom_kinds: security, posture, exposure
tools: get_security_findings, get_topology_context, get_rca_verdict, get_device_health
gather:
  - get_security_findings(device, current=true)
  - get_topology_context(device_id)
  - get_rca_verdict(correlation_id)
look_for:
  - The CURRENT verdict per finding, not the whole verdict history. A finding that was remediated last week should not be reported as exposure today.
  - Which seam the finding sits on. An exposure on an internet-facing seam and the same exposure on an internal seam are not the same risk.
  - Whether the finding is corroborated by anything operational. Security evidence is one evidence class among four here; it supports a network conclusion, it does not replace one.
  - Coverage. Say plainly which devices were assessed and which were not, because an unassessed device reads as clean if you do not.
decisions:
  - next=osi-bisection when verdict:tier=confirmed a confirmed outage verdict is in scope, so the operator's real question is the outage rather than posture
  - next=path-seam-handoff when the exposure is on a seam whose owner is not us
  - verdict=name the finding, its severity, its seam and whether it is current, and state the assessed scope
  - escalate=the security owner for remediation — this platform reports exposure, it does not remediate it
---

# Security exposure context

Correlix is network-first. Security findings are the fourth evidence class, and
this skill exists to answer "what is my exposure here", not to run a SIEM
investigation.

**Current state, not history.** Report the latest verdict for each finding.
Retained history is available but is almost never the answer to an operator's
question, and mixing the two inflates the count.

**Seam decides severity in practice.** The same weak cipher is a different
problem on an internet-facing handoff than on a management VLAN. Always report
the seam alongside the severity.

**Do not manufacture causality.** A device with open findings that is also in an
outage is not thereby explained by those findings. If security evidence
corroborates the operational picture, say how; if it does not, say that it is
context rather than cause.

**Report coverage explicitly.** "No findings" and "not assessed" look identical
in a list and mean opposite things. Name the assessed scope every time.

**Never emit remediation commands.** This skill produces a named finding, a
severity, a seam and an owner. Fixing is a human, ticketed action outside this
assistant.
