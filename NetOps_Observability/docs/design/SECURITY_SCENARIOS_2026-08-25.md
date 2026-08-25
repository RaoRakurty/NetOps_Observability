# Security design — two realistic end-to-end flows (2026-08-25)

Two scenarios that exercise the finalized security design end-to-end, showing
which module produces what and where the data flows. Scenario A is the
PREVENTIVE / posture flow; Scenario B is the DETECTIVE / correlation flow (the
flagship exposure story). Both assume the config-backup, hardening-audit, and
security lanes are enabled (opt-in modules).

---

## Scenario A — "A change left the management plane exposed" (posture flow)

**Situation:** an engineer edits `br-edge-07`, a branch edge router whose
DIA/INET interface faces the ISP seam, during a Tuesday maintenance window. In
the change they enable Telnet for a quick test and remove the VTY access-class,
intending to put it back — and forget.

**The flow:**

1. **Capture (config-backup module).** The device emits `SYS-5-CONFIG_I`. The
   backup module's on-change trigger fires within minutes: it captures the new
   running-config over the audited SSH gateway, seals it under the tenant DEK,
   and stores a new content-addressed version. (No new version if nothing
   changed — but it did.)

2. **Drift / sync (device inventory).** The new running-config no longer
   matches the golden baseline. `br-edge-07` flips on the Devices inventory
   from **In sync → Not in sync**, badge linking to the diff (secrets
   redacted). Because it happened inside a maintenance window, the drift is
   classified **planned** — so it does not, by itself, page anyone.

3. **Hardening re-audit (security/compliance lane).** The config change re-runs
   the network hardening rules against `br-edge-07` (only this device, only the
   affected rules — the evaluate-on-change efficiency). Two rules fire:
   - `net-telnet-enabled` — Telnet on VTY.
   - `net-mgmt-exposed-untrusted-seam` — and this is the differentiator: the
     engine knows the VTY is reachable via the interface on the **ISP seam**
     and there is now **no access-class**. A plain CIS scanner would say
     "Telnet is on." Correlix says **"Telnet is on AND reachable from the
     internet with no ACL → EXPOSED (critical)."**

4. **Finding with remediation (ComplianceFinding → OCSF).** The lane emits a
   `ComplianceFinding` (evidence_class `posture`): status Fail, severity
   critical, resource `br-edge-07`, and the **remediation the owner asked for**,
   in the device's dialect:
   > "Telnet enabled on VTY, reachable from the ISP seam with no access-class.
   > Harden: `line vty 0 4 / transport input ssh / access-class MGMT-IN in`."
   It is tagged to its controls — CIS L1, NIST **CM-6 / AC-17 / SC-8**, and via
   the 800-53 crosswalk it rolls up to **PCI-DSS Req 2.2** (no insecure
   services) and **Req 1** (network access control). Coverage %, not
   "PCI compliant."

5. **Surfacing.** It appears on the Security → Exposure/Findings surface AND as
   a red exposure marker on `br-edge-07` in the inventory. Because it is
   **critical + internet-exposed**, it pages regardless of the planned-window
   classification (an insecure result is insecure whether or not the change was
   planned — the window suppresses NOISE, not CRITICAL exposure).

6. **Close the loop.** The NOC operator reads the finding, applies the one-line
   remediation (optionally IRIS proposes it as a `propose_device_check`/config
   card the operator approves — never auto-applied), re-audit runs on the next
   config change, the finding clears, and `br-edge-07` returns to **In sync**.
   The whole exchange — drift, finding, fix, re-verify — is one evidence trail.

**What this flow proves:** capture → drift/sync badge → seam-aware exposure
(the wedge) → remediation-in-the-finding → framework rollup → honest
planned-vs-unplanned. All from telemetry and config Correlix already has.

---

## Scenario B — "The exposure story" (detective / correlation flow — the flagship)

**Situation:** 02:40, no human made a change. `core-r1` is an internet-facing
edge router on the ISP seam for tenant Acme-East. It has been quietly carrying
a KEV-listed CVE on its IOS-XE for a week. An attacker with stolen credentials
begins working.

**The flow — four independent lanes, one story:**

1. **Vuln/exposure lane (already standing).** `core-r1` already carries an
   `ExposureFinding`: KEV-listed CVE on IOS-XE 17.9.x, exposure score elevated
   because the **seam model** says it is internet-facing and EoL is approaching.
   This has been open, informational, for a week.

2. **Config-drift + threat lane (02:41).** A config change appears on `core-r1`
   **outside any maintenance window** → drift classified **unplanned** →
   inventory flips to **Not in sync**. The hardening/threat re-audit sees three
   things at once, MITRE-tagged: a **new local user**, a **new GRE tunnel
   interface** (the Salt Typhoon TTP), and the **syslog target removed**
   (logging disabled — the ArcaneDoor tell). Each becomes a `SecuritySignal`
   emitted onto the bus.

3. **Flow lane (02:44).** NetFlow shows a **new persistent low-jitter flow**
   from `core-r1`'s control plane to a previously-unseen ASN — beaconing shape.
   Another `SecuritySignal`.

4. **DEM lane (02:50).** Branch-site experience scores degrade on the paths
   that transit `core-r1`. A `ConfigDrift`/experience signal.

5. **The correlation engine folds them into ONE exposure story.** This is the
   crux and the modularity payoff: the engine has **zero security-specific
   code**. Each lane emitted a generic evidence object carrying
   `entity=core-r1 + seam=ISP + timestamp + evidence-refs`. The engine grounds
   them the same way it grounds a link-down or a BGP flap — on the shared
   entity and seam — and, seeing them cluster on `core-r1` within minutes,
   promotes an **Exposure Story**:

   > "Branch experience degradation and anomalous egress from `core-r1`
   > **possibly because of** compromise via CVE-XXXX. Evidence chain:
   > [KEV CVE, internet-facing seam] → [unplanned config change: new user +
   > GRE tunnel + logging disabled] → [beaconing flow to AS-nnnnn] →
   > [branch paths degraded]. Ownership: **LAN edge — yours** (not the ISP,
   > not the app team). Mobilize: isolate `core-r1` / apply interim ACL /
   > golden-image upgrade."

   Every edge in that chain cites its raw evidence (the config diff, the flow
   series, the advisory, the path metrics) — the inspectable causality no NDR
   or digital-twin competitor can produce.

6. **IRIS narrates, the operator acts.** IRIS writes the plain-language summary
   with citations and proposes next steps as approve-cards ("isolate core-r1",
   "draft the outreach") — human-in-the-loop, never auto-executed. The operator
   confirms; every action lands in the story's evidence log, which becomes the
   post-incident record.

**What this flow proves:** the flagship. Four disconnected alerts every other
tool would make an operator correlate by hand become ONE seam-attributed story
with an evidence chain and a next action — and it is literally the CTEM loop
(Scope → Discover → Prioritize → **Validate with live telemetry** → Mobilize).
The "validate with observed telemetry" step is what a pure exposure/twin vendor
cannot do, and the seam ownership ("yours, the LAN edge") is what the RCA
philosophy already does for outages, now applied to compromise.

---

## The through-line

Both flows are the same architecture: security lanes are **producers** emitting
generic evidence; the correlation engine is a **generic consumer** that grounds
evidence on entities and seams; findings carry **remediation**; verdicts are
**honest** (planned-vs-unplanned, coverage %, "possibly because of", exposed-
vs-informational by seam). Scenario A catches the exposure before it is
abused; Scenario B explains the abuse when it happens — and both are removable
(flags off → the engine keeps running, one fewer evidence source).
