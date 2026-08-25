# Correlix Compliance Model — enhanced (2026-08-25)

Owner's model, enhanced with the layer separation (§5h provider principle),
the honesty/versioning details, and the tie into correlation. The relationships
are the point: a Check satisfies MANY Controls; a Control needs MANY Checks; a
Control maps to MANY frameworks (all M:N). Correlix OWNS the middle; everything
external is a swappable provider.

```
                     CORRELIX COMPLIANCE MODEL
        (Correlix OWNS the model; externals are interchangeable providers)

  FRAMEWORK LAYER   ── providers: NIST/OSCAL · PCI · CIS · ISO · STIG ──
                       abstract + versioned; added INDEPENDENTLY; licensed
                       content stays behind its provider (never redistributed)
        NIST 800-53        PCI-DSS         CIS/STIG        ISO 27001
             ▲                ▲               ▲               ▲
             └────── crosswalk (M:N, via the 800-53 hub) ─────┘
                                 │                    coverage % per framework
                                 │                    (honest: not every control
  CONTROL LAYER (owned, canonical)                     is check-verifiable)
        ┌──────────────── Control ─────────────────┐
        │        id · family · VERSION             │
        └────────────────────┬─────────────────────┘
                             │  satisfied-by  (M:N)
                             ▼
  CHECK LAYER (owned catalog; concept-level, vendor-neutral — §5e)
        ┌───────────── Technical Check ────────────┐
        │  detect logic + REMEDIATION (per vendor) │  ← "what to configure"
        │  severity · control tags · seam-aware?   │
        └────────────────────┬─────────────────────┘
                             │  collected-by  (interchangeable AssessmentProviders, §5h)
          ┌──────────┬───────┴───┬────────────┬──────────────┐
      NETCONF/     Vendor      OpenSCAP     Correlix       CIS-CAT
       gNMI         API         /SSG        net-rule       (OPTIONAL — no
     (capture)   (advisory)   (Linux)      engine (net)    core dependency)
          └──────────┴───────────┴────────────┴──────────────┘
                             ▼
  EVIDENCE  ── BY-REFERENCE: immutable pointer to the raw OS doc / CH row /
               config line / OVAL result.  VERSION-PINNED: (control, check,
               ruleset) versions stamped, so any past verdict is replayable.
                             ▼
  VERDICT   ── OCSF-normalized: Pass · Warning · Fail · NotApplicable · Error.
               NEVER a false "clear"; an unassessed control/device shows as
               UNASSESSED, not green.
                             ▼
  ROLL-UP   ── Exposure  ·  Risk score  ·  Drift (in-sync / not-in-sync)
                             │
                             ▼   emitted as a PRODUCER onto the bus
                CORRELATION ENGINE grounds it on (entity + seam)
                             ▼
                     EXPOSURE STORY  (the flagship)
                (removable-module seam: the engine has ZERO compliance code —
                 it grounds a generic evidence object like any other)

  CROSS-CUTTING:  §3a tenant-scoped everywhere · everything version-pinned ·
                  providers swap behind interfaces · Correlix owns the
                  normalized model, never depends on any one tool's shape.
```

## What the enhancement adds to the base model

1. **Framework layer is a PROVIDER layer** (not baked in): NIST/OSCAL, PCI,
   CIS, ISO are abstract, versioned, added independently; the crosswalk goes
   through the **800-53 hub** (one control tag → many frameworks, no N² maps).
   Licensed content stays behind its provider.
2. **Cardinality made explicit** — Check↔Control and Control↔Framework are both
   **M:N**. A check satisfies several controls; a control needs several checks;
   the same finding rolls into PCI *and* HIPAA *and* CIS at once.
3. **Coverage % honesty** — not every control is check-verifiable (admin/
   physical/process controls aren't); the model shows what fraction a config
   audit can actually evidence, so no overclaim (§5d).
4. **Collection = interchangeable AssessmentProviders** (§5h) — NETCONF/gNMI,
   vendor API, OpenSCAP, the Correlix network-rule engine, and CIS-CAT as an
   OPTIONAL provider with no core dependency. Add/replace with zero core change.
5. **Remediation on every check** — the "what to configure to harden," per
   vendor dialect (§5e) — carried from Check → Finding.
6. **Evidence by-reference + version-pinning** — the pointer, not a copy;
   (control, check, ruleset) versions stamped so a past verdict is replayable
   (the auditor requirement, §5c).
7. **Verdict is OCSF-normalized, not binary** — Pass/Warning/Fail/NotApplicable/
   Error, and unassessed renders as unassessed, never a false clear.
8. **The roll-up feeds correlation** — Exposure/Risk/Drift are emitted as a
   generic evidence object onto the bus; the correlation engine grounds it into
   the **exposure story** with zero compliance-specific code (the removable-
   module seam). This is the line from "a failed check" to "a seam-owned
   incident narrative."

The through-line: **Correlix owns the Control / Check / Finding / Evidence
model; frameworks, scanners, capture methods, and CVE feeds are all providers
behind interfaces** — swap any one, the model is untouched.
