# Notification & Ticketing Architecture (#103)

Two lanes, one framework. Customer-facing destinations are tenant-scoped and
RCA-policy-driven; operator/platform channels are global and raw-alert-driven
by design.

```mermaid
flowchart TB
    subgraph SRC["Signal sources"]
        RAW["Raw alerts<br/>(alert engine, rules.yaml)"]
        CORR["Correlated RCA objects<br/>(correlation engine, verdicts)"]
    end

    subgraph TENANT["TENANT-SCOPED — customer incident lane (per-tenant credentials, RLS, policy-gated)"]
        SWEEP["Ticket sweeper<br/>per (tenant × system) policy resolution<br/>one enabled policy per system · opt-in for paging/chat"]
        POL{{"Incident policies<br/>verdict / severity / customer-facing /<br/>persistence gates · priority-urgency mapping"}}
        OUTBOX[("Transactional outbox<br/>SKIP-LOCKED worker · backoff+jitter ·<br/>Retry-After · dead-letter ·<br/>tenant assertion before EVERY external call")]
        LINKS[("ticket_links<br/>PK (tenant, corr object, system)<br/>= dedup identity store")]
        SN["ServiceNow adapter<br/>Table API · INC per root cause<br/>default-on MVP policy"]
        PD["PagerDuty adapter<br/>Events v2 · dedup correlix:tenant:corr:pd<br/>trigger/update/resolve one identity · OPT-IN"]
        SLK["Slack adapter<br/>tenant webhook · opened/updated/resolved<br/>messages per root cause · OPT-IN"]
        JIRA["Jira (roadmap:<br/>same pattern)"]
    end

    subgraph PLAT["PLATFORM-GLOBAL — operator self-health lane (engine-independent)"]
        GATE["Severity gate + PlatformScopeFilter<br/>allowlist: layer ∈ stack·host·clickhouse·platform<br/>customer alerts REJECTED (default-closed)"]
        GPD["Global PagerDuty key<br/>(platform health ONLY)"]
        GSLK["Operator Slack / email / SMS / ntfy"]
        WD["stack-watchdog cron<br/>(container OOM/restart sentinel,<br/>independent of the whole stack)"]
    end

    CORR --> SWEEP --> POL --> OUTBOX
    OUTBOX --> SN & PD & SLK
    OUTBOX -.-> JIRA
    SN & PD & SLK --> LINKS
    RAW --> GATE
    GATE --> GPD & GSLK
    RAW -. "resolutions always pass" .-> GPD
    WD --> GPD

    style TENANT fill:#0b2545,stroke:#3e6fb0,color:#e8eef7
    style PLAT fill:#332114,stroke:#b07a3e,color:#f7efe8
    style SRC fill:#1a1a2e,stroke:#666,color:#eee
```

## Invariants

1. **Raw customer alerts never reach a customer destination.** Only correlated
   RCA objects, through a tenant policy.
2. **One external incident per root cause per destination** — identity =
   `(tenant, correlation UUID, system)`; storms, retries, and crashes reuse it.
3. **Per-tenant credentials, write-only**, tenant asserted at delivery time;
   a mismatched connection is quarantined, never sent.
4. **Platform lane is engine-independent** — it must page even when
   correlation is down, which is why it stays raw-alert-driven behind a typed
   allowlist, and why the watchdog lives outside the stack entirely.
5. **Connectors are independent** — any combination per tenant; one
   destination's failure retries alone (separate outbox rows per system).
6. **Resolutions bypass severity, never scope** (#103-H): a customer or
   untyped resolution is rejected from the platform lane (default-closed,
   counted); an in-scope resolution for a never-opened incident is a safe
   destination-side no-op.
7. **Lifecycle cannot move backward**: the ticket link's state is the
   ordering authority — duplicate OPENs, stale UPDATE/OPEN after RESOLVE,
   and repeated RESOLVEs become audited no-op successes
   (`noop_duplicate` / `noop_stale_after_resolve`), never external calls.
8. **Platform deployment identity is trusted config** (PLATFORM_ENV /
   PLATFORM_REGION): staging cannot open or resolve production incidents;
   regions never share dedup identity; unset preserves legacy keys.
9. **Stable root-cause identity**: dedup keys on `(tenant, correlation-object
   UUID, system)` — the object UUID is version-stable (versions are rows
   under it; merges redirect to the canonical survivor); tenant slugs /
   display names / policy names never participate in identity.
10. **Connection scoping (MVP decision, documented)**: today one connection
   per (tenant, system) — the system name IS the default connection
   discriminator in keys and the one-enabled-policy invariant. Multi-
   connection (two PD services, regional SNOW instances) extends the same
   fields with a real connection id + migration; nothing hard-codes against it.
```
