# Contact points + report delivery (Reports ↔ notifications)

> Status: **design** (2026-06-02). Decisions locked (user): **contact-points
> model** (reusable audiences referenced by reports *and*, later, alerts) and
> **per-report delivery mode** — author chooses **email-the-report** or
> **secure link**. Builds on the notify layer (`notify/dispatcher.go`) and the
> report scheduler (`report_scheduler.go`). Related: `secret-custody.md` (signed
> links), tenancy (#33/#20).

---

## 1. Problem

Today a report's "email" delivery routes to the notify Dispatcher's single
`email` channel, whose recipients are the **one global `smtpConfig.To` list**
(`notify_config.go:34`, `buildEmailChannel` → `WithRecipients(c.To)`). There is:
- no per-report recipient choice (every report emails the same global list),
- no named groups / distribution lists,
- no tenant scoping of recipients,
- only "email the rendered body" (no secure-link option).

The "Send now" picker chooses *channels* (`Names()`), never *recipients*.

## 2. Model — contact points as an ADDITIVE routing layer

A **contact point** is a reusable, named, tenant-scoped audience:

```
ContactPoint {
  ID        string
  TenantID  string            // owner; '' = platform/global
  Name      string            // "NOC On-call", "Acme Execs"
  Type      string            // email | slack | webhook (extensible)
  Email     []string          // for type=email (a distribution list / group)
  Target    string            // slack webhook URL / generic webhook URL
  Enabled   bool
}
```

**Crucially, this does NOT replace the existing `notify.Channel` registry.** The
registered channels (email/slack/pagerduty/sns/twilio/…) and the alert path keep
working unchanged. Contact points are a *routing layer* on top:

- Reports reference contact points by id.
- At delivery, each contact point is **resolved to a concrete send** by reusing
  the existing notify constructors with overridden recipients — e.g. an
  email-type point → `notify.NewEmail(smtp host, from).WithRecipients(point.Email)`
  using the SMTP transport from `smtpConfig`, then `Send`. No global channel
  state is mutated.

This de-risks the "refactor": alerts are untouched until Phase 4 opts them in.

## 3. Delivery modes (per report)

`reportSpec` gains:
```
ContactPoints []string  // contact-point ids this report targets
DeliveryMode  string    // "body" (email the rendered report) | "link" (secure link)
```

- **body** — current behavior: render the report, email it to the resolved
  recipients (now the contact points' addresses, not the global To).
- **link** — email a **short-lived signed link** to a report-view endpoint
  instead of the data. Recipients click through to an authenticated view. Keeps
  tenant data out of inboxes/forwards (SaaS-safe). Mechanism in Phase 3.

## 4. Phased build

| Phase | Deliverable |
|------|-------------|
| **1 (backend foundation)** | `contactpoints.go`: tenant-scoped `contactPointStore` (kv-backed, same pattern as the other stores) + CRUD API `GET/POST/PUT/DELETE /api/notify/contact-points` (admin-gated, tenant-scoped via `principalTenant`/`sameTenant`); resolver `resolveContactPoints(ids) → recipients/targets`. Unit tests. |
| **2 (reports wiring + UI)** | `reportSpec.ContactPoints` + `DeliveryMode`; scheduler resolves contact points and delivers (body mode) via transient sends. Frontend: manage contact points in the Notifications section; report create/edit + "Send now" gain a contact-point multiselect + delivery-mode toggle. |
| **3 (secure link)** | Signed, short-lived report-view endpoint (`GET /api/reports/view?token=…`, HMAC over report id + tenant + exp, reuse `JWT_SECRET`/jwt.go); link-mode email template; render the saved report read-only behind the token. |
| **4 (alerts adopt contact points + routing — later)** | Optional notification-routing policies (severity/tenant/tag → contact points) so alerts use the same audiences. The full Grafana/Datadog "contact points + notification policies" model. Sequenced after Reports proves the model. |

## 5. Tenancy & security

- Contact points carry `TenantID`; a tenant admin manages/sees only its own
  (handler enforces `sameTenant`, like users/api-keys). Platform owner sees all.
- A report may only target contact points visible to its owning tenant
  (validated at save + at delivery).
- Email-type contact points hold addresses (not secrets) → fine in app-state.
  The SMTP *credentials* stay in `smtpConfig` and move under secret-custody
  (`secret-custody.md`) separately.
- Link mode: token is short-lived, HMAC-signed, tenant-scoped; the view endpoint
  re-checks the caller is allowed to see that tenant's report.

## 6. Reuse / touch-points

- `notify/dispatcher.go` (`Channel`, `NewEmail().WithRecipients`) — reused for
  resolution; no interface change in Phase 1.
- `notify_config.go` (`smtpConfig`) — source of the SMTP transport for email
  contact points; add a `GET` the UI uses to know email is configured.
- `report_scheduler.go` (`reportSpec`, `deliver`) — Phase 2 resolution hook.
- `tenancy.go` (`principalTenant`, `sameTenant`) — contact-point scoping.
- `jwt.go` / `JWT_SECRET` — Phase 3 signed links.

## 7. Open decisions

- Contact-point store: dedicated kv store now (Phase 1), normalize into an RLS
  table later (#33 pattern) — not in the critical path yet.
- Whether Phase 4 routing policies live here or in the alert engine — defer.
