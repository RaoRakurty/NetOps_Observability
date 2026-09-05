// Package dem is the Digital Experience Monitoring domain: the per-tenant
// catalogue of experience TARGETS, the identity model every experience
// measurement is stamped with, and the pure score maths that turns raw
// measurements into an availability / latency / path-stability verdict.
//
// WHY IT IS ITS OWN PACKAGE (CLAUDE.md §2 + the root file-count ratchet):
// experience monitoring is a new domain, so it starts in a real subpackage on
// day one. The root package keeps only the wiring (backend selection, the RBAC
// gate mapping, the route registrations) — no business logic.
//
// # THE ONE FACT
//
// Everything here is built around a single fact type, [Measurement]: "subject X
// of tenant T, observed from source S, was reachable/not at time TS with these
// timings". Today exactly one source produces it — the synthetic prober
// (ICMP / TCP / DNS / HTTP checks against catalogue targets). The identity
// model ([Identity]) and the metric series it is stamped into are deliberately
// source-agnostic so the later feeds named in the DEM data model —
// SD-WAN controller per-app SLA, wireless-controller client experience,
// flow-derived application response time, endpoint agents and browser RUM —
// land on the SAME series and the SAME score maths without a schema break.
// See docs/design/DEM_DATA_MODEL_2026-09-05.md.
//
// # ZERO TRUST / ISOLATION (§3, §3a)
//
// The catalogue is per-tenant DATA, not platform plumbing: every read and write
// is scoped to ONE concrete tenant, resolved from the caller's token and never
// from the request body. Isolation lives in the store (§3a rule 4) — the file
// store keys rows by tenant so a lookup for tenant A can only ever walk A's
// bucket, and the Postgres store runs every statement inside WithTenant so the
// `tenant_iso` FORCE-RLS policy always has its GUC. There is no "list every
// tenant's targets" method on the tenant surface; the ONLY cross-tenant read is
// [Catalogue.ListAll], which exists solely so the prober's target projector can
// publish the fleet's work queue, and which no HTTP handler may call.
//
// # HONESTY (§10)
//
// A score is never fabricated. When no measurement exists for a window the
// result carries Measured=false and a Reason naming why (feature off, no
// targets, target paused, prober not reporting, window empty) — never a zero
// that renders as "100% broken" or "perfectly healthy".
package dem

// Environment switches this module reads. Declared as constants so the
// integrator (which does the os.Getenv) and the operator documentation cannot
// drift apart — the env-docs guard checks that every documented switch is
// consumed by real code.
const (
	// EnvFeatureFlag turns Digital Experience Monitoring on. Default-off: the
	// prober is a privileged sidecar and an active-measurement plane must never
	// start itself (ADR 0001).
	EnvFeatureFlag = "FEATURE_DEM"
	// EnvTargetsFile is the file backend's catalogue path.
	EnvTargetsFile = "DEM_TARGETS_FILE"
	// EnvProjectInterval is how often the api republishes the prober's work
	// queue. Short enough that a new target starts being measured promptly,
	// long enough that the queue is not a busy loop.
	EnvProjectInterval = "DEM_PROJECT_INTERVAL"
)
