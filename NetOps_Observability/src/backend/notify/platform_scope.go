package notify

import (
	"expvar"

	"netops/backend/models"
)

// Observability (#103-H E1): default-closed rejections are counted, never
// silent. Package-level expvars surface on /debug/vars // /metrics bridge.
var (
	platformScopeRejectedTotal        = expvar.NewInt("platform_scope_rejection_total")
	platformScopeResolveRejectedTotal = expvar.NewInt("platform_scope_resolve_rejection_total")
)

// platform_scope.go — the #103 platform self-health lane guard.
//
// The platform-global PagerDuty routing key may only page for Correlix STACK
// failures (the cases where the correlation engine itself may be down and the
// per-tenant RCA policy lane therefore cannot be trusted to page). Customer-
// network alerts (device/interface/BGP/path/flow/...) must page through the
// tenant-scoped RCA incident-policy lane instead — never the global key.
//
// Membership is an explicit allowlist of `layer` label values — the typed
// event-source marker rules.yaml stamps on stack-resilience/host/ClickHouse
// platform rules. Customer alerts carry no layer label (or a non-platform
// one) and are dropped here by default-closed matching.

// PlatformLayers is the allowlist of platform self-health alert classes.
var PlatformLayers = map[string]bool{
	"stack":      true, // container/compose resilience (ContainerDown, restart loops, …)
	"host":       true, // host memory/disk/OOM-killer
	"clickhouse": true, // CH memory/query-failure pressure
	"platform":   true, // core service reachability (ScrapeTargetDown, collectors, bus)
}

// PlatformScopeFilter wraps a paging channel and forwards ONLY platform
// self-health alerts. Resolutions always pass (closing an incident that was
// never opened is a no-op at the destination; suppressing a close is never
// safe). Default-closed: no layer label → not platform → dropped.
type PlatformScopeFilter struct {
	next Channel
}

func NewPlatformScopeFilter(next Channel) *PlatformScopeFilter {
	return &PlatformScopeFilter{next: next}
}

func (f *PlatformScopeFilter) Name() string { return f.next.Name() }

// Pages forwards the PageClassifier question through the scope filter — an
// alert this filter would drop is never delivered at all, so the answer only
// ever matters for one it forwards.
func (f *PlatformScopeFilter) Pages(a models.Alert) bool { return channelPages(f.next, a) }

func (f *PlatformScopeFilter) Send(a models.Alert) error {
	if !platformScoped(a) {
		platformScopeRejectedTotal.Add(1)
		return nil // customer-network alert: RCA policy lane territory
	}
	return f.next.Send(a)
}

// SendResolve (#103-H E1): a resolution may bypass the SEVERITY threshold
// (SeverityGate already forwards resolves un-gated) but it must NEVER bypass
// platform-SCOPE validation — a customer alert's resolution has no business
// reaching the operator's global destination, and an untyped resolution is
// treated as customer traffic (default-closed). An in-scope resolution for an
// incident that was never opened is a harmless no-op at the destination
// (Events v2 ignores unknown dedup keys) — allowed, since suppressing a close
// is never safe while forwarding one always is.
func (f *PlatformScopeFilter) SendResolve(a models.Alert) error {
	if !platformScoped(a) {
		platformScopeResolveRejectedTotal.Add(1)
		return nil
	}
	if rs, ok := f.next.(ResolveSender); ok {
		return rs.SendResolve(a)
	}
	return nil
}

// platformScoped is the ONE typed allowlist check both directions share.
// The layer label is stamped by rules.yaml (server-controlled), never by
// device/customer data; anything absent or unknown is customer traffic.
func platformScoped(a models.Alert) bool {
	return PlatformLayers[a.Labels["layer"]]
}
