package notify

import "netops/backend/models"

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

func (f *PlatformScopeFilter) Send(a models.Alert) error {
	if !PlatformLayers[a.Labels["layer"]] {
		return nil // customer-network alert: RCA policy lane territory
	}
	return f.next.Send(a)
}

// SendResolve forwards resolutions un-filtered so a previously opened platform
// incident always closes even if labels drift.
func (f *PlatformScopeFilter) SendResolve(a models.Alert) error {
	if rs, ok := f.next.(ResolveSender); ok {
		return rs.SendResolve(a)
	}
	return nil
}
