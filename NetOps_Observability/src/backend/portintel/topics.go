package portintel

// topics.go — the ingestion topic names for the Port Intelligence plane (#94,
// owner spec). Follows the existing bus convention (netops.<domain>.<...>.vN,
// cf. appIdentityTopic "netops.app.identities.v1"). The collectors (P3) publish
// normalized payloads here; the router folds them into the relational
// current-state tables (0019) and the TSDB metric families.
//
// Cardinality law is enforced at the ROUTER, not the topic: inventory identity
// fields (serial/part) go to relational storage; only the numeric metric
// families carry TSDB series, keyed by the stable (device, port[, lane]) tuple.
const (
	TopicInventory = "netops.port.inventory.v1" // InventoryPayload
	TopicMetrics   = "netops.port.metrics.v1"   // port counters (→ TSDB)
	TopicLanes     = "netops.port.lanes.v1"     // LanePayload (→ TSDB lane family + port_lane_current)
	TopicOptical   = "netops.port.optical.v1"   // DDM/DOM + CoherentPMPayload (→ TSDB optics/coherent families)
	TopicEvents    = "netops.port.events.v1"    // EventPayload (→ port_event_log)
	TopicHealth    = "netops.port.health.v1"    // computed port-health snapshots (→ port_health_current)
)

// AllTopics is the registration list for the bus wiring.
func AllTopics() []string {
	return []string{TopicInventory, TopicMetrics, TopicLanes, TopicOptical, TopicEvents, TopicHealth}
}
