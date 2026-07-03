package nms

import "os"

// topics.go — bus topic names + the feature flag. The whole framework is dormant
// unless FEATURE_NMS_INTEGRATIONS=true (ships incrementally, off by default).

const (
	// TopicControllerEvents carries normalized controller_event records (§3.3)
	// to the correlation service (raw landing + → corr_signals).
	TopicControllerEvents = "netops.controller_events"
	// TopicEvents is the optional normalized cross-source event topic (state
	// transitions can also be emitted here).
	TopicEvents = "netops.events"
)

// Enabled reports whether the NMS integration framework is turned on.
func Enabled() bool { return os.Getenv("FEATURE_NMS_INTEGRATIONS") == "true" }
