// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
// Enabled reports whether the NMS vendor-controller framework is active. ON BY
// DEFAULT (owner directive, 2026-07-04): the runtime is read-only and inert
// until a customer actually connects a controller — an empty runtime just
// serves the static connector catalog + an empty integration list (so the
// gallery renders on a fresh install, matching the reference deployment). No
// polling, no external calls, no data until an integration is created. Disable
// explicitly with FEATURE_NMS_INTEGRATIONS=false.
func Enabled() bool {
	if v := os.Getenv("FEATURE_NMS_INTEGRATIONS"); v != "" {
		return v == "true"
	}
	return true
}
