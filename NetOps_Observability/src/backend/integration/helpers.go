package integration

import (
	"strings"
	"time"
)

// helpers.go — small shared utilities for the provider translators.

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseLooseTime accepts the common timestamp shapes providers emit, returning
// the zero time on failure (the ordering layer then leans on ExternalSeq).
func parseLooseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// stateToEventType classifies a canonical state token into an inbound event type.
// Used to tag the event; the reconciler still drives the transition off the
// mapped ExternalState. Resolved/ack are called out so they route correctly even
// when a tenant's state map is customized.
func stateToEventType(canonicalState string) EventType {
	switch strings.ToLower(strings.TrimSpace(canonicalState)) {
	case "resolved", "closed", "done", "cancelled":
		return EventResolved
	case "acknowledged", "ack", "in progress", "in-progress":
		return EventAcknowledged
	case "new", "open", "triggered", "reopened":
		return EventCreated
	default:
		return EventUpdated
	}
}
