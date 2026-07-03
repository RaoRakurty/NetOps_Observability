package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// mustJSON marshals v, returning nil on error (best-effort raw-payload capture).
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// normalize.go — shared normalization helpers used by every transformer so
// severity, time, and evidence-role mapping stay consistent across vendors.

// normSeverity maps a vendor severity string to the canonical set
// info|warn|high|crit (matching corr_signals). Unknown → warn (safe middle).
func normSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical", "crit", "p1", "emergency", "1", "fatal", "severe":
		return "crit"
	case "high", "major", "error", "p2", "2", "alert":
		return "high"
	case "info", "informational", "p4", "notice", "debug", "4", "low", "cleared", "clear":
		return "info"
	default: // warning, minor, p3, medium, ...
		return "warn"
	}
}

// msToTime converts vendor epoch-millis to UTC time (0 → zero time).
func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// parseTime parses an RFC3339-ish timestamp; zero time on failure.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// roleForEventType assigns a default evidence role from the normalized event
// type. Policy changes are DISCRIMINATING ("what changed?"); everything else is
// SUPPORTING by default (the engine downgrades to CONTRADICTING at correlation
// time when it conflicts with direct telemetry — that's a correlation-time
// decision, not a transform-time one).
func roleForEventType(net string) EvidenceRole {
	if net == "controller_policy_change" {
		return RoleDiscriminating
	}
	return RoleSupporting
}

// upDownState maps common vendor state words to up|down (else the raw value).
func upDownState(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "up", "reachable", "connected", "active", "green", "success", "deployed":
		return "up"
	case "down", "unreachable", "disconnected", "inactive", "red", "failed", "fail":
		return "down"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}
