package tac

// wire.go — the pure helpers the HTTP adapter needs.
//
// They live here rather than in the root package for a mechanical reason and a
// real one. Mechanically, the root package is at its growth ceiling and its TAC
// adapter has a line budget a test enforces. Really: none of these is an HTTP
// concern. Extracting hypothesis ids from a correlation blob, deciding what to
// say when no capture transport is wired, and shaping the class list an operator
// may override to are all decisions ABOUT THE ESCALATION, and they are testable
// here without a server, a socket or a request.

import (
	"regexp"
	"strings"
	"time"
)

// templateIDRE extracts hypothesis template ids from the correlation object's
// JSON-encoded `hypotheses` column WITHOUT unmarshalling a schema this package
// does not own. The ids have a fixed, closed shape, so a scan over the blob is
// both cheaper and less brittle than tracking the correlation engine's struct.
var templateIDRE = regexp.MustCompile(`sig\.ent\.[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?`)

// maxExtracted bounds every extraction below (§9): these read a blob that came
// from a store, and a pathological row must not become an unbounded slice.
const maxExtracted = 64

// HypothesisIDs returns the distinct hypothesis template ids in a correlation
// blob, in first-seen order.
func HypothesisIDs(blob string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range templateIDRE.FindAllString(blob, maxExtracted) {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// deviceRE extracts device ids from an `affected` JSON blob.
var deviceRE = regexp.MustCompile(`"([A-Za-z0-9][A-Za-z0-9._:@+-]{0,63})"`)

// AffectedDevices returns the distinct device references in an `affected` blob.
// It is only a HINT for the UI's device picker default — the device a collection
// actually runs against is always resolved through the caller's own inventory.
func AffectedDevices(blob string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range deviceRE.FindAllStringSubmatch(blob, maxExtracted) {
		v := m[1]
		if seen[v] || len(out) >= 16 {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// ParseTime reads the timestamp shapes the platform's stores emit. An
// unparseable value is the zero time, which every caller renders as "not
// recorded" rather than as an epoch.
func ParseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// maxConsentIntents bounds the operator's approval list.
const maxConsentIntents = 64

// ConsentSet turns a request's approved-intent list into a lookup, bounded and
// shape-checked like any other untrusted input.
func ConsentSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for i, v := range in {
		if i >= maxConsentIntents {
			break
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 128 {
			continue
		}
		out[v] = true
	}
	return out
}

// CollectNote is the transport's honest condition, in one place so every
// surface — the state endpoint, the plan response, the 503 body and the page —
// says exactly the same thing. An operator who reads it on two screens must not
// have to wonder whether they mean different things.
func CollectNote(canCollect bool) string {
	if canCollect {
		return ""
	}
	return "Live collection is not wired on this deployment (FEATURE_PROTOCOL_DIAG_COLLECT is off, or no read-only " +
		"SSH account is provisioned). The plan, the bundle and the case text still work — collect the outputs by " +
		"hand and paste them into the collect step."
}

// ClassSummary is one row of the override list.
type ClassSummary struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Protocol string `json:"protocol"`
	Summary  string `json:"summary,omitempty"`
	// Manual marks a class that carries no detection rules: it can never be
	// selected automatically, only chosen by an operator. Saying so is the
	// difference between "we looked and it did not match" and "we cannot look".
	Manual bool `json:"manual,omitempty"`
}

// ClassSummaries is the override list the operator picks from. It is EVERY
// class, not only the ones that scored: the design's override is unrestricted,
// because the operator standing in front of the device knows things the
// evidence does not carry.
func (c *Catalog) ClassSummaries() []ClassSummary {
	if c == nil {
		return []ClassSummary{}
	}
	out := make([]ClassSummary, 0, len(c.classOrder))
	for _, id := range c.classOrder {
		cl := c.classes[id]
		out = append(out, ClassSummary{
			ID: cl.ID, Title: cl.Title, Protocol: cl.Protocol, Summary: cl.Summary,
			Manual: cl.ID != GenericClassID && cl.Detect.empty(),
		})
	}
	return out
}
