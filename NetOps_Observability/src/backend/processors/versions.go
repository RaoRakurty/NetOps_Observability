package processors

// versions.go — processor VERSION HISTORY + rollback (spec §10).
//
// Every saved edit appends an immutable snapshot of the processor's config.
// History is append-only: rollback does not rewind the chain, it writes the old
// config forward as a NEW version. An audit trail you can rewrite is not an
// audit trail — and the operator question ("what did this look like on Tuesday,
// and who changed it?") stays answerable either way.
//
// Retention is bounded (§9): MaxVersionsPerProcessor snapshots, oldest evicted.
// The evicted count is disclosed by ListVersions so "truncated" never reads as
// "nothing happened before this".

import (
	"context"
	"encoding/json"
	"time"
)

// MaxVersionsPerProcessor bounds retained history per processor.
const MaxVersionsPerProcessor = 50

// Version is one immutable snapshot of a processor's configuration.
type Version struct {
	ProcessorID string    `json:"processor_id"`
	Version     int       `json:"version"`
	Config      Rule      `json:"config"`
	ChangedBy   string    `json:"changed_by,omitempty"`
	ChangeKind  string    `json:"change_kind"` // created | updated | rolled_back
	CreatedAt   time.Time `json:"created_at"`
}

// VersionStore is the history half of the engine's persistence. Kept a separate
// interface so a backend can implement it independently (and so a caller that
// only needs CRUD cannot accidentally depend on history).
type VersionStore interface {
	// ListVersions returns the processor's history, newest first. Returns
	// found=false for an id the caller cannot see (cross-tenant → 404 upstream).
	ListVersions(ctx context.Context, tenant string, cross bool, id string) ([]Version, bool, error)
	// Rollback restores a historical config as a NEW version (append-only).
	Rollback(ctx context.Context, tenant string, cross bool, id string, version int, actor string) (Rule, bool, error)
}

// cloneConfig deep-copies the mutable parts of a Rule so a stored snapshot can
// never alias the live record (a shared *Match would let a later edit silently
// rewrite history).
func cloneConfig(r Rule) Rule {
	out := r
	if r.Match != nil {
		m := *r.Match
		out.Match = &m
	}
	return out
}

// versionsJSON is the file backend's on-disk shape.
type versionsJSON struct {
	Rules    []Rule    `json:"rules"`
	Versions []Version `json:"versions"`
}

// trimVersions keeps the newest MaxVersionsPerProcessor snapshots per processor.
func trimVersions(all []Version, id string) []Version {
	var mine, others []Version
	for _, v := range all {
		if v.ProcessorID == id {
			mine = append(mine, v)
		} else {
			others = append(others, v)
		}
	}
	if len(mine) <= MaxVersionsPerProcessor {
		return all
	}
	// mine is append-ordered (oldest first) — drop from the front.
	mine = mine[len(mine)-MaxVersionsPerProcessor:]
	return append(others, mine...)
}

// marshalVersions is the shared encoder for the file backend.
func marshalVersions(rules []Rule, versions []Version) ([]byte, error) {
	return json.Marshal(versionsJSON{Rules: rules, Versions: versions})
}
