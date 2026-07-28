package incident

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// incidents.go — the Incident system's transport-neutral model + repository seam.
//
// An Incident is the platform's INTERNAL system of record for an operational
// problem. Findings/alerts/anomalies are folded into incidents (deduplicated), an
// operator drives the lifecycle in-platform, and — optionally and asynchronously —
// the incident is PROJECTED to an external ITSM ticket (ServiceNow/Jira). The
// incident never depends on the ITSM tool: external_* are projection bookkeeping.
//
// The store is Postgres+RLS only (the SaaS backend); on the file/dev backend the
// repo is nil and the handlers answer 409 (mirrors the report pipeline).

// Incident severity ladder (low→high) and status set.
var Severities = []string{"info", "low", "medium", "high", "critical"}

func SeverityRank(s string) int {
	for i, v := range Severities {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return i
		}
	}
	return 0 // unknown → info
}

// ValidSeverity reports whether s is EXACTLY one of the ladder values
// (case-insensitively). It exists because SeverityRank above maps every
// unrecognised string to 0 — and 0 is not "no match", it is `info`.
//
// F-74: /api/incidents?severity=X ran that mapping and then applied the result
// as a real SQL predicate, so `?severity=warning` (not on the ladder),
// `?severity=WARN` and `?severity=bogus` all returned the byte-identical `info`
// bucket. A client filtering for warnings received info incidents labelled as
// warnings — confidently wrong, which is worse than ignoring the parameter.
// Filter parsing must use THIS, never the rank/normalize pair.
func ValidSeverity(s string) bool {
	t := strings.TrimSpace(s)
	for _, v := range Severities {
		if strings.EqualFold(t, v) {
			return true
		}
	}
	return false
}

// CanonicalSeverity lowercases a severity already known to be valid.
func CanonicalSeverity(s string) string {
	t := strings.TrimSpace(s)
	for _, v := range Severities {
		if strings.EqualFold(t, v) {
			return v
		}
	}
	return ""
}

func NormalizeSeverity(s string) string {
	if r := SeverityRank(s); r >= 0 && r < len(Severities) {
		if strings.EqualFold(strings.TrimSpace(s), Severities[r]) {
			return Severities[r]
		}
	}
	return "info"
}

const (
	StatusOpen          = "open"
	StatusAcknowledged  = "acknowledged"
	StatusInvestigating = "investigating"
	StatusResolved      = "resolved"
	StatusClosed        = "closed"
)

func IsTerminalStatus(s string) bool { return s == StatusResolved || s == StatusClosed }

func ValidStatus(s string) bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusInvestigating, StatusResolved, StatusClosed:
		return true
	}
	return false
}

// ValidTransition enforces a lenient-but-sane lifecycle: forward progress plus
// reopen from a terminal state. A no-op (same status) is rejected by the caller.
func ValidTransition(from, to string) bool {
	if !ValidStatus(to) {
		return false
	}
	switch to {
	case StatusAcknowledged, StatusInvestigating:
		return from == StatusOpen || from == StatusAcknowledged || from == StatusInvestigating
	case StatusResolved:
		return !IsTerminalStatus(from)
	case StatusClosed:
		return from == StatusResolved || from == StatusOpen || from == StatusAcknowledged || from == StatusInvestigating
	case StatusOpen: // reopen
		return IsTerminalStatus(from)
	}
	return false
}

// Incident is one operational problem (the internal record).
type Incident struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	SourceType     string     `json:"source_type"`
	SourceID       string     `json:"source_id,omitempty"`
	DedupKey       string     `json:"dedup_key,omitempty"`
	Owner          string     `json:"owner,omitempty"`
	Occurrences    int        `json:"occurrences"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ExternalTicket string     `json:"external_ticket_id,omitempty"`
	ExternalURL    string     `json:"external_url,omitempty"`
	ExternalSystem string     `json:"external_system,omitempty"`
	SyncStatus     string     `json:"sync_status"`
	LastSyncedAt   *time.Time `json:"last_synced_at,omitempty"`
	// NotifiedVia lists the notification channels this incident was actually
	// delivered to (derived from `notified` timeline events — a recorded
	// delivery, never an intent). Feeds the UI "Notified via" column (#103 UX-1).
	NotifiedVia []string `json:"notified_via,omitempty"`
}

// DisplayID turns an internal incident id (16 hex chars) into the
// human handle operators reference (INC-3FA2C1) — the incident-system sibling
// of noclabel.ProblemDisplayID (#103 UX-2: no raw hex in notifications or lists).
// Byte-identical to the TS friendlyIncidentId. Display-only: the internal id
// stays canonical for routes/dedup/buttons. Idempotent and safe on non-hex ids.
func DisplayID(id string) string {
	if id == "" || strings.HasPrefix(id, "INC-") {
		return id
	}
	if len(id) < 6 {
		return id
	}
	return "INC-" + strings.ToUpper(id[:6])
}

// Event is one append-only timeline entry.
type Event struct {
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id"`
	EventType  string         `json:"event_type"`
	Payload    map[string]any `json:"payload,omitempty"`
	Actor      string         `json:"actor"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Input is a detection (or manual request) to be folded into an incident.
type Input struct {
	TenantID    string
	Title       string
	Description string
	Severity    string
	SourceType  string // alert | log | anomaly | manual
	SourceID    string
	DedupKey    string // explicit; empty → derived
	Owner       string
	Actor       string // who/what raised it (audit/timeline)
}

// Query parameterizes a tenant-scoped listing (newest-last-seen first).
type Query struct {
	Status   string
	Severity string
	Before   time.Time
	Limit    int
	Offset   int
}

// Repo is the Incident store seam (mirrors auditRepo/savedRepo). Reads
// are RLS tenant-scoped; system writes (Ingest, MarkSync) run at platform scope
// but stamp the row's tenant_id (RLS WITH CHECK passes under '*').
type Repo interface {
	// Ingest creates a new incident or, when an active one shares the dedup key,
	// folds the detection into it (occurrences++, last_seen bumped, severity
	// escalated). created reports which happened — the dedup guarantee.
	Ingest(ctx context.Context, in Input) (inc Incident, created bool, err error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Incident, []Event, bool, error)
	List(ctx context.Context, tenant string, cross bool, q Query) ([]Incident, error)
	// Count is List's TRUE total under the SAME filters and the SAME RLS tenant
	// scope, ignoring limit/offset. Without it a capped page is indistinguishable
	// from the whole set at the client (audit F-74/F-79 class).
	Count(ctx context.Context, tenant string, cross bool, q Query) (int, error)
	// Transition changes status (validated), stamps resolved_at on resolve, and
	// appends a status_change event. Returns the updated incident.
	Transition(ctx context.Context, tenant string, cross bool, id, to, actor, note string) (Incident, error)
	AddNote(ctx context.Context, tenant string, cross bool, id, actor, note string) (Incident, error)
	Assign(ctx context.Context, tenant string, cross bool, id, owner, actor string) (Incident, error)
	// MarkSync records the ITSM projection result (worker, platform scope).
	MarkSync(ctx context.Context, id, system, externalID, externalURL, syncStatus string, at time.Time) error
	// MarkNotified records a SUCCESSFUL notification delivery for the incident
	// (platform scope, like MarkSync) as a `notified` timeline event — the
	// source the notified_via read derives from. Never called on send failure.
	MarkNotified(ctx context.Context, id, channel string) error
	// FindByExternalTicket resolves an incident from its ITSM ticket id (the
	// external_ticket_id forward link) for INBOUND reconciliation. Tenant-scoped.
	FindByExternalTicket(ctx context.Context, tenant, system, externalID string) (Incident, bool, error)
}

// DedupKeyFor returns the deterministic grouping key for a detection: the explicit
// key when given, else a stable hash of (source_type | source_id | normalized
// title). Two detections of the same root cause map to the same key.
func DedupKeyFor(in Input) string {
	if k := strings.TrimSpace(in.DedupKey); k != "" {
		return k
	}
	seed := strings.ToLower(strings.TrimSpace(in.SourceType)) + "|" +
		strings.ToLower(strings.TrimSpace(in.SourceID)) + "|" +
		normalizeTitle(in.Title)
	sum := sha256.Sum256([]byte(seed))
	return "auto-" + hex.EncodeToString(sum[:8])
}

// normalizeTitle lowercases, collapses whitespace, and trims so titles
// that differ only cosmetically dedup together.
func normalizeTitle(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// AutoTicketEligible encodes the agreed auto-create policy: severity ≥ critical
// (rca-confidence ≥ 0.8 is applied upstream where the score is known).
func AutoTicketEligible(severity string) bool {
	return SeverityRank(severity) >= SeverityRank("critical")
}
