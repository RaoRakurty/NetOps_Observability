package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// incidents_pg.go — the Postgres-backed Incident store (incidentsRepo). Reads are
// RLS tenant-scoped; system writes (Ingest, MarkSync) run at platform scope and
// stamp the row's tenant_id (RLS WITH CHECK passes under '*'). Modeled on
// audit_pg.go / saved_pg.go.

type pgIncidentStore struct {
	db *pgDB
}

func newPgIncidentStore(db *pgDB) *pgIncidentStore { return &pgIncidentStore{db: db} }

var (
	errIncidentNotFound = errors.New("incident not found")
	errBadTransition    = errors.New("invalid incident status transition")
)

func normalizeSourceType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "alert", "log", "anomaly", "manual":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "manual"
	}
}

func actorOr(a string) string {
	if strings.TrimSpace(a) == "" {
		return "system"
	}
	return a
}

// sevArray is the SQL severity ladder for array_position-based escalation.
const sevArray = `ARRAY['info','low','medium','high','critical']`

// upsertIncidentSQL creates a new incident or folds a detection into the active
// one sharing (tenant, dedup_key). The partial-unique index arbitrates, so an
// alert storm collapses to one incident under concurrency. (xmax = 0) reports
// whether this was a fresh INSERT (new incident) vs a dedup UPDATE.
var upsertIncidentSQL = `
INSERT INTO incidents
  (id, tenant_id, title, description, severity, status, source_type, source_id, dedup_key, owner,
   occurrences, created_at, updated_at, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,$9, 1, now(), now(), $10, $10)
ON CONFLICT (tenant_id, dedup_key) WHERE (dedup_key <> '' AND status NOT IN ('resolved','closed'))
DO UPDATE SET
   occurrences  = incidents.occurrences + 1,
   last_seen_at = GREATEST(incidents.last_seen_at, EXCLUDED.last_seen_at),
   severity     = CASE WHEN array_position(` + sevArray + `, EXCLUDED.severity)
                          > array_position(` + sevArray + `, incidents.severity)
                       THEN EXCLUDED.severity ELSE incidents.severity END,
   updated_at   = now()
RETURNING id, (xmax = 0) AS inserted`

func (s *pgIncidentStore) Ingest(ctx context.Context, in IncidentInput) (Incident, bool, error) {
	id := randHex(8)
	dk := dedupKeyFor(in)
	sev := normalizeSeverity(in.Severity)
	st := normalizeSourceType(in.SourceType)
	tid := normTenant(in.TenantID)
	now := time.Now().UTC()

	var resultID string
	var inserted bool
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, upsertIncidentSQL,
			id, tid, in.Title, in.Description, sev, st, nullText(in.SourceID), dk, in.Owner, now)
		if err := row.Scan(&resultID, &inserted); err != nil {
			return err
		}
		evType := "dedup"
		if inserted {
			evType = "created"
		}
		payload, _ := json.Marshal(map[string]any{
			"severity": sev, "source_type": st, "source_id": in.SourceID, "title": in.Title,
		})
		return appendIncidentEvent(ctx, tx, resultID, tid, evType, payload, actorOr(in.Actor))
	})
	if err != nil {
		return Incident{}, false, err
	}
	inc, _, _, err := s.Get(ctx, "", true, resultID)
	return inc, inserted, err
}

// FindByExternalTicket resolves an incident from its external_ticket_id (the
// forward link set on outbound projection). Used by inbound reconciliation to
// correlate a webhook back to the originating incident. Tenant-scoped (RLS).
func (s *pgIncidentStore) FindByExternalTicket(ctx context.Context, tenant, system, externalID string) (Incident, bool, error) {
	var inc Incident
	var found bool
	err := s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectIncidentCols+`
			FROM incidents WHERE external_system=$1 AND external_ticket_id=$2
			ORDER BY created_at DESC LIMIT 1`, system, externalID)
		r, ok, err := scanIncident(row)
		if err != nil {
			return err
		}
		if ok {
			inc, found = r, true
		}
		return nil
	})
	return inc, found, err
}

func (s *pgIncidentStore) Get(ctx context.Context, tenant string, cross bool, id string) (Incident, []IncidentEvent, bool, error) {
	var inc Incident
	var events []IncidentEvent
	found := false
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectIncidentCols+` FROM incidents WHERE id=$1`, id)
		r, ok, err := scanIncident(row)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		found = true
		inc = r
		rows, err := tx.Query(ctx, `
			SELECT id, incident_id, event_type, payload, actor, created_at
			  FROM incident_events WHERE incident_id=$1 ORDER BY created_at ASC, id ASC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev IncidentEvent
			var payload []byte
			if err := rows.Scan(&ev.ID, &ev.IncidentID, &ev.EventType, &payload, &ev.Actor, &ev.CreatedAt); err != nil {
				return err
			}
			if len(payload) > 0 {
				_ = json.Unmarshal(payload, &ev.Payload)
			}
			events = append(events, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return Incident{}, nil, false, err
	}
	return inc, events, found, nil
}

// incidentFilterSQL builds the shared WHERE fragment + args for List and Count,
// so the total can never be computed under different filters than the page.
//
// It FAILS CLOSED on an unrecognised severity instead of substituting one
// (F-74): normalizeSeverity used to be called right here, turning every
// unknown value into `info` and applying it as a real predicate. The handler
// validates first; this is the storage-layer backstop required by §3a.4 — no
// caller, internal or external, gets a silently different filter.
func incidentFilterSQL(q IncidentQuery) (string, []any, error) {
	var args []any
	var conds []string
	if q.Status != "" {
		if !validIncidentStatus(q.Status) {
			return "", nil, fmt.Errorf("unknown incident status %q", q.Status)
		}
		args = append(args, q.Status)
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)))
	}
	if q.Severity != "" {
		if !validIncidentSeverity(q.Severity) {
			return "", nil, fmt.Errorf("unknown incident severity %q", q.Severity)
		}
		args = append(args, canonicalIncidentSeverity(q.Severity))
		conds = append(conds, fmt.Sprintf("severity = $%d", len(args)))
	}
	if !q.Before.IsZero() {
		args = append(args, q.Before)
		conds = append(conds, fmt.Sprintf("last_seen_at < $%d", len(args)))
	}
	if len(conds) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

func (s *pgIncidentStore) List(ctx context.Context, tenant string, cross bool, q IncidentQuery) ([]Incident, error) {
	where, args, err := incidentFilterSQL(q)
	if err != nil {
		return nil, err
	}
	sql := selectIncidentCols + ` FROM incidents` + where
	args = append(args, clampIncidentLimit(q.Limit))
	sql += fmt.Sprintf(" ORDER BY last_seen_at DESC, id DESC LIMIT $%d", len(args))
	// OFFSET completes the walk: a limit-only read could never reach row
	// limit+1, which is how /api/vulns lost 5,560 of 7,560 findings (F-79).
	if q.Offset > 0 {
		args = append(args, q.Offset)
		sql += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	var out []Incident
	err = s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, _, err := scanIncident(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Count is List's true total under the same filters and the same RLS scope.
func (s *pgIncidentStore) Count(ctx context.Context, tenant string, cross bool, q IncidentQuery) (int, error) {
	where, args, err := incidentFilterSQL(q)
	if err != nil {
		return 0, err
	}
	var n int
	err = s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM incidents`+where, args...).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *pgIncidentStore) Transition(ctx context.Context, tenant string, cross bool, id, to, actor, note string) (Incident, error) {
	to = strings.ToLower(strings.TrimSpace(to))
	if !validIncidentStatus(to) {
		return Incident{}, errBadTransition
	}
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var cur, tid string
		// RLS scopes this read: a tenant can only transition its own incidents.
		if err := tx.QueryRow(ctx, `SELECT status, tenant_id FROM incidents WHERE id=$1`, id).Scan(&cur, &tid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errIncidentNotFound
			}
			return err
		}
		if cur == to {
			return nil // idempotent no-op
		}
		if !validTransition(cur, to) {
			return errBadTransition
		}
		if _, err := tx.Exec(ctx, `
			UPDATE incidents
			   SET status=$2,
			       resolved_at = CASE WHEN $2='resolved' THEN now()
			                          WHEN $2='open' THEN NULL
			                          ELSE resolved_at END,
			       updated_at=now()
			 WHERE id=$1`, id, to); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"from": cur, "to": to, "note": note})
		return appendIncidentEvent(ctx, tx, id, tid, "status_change", payload, actorOr(actor))
	})
	if err != nil {
		return Incident{}, err
	}
	inc, _, found, err := s.Get(ctx, tenant, cross, id)
	if err == nil && !found {
		return Incident{}, errIncidentNotFound
	}
	return inc, err
}

func (s *pgIncidentStore) AddNote(ctx context.Context, tenant string, cross bool, id, actor, note string) (Incident, error) {
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM incidents WHERE id=$1`, id).Scan(&tid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errIncidentNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET updated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"note": note})
		return appendIncidentEvent(ctx, tx, id, tid, "note", payload, actorOr(actor))
	})
	if err != nil {
		return Incident{}, err
	}
	inc, _, _, err := s.Get(ctx, tenant, cross, id)
	return inc, err
}

func (s *pgIncidentStore) Assign(ctx context.Context, tenant string, cross bool, id, owner, actor string) (Incident, error) {
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM incidents WHERE id=$1`, id).Scan(&tid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errIncidentNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET owner=$2, updated_at=now() WHERE id=$1`, id, owner); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"owner": owner})
		return appendIncidentEvent(ctx, tx, id, tid, "assignment", payload, actorOr(actor))
	})
	if err != nil {
		return Incident{}, err
	}
	inc, _, _, err := s.Get(ctx, tenant, cross, id)
	return inc, err
}

// MarkSync records the external ITSM projection outcome (worker, platform scope).
// The incident is the source of truth; this is bookkeeping only.
func (s *pgIncidentStore) MarkSync(ctx context.Context, id, system, externalID, externalURL, syncStatus string, at time.Time) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM incidents WHERE id=$1`, id).Scan(&tid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errIncidentNotFound
			}
			return err
		}
		// COALESCE keeps any existing external_* when called with empty values
		// (e.g. the "pending" mark at enqueue must not wipe a prior ticket id).
		if _, err := tx.Exec(ctx, `
			UPDATE incidents
			   SET external_system=COALESCE($2, external_system),
			       external_ticket_id=COALESCE($3, external_ticket_id),
			       external_url=COALESCE($4, external_url),
			       sync_status=$5, last_synced_at=$6, updated_at=now()
			 WHERE id=$1`,
			id, nullText(system), nullText(externalID), nullText(externalURL), syncStatus, at); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{
			"system": system, "external_ticket_id": externalID, "sync_status": syncStatus,
		})
		return appendIncidentEvent(ctx, tx, id, tid, "sync", payload, "system")
	})
}

// MarkNotified appends a `notified` delivery event (platform scope — the notify
// path runs outside a request principal, like MarkSync). Only successful sends
// are recorded, so notified_via is a delivery record, never an intent.
func (s *pgIncidentStore) MarkNotified(ctx context.Context, id, channel string) error {
	channel = strings.ToLower(strings.TrimSpace(channel))
	if channel == "" {
		return nil
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM incidents WHERE id=$1`, id).Scan(&tid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errIncidentNotFound
			}
			return err
		}
		payload, _ := json.Marshal(map[string]any{"channel": channel})
		return appendIncidentEvent(ctx, tx, id, tid, "notified", payload, "system")
	})
}

// ---- helpers ----

func appendIncidentEvent(ctx context.Context, tx pgx.Tx, incidentID, tenant, evType string, payload []byte, actor string) error {
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO incident_events (id, incident_id, tenant_id, event_type, payload, actor)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		randHex(8), incidentID, tenant, evType, payload, actor)
	return err
}

// notified_via is derived from the recorded `notified` delivery events — a
// bounded correlated subquery (lists are capped at 500 rows) that keeps the
// timeline as the single source of truth, no extra column/migration.
const selectIncidentCols = `SELECT id, tenant_id, title, COALESCE(description,''), severity, status,
	source_type, COALESCE(source_id,''), dedup_key, COALESCE(owner,''), occurrences,
	created_at, updated_at, first_seen_at, last_seen_at, resolved_at,
	COALESCE(external_ticket_id,''), COALESCE(external_url,''), COALESCE(external_system,''),
	sync_status, last_synced_at,
	COALESCE((SELECT array_agg(DISTINCT e.payload->>'channel')
	            FROM incident_events e
	           WHERE e.incident_id = incidents.id AND e.event_type = 'notified'
	             AND e.payload->>'channel' IS NOT NULL), '{}') AS notified_via`

func scanIncident(row pgx.Row) (Incident, bool, error) {
	var r Incident
	var resolved, lastSync *time.Time
	if err := row.Scan(&r.ID, &r.TenantID, &r.Title, &r.Description, &r.Severity, &r.Status,
		&r.SourceType, &r.SourceID, &r.DedupKey, &r.Owner, &r.Occurrences,
		&r.CreatedAt, &r.UpdatedAt, &r.FirstSeenAt, &r.LastSeenAt, &resolved,
		&r.ExternalTicket, &r.ExternalURL, &r.ExternalSystem, &r.SyncStatus, &lastSync,
		&r.NotifiedVia); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Incident{}, false, nil
		}
		return Incident{}, false, err
	}
	r.ResolvedAt = resolved
	r.LastSyncedAt = lastSync
	return r, true, nil
}

func clampIncidentLimit(n int) int {
	if n <= 0 || n > 500 {
		return 100
	}
	return n
}

var _ incidentsRepo = (*pgIncidentStore)(nil)
