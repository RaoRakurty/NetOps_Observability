package backend

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/integration"
)

// integrations_http_test.go — M14 (third-pass review).
//
// applyInboundEvent's contract (its own doc-comment): a non-nil error is a
// TRANSIENT store failure the caller RETRIES; only DEFINITIVE outcomes (no
// incident, stale, bad-transition, gone) write a ledger verdict. The mutation
// branches (Transition/Assign/AddNote) used to record a terminal "dropped"
// verdict for ANY non-nil error, so a plain DB blip permanently lost a real ITSM
// transition — the job Completed with no retry and redelivery couldn't rescue a
// non-"received" row. This pins the corrected classification: only
// ErrBadTransition / ErrNotFound are definitive drops; everything else retries.

// f1SeamRow / f1SeamTx / f1SeamDB fake exactly the store surface applyInboundEvent
// touches BEFORE the incident transition: the watermark read (GetMapping →
// SELECT FROM integration_mappings) returns no rows (empty watermark), and any
// ledger verdict write (MarkEvent → UPDATE integration_events) is counted so the
// test can assert NO "dropped" verdict is written on the transient path. Every
// other query panics loudly via the embedded nil pgx.Tx — the test must not
// silently exercise more surface.
type f1SeamRow struct{ scan func(dest ...any) error }

func (r f1SeamRow) Scan(dest ...any) error { return r.scan(dest...) }

type f1SeamTx struct {
	pgx.Tx
	verdictWrites *int
}

func (tx f1SeamTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "FROM integration_mappings"):
		// No persisted watermark yet → GetMapping treats ErrNoRows as "empty".
		return f1SeamRow{scan: func(...any) error { return pgx.ErrNoRows }}
	default:
		return f1SeamRow{scan: func(...any) error { return errors.New("unexpected query: " + sql) }}
	}
}

func (tx f1SeamTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "UPDATE integration_events") {
		*tx.verdictWrites++
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	return pgconn.CommandTag{}, errors.New("unexpected exec: " + sql)
}

type f1SeamDB struct{ tx f1SeamTx }

func (d f1SeamDB) WithTenant(_ context.Context, _ string, _ bool, fn func(pgx.Tx) error) error {
	return fn(d.tx)
}

// FAILING-FIRST (M14): with the pre-fix code the Transition branch stamps
// "dropped" for the injected TRANSIENT error and returns (false, nil) — so this
// test sees verdictWrites==1 and a nil error and fails. The fix classifies the
// error: not ErrBadTransition/ErrNotFound → retry (return non-nil, no verdict).
func TestApplyInboundEventRetriesTransientTransitionError(t *testing.T) {
	ctx := context.Background()

	// correlateIncident resolves via the slack path (incidents.Get by AlertID);
	// fakeIncidents returns the row found, and its Transition returns the generic
	// errFakeUnused — a TRANSIENT-looking error, NOT ErrBadTransition/ErrNotFound.
	inc := Incident{ID: "inc-1", TenantID: "acme", Status: "open"}
	repo := &fakeIncidents{rows: []Incident{inc}}

	verdicts := 0
	db := f1SeamDB{tx: f1SeamTx{verdictWrites: &verdicts}}
	s := &server{
		incidents:    repo,
		integrations: integration.NewStore(db, nil),
	}

	// A resolve event with a positive sequence: not stale against the empty
	// watermark, maps to StateResolved → the Transition branch runs.
	ev := integration.IntegrationEvent{
		Tenant: "acme", Provider: "slack", ExternalID: "INC1", AlertID: "inc-1",
		Type: integration.EventResolved, ExternalSeq: 1, OccurredAt: time.Unix(1, 0),
	}

	mutated, err := s.applyInboundEvent(ctx, integration.Config{Tenant: "acme"}, ev, "ledger-1", "corr-1")
	if err == nil {
		t.Fatal("transient transition error must be returned for RETRY, got nil (the M14 permanent-drop bug)")
	}
	if mutated {
		t.Fatalf("mutated = true, want false — the transition did not succeed")
	}
	if verdicts != 0 {
		t.Fatalf("ledger verdict writes = %d, want 0 — a transient DB error must not write a terminal 'dropped' verdict", verdicts)
	}
}
