package rcafeedback

// import.go — the one-time file→Postgres cutover for the RCA verdict register
// (tracker 245 / the 2026-09-06 importer extension).
//
// These rows are the operator's judgement of the engine's own verdicts: the
// only measurement of whether correlation is right. Losing them on a backend
// switch resets the false-positive rate to "no data", which reads as "nothing
// has been wrong" — the most flattering possible lie about the engine.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many verdict rows the Postgres target holds across
// every tenant (platform scope — the importer's own read).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM rca_feedback`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file register into rca_feedback, preserving each
// verdict's id, owner, judged case, version and timestamp. Returns the number of
// rows written.
//
// Validate is re-run with objectVersion 0 ("unknown"), which is what the file
// itself can attest to: the ClickHouse object it judged may since have been
// re-versioned or aged out, and refusing a stored verdict because its object
// moved on would destroy exactly the history this register exists to keep.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var list []Feedback
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("rcafeedback: the verdict register file is malformed: %w", err)
	}
	perCase := map[string]int{}
	for i := range list {
		list[i].TenantID = NormTenant(list[i].TenantID)
		if list[i].ID == "" || list[i].CorrelationID == "" {
			return 0, fmt.Errorf("rcafeedback: the register holds a verdict with no id or no correlation id (tenant %q)", list[i].TenantID)
		}
		if err := Validate(&list[i], 0); err != nil {
			return 0, fmt.Errorf("rcafeedback: verdict %s (tenant %s) is invalid: %w", list[i].ID, list[i].TenantID, err)
		}
		k := list[i].TenantID + "\x00" + list[i].CorrelationID
		perCase[k]++
		if perCase[k] > MaxPerCase {
			return 0, fmt.Errorf("rcafeedback: tenant %s case %s holds more than the %d verdict cap — refusing to import a truncated register",
				list[i].TenantID, list[i].CorrelationID, MaxPerCase)
		}
	}
	if len(list) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, f := range list {
			var version *int32
			if f.CorrelationVersion != nil {
				// Bounded by Validate (1..1<<30), so the narrowing is safe.
				v := int32(*f.CorrelationVersion) // #nosec G115 -- Validate caps correlation_version at 1<<30
				version = &v
			}
			at := f.CreatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rca_feedback
			        (tenant_id, id, correlation_id, verdict, wrong_part, reason,
			         correlation_version, top_hypothesis, verdict_tier, created_by, created_at)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				f.TenantID, f.ID, f.CorrelationID, f.Verdict, f.WrongPart, f.Reason,
				version, f.TopHypothesis, f.VerdictTier, f.CreatedBy, at); err != nil {
				return fmt.Errorf("rcafeedback: import verdict %s (tenant %s): %w", f.ID, f.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(list), nil
}
