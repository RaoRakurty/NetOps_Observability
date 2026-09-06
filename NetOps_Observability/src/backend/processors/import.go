package processors

// import.go — the one-time file→Postgres cutover for the pipeline-processor
// register and its version history (tracker 245 / the 2026-09-06 importer
// extension).
//
// These rules are the REDACTION pipeline. A cutover that lost them would ship
// an empty router config and stop every redaction — unredacted customer data
// flowing into the stores, with nothing in the API saying anything changed.
// That is the exact failure NewFileStore already refuses to hide at runtime,
// and a migration must not reintroduce it.
//
// The version history travels with the rules: it is the immutable audit of who
// changed a redaction and when, and an audit that a backend switch can erase is
// not an audit.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many rows the Postgres target holds — processors plus
// version snapshots, across every tenant (platform scope). Both tables carry
// one file, so they share one count and one import decision.
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var rules, versions int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pipeline_processors`).Scan(&rules); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM processor_versions`).Scan(&versions)
	})
	return rules + versions, err
}

// ImportFile writes the file register into pipeline_processors and
// processor_versions, preserving ids, owners, execution order, versions and
// timestamps. Returns the total number of rows written.
//
// Both on-disk shapes NewFileStore accepts are accepted here: the current
// {rules,versions} envelope and the ORIGINAL flat array (a pre-history file
// must still migrate, or upgrading before cutting over would lose everything).
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	env, err := decodeProcessorFile(raw)
	if err != nil {
		return 0, err
	}
	perTenant := map[string]int{}
	for i := range env.Rules {
		env.Rules[i].TenantID = normTenant(env.Rules[i].TenantID)
		if env.Rules[i].ID == "" {
			return 0, fmt.Errorf("processors: the store holds a processor with no id (tenant %q)", env.Rules[i].TenantID)
		}
		if err := env.Rules[i].Validate(); err != nil {
			return 0, fmt.Errorf("processors: processor %s (tenant %s) is invalid: %w",
				env.Rules[i].ID, env.Rules[i].TenantID, err)
		}
		perTenant[env.Rules[i].TenantID]++
		if perTenant[env.Rules[i].TenantID] > MaxPerTenant {
			return 0, fmt.Errorf("processors: tenant %s holds more than the %d processor cap — refusing to import a truncated set",
				env.Rules[i].TenantID, MaxPerTenant)
		}
	}
	for i := range env.Versions {
		env.Versions[i].Config.TenantID = normTenant(env.Versions[i].Config.TenantID)
		if env.Versions[i].ProcessorID == "" {
			return 0, fmt.Errorf("processors: the history holds a snapshot with no processor id")
		}
	}
	if len(env.Rules) == 0 && len(env.Versions) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err = db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range env.Rules {
			blob, berr := ruleBlob(r)
			if berr != nil {
				return berr
			}
			created, updated := r.CreatedAt, r.UpdatedAt
			if created.IsZero() {
				created = time.Now().UTC()
			}
			if updated.IsZero() {
				updated = created
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pipeline_processors
			        (tenant_id, rule_id, lane, rule_type, enabled, data, created_by, created_at, updated_at,
			         rule_order, version, source)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
				r.TenantID, r.ID, r.Lane, r.Type, r.Enabled, blob, r.CreatedBy, created, updated,
				r.Order, r.Version, r.Source); err != nil {
				return fmt.Errorf("processors: import processor %s (tenant %s): %w", r.ID, r.TenantID, err)
			}
		}
		for _, v := range env.Versions {
			blob, berr := ruleBlob(cloneConfig(v.Config))
			if berr != nil {
				return berr
			}
			at := v.CreatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			kind := v.ChangeKind
			if kind == "" {
				kind = "updated" // the column's own default; the CHECK forbids ""
			}
			if _, err := tx.Exec(ctx, `INSERT INTO processor_versions
			        (tenant_id, processor_id, version, config, changed_by, change_kind, created_at)
			    VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				v.Config.TenantID, v.ProcessorID, v.Version, blob, v.ChangedBy, kind, at); err != nil {
				return fmt.Errorf("processors: import version %d of processor %s: %w", v.Version, v.ProcessorID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(env.Rules) + len(env.Versions), nil
}

// decodeProcessorFile parses either on-disk shape into the envelope.
//
// The shape is decided by the FIRST TOKEN, not by whether a decode produced
// anything: a legitimately EMPTY envelope (`{"rules":[],"versions":[]}`) and
// "these bytes are not an envelope" would otherwise be the same fact, and the
// empty store would be reported as a malformed one. A JSON array is the legacy
// flat shape (a pre-history file must still migrate, or upgrading before
// cutting over would lose everything); anything else must be the envelope, and
// a failure to read it as one is a MALFORMED FILE, never an empty import
// (§10 — an unreadable redaction store must never import as an empty one).
func decodeProcessorFile(raw []byte) (versionsJSON, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []Rule
		if err := json.Unmarshal(raw, &list); err != nil {
			return versionsJSON{}, fmt.Errorf("processors: the processor store file is a malformed processor array: %w", err)
		}
		return versionsJSON{Rules: list}, nil
	}
	var env versionsJSON
	if err := json.Unmarshal(raw, &env); err != nil {
		return versionsJSON{}, fmt.Errorf("processors: the processor store file is a malformed {rules,versions} envelope: %w", err)
	}
	return env, nil
}
