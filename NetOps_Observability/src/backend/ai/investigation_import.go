package ai

// investigation_import.go — the one-time file→Postgres cutover for IRIS
// investigation memory (tracker 245 / the 2026-09-06 importer extension).
//
// The memory register is selected by STORE_BACKEND: on Postgres the api reads
// iris_investigations and never opens iris_investigations.json, so a backend
// switch silently forgets every concluded investigation. This is the move that
// keeps them.
//
// Stricter than NewInvestigationFileStore on purpose: the file store drops an
// unattributable row so a running install keeps serving, a MIGRATION must not —
// a dropped row here is history the operator cannot get back.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// investigationImportTimeout bounds the whole-collection write (§9). Far larger
// than the per-call timeout: one transaction, once, at boot.
const investigationImportTimeout = 2 * time.Minute

// CountInvestigationRows reports how many rows the Postgres target holds across
// every tenant (platform scope — the importer's own read).
func CountInvestigationRows(ctx context.Context, db InvestigationDB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigations`).Scan(&n)
	})
	return n, err
}

// ImportInvestigationFile writes the file backend's memory into
// iris_investigations, preserving ids, owners and both timestamps. Returns the
// number of rows written.
//
// The per-tenant retention cap is NOT applied silently: a file over the cap is
// refused, naming the tenant, rather than quietly evicting rows the operator can
// still see on disk.
func ImportInvestigationFile(ctx context.Context, db InvestigationDB, raw []byte) (int, error) {
	var list []persistedInvestigation
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("investigation memory: the file is malformed: %w", err)
	}
	perTenant := map[string]int{}
	rows := make([]InvestigationRow, 0, len(list))
	for _, p := range list {
		row := p.InvestigationRow
		row.TenantID = normTenant(p.TenantID)
		if row.TenantID == "" {
			return 0, fmt.Errorf("investigation memory: the file holds a row (%s) with no owning tenant", p.ID)
		}
		norm, err := NormalizeInvestigation(row)
		if err != nil {
			return 0, fmt.Errorf("investigation memory: row %s (tenant %s) is invalid: %w", p.ID, row.TenantID, err)
		}
		if norm.ID == "" {
			return 0, fmt.Errorf("investigation memory: tenant %s holds a row with no id", norm.TenantID)
		}
		perTenant[norm.TenantID]++
		if perTenant[norm.TenantID] > MaxInvestigationsPerTenant {
			return 0, fmt.Errorf("investigation memory: tenant %s holds more than the %d row cap — refusing to import a truncated memory",
				norm.TenantID, MaxInvestigationsPerTenant)
		}
		rows = append(rows, norm)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, investigationImportTimeout)
	defer cancel()
	// ONE transaction under platform scope: the whole memory arrives or none of
	// it does.
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, row := range rows {
			// The array columns are NOT NULL: a nil slice encodes as NULL and
			// is refused, so "none" is written as an EMPTY array.
			skills, citations := row.Skills, row.Citations
			if skills == nil {
				skills = []string{}
			}
			if citations == nil {
				citations = []string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO iris_investigations (`+pgInvestigationCols+`)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
				row.TenantID, row.ID, row.DeviceID, row.DeviceName, row.Peer, row.Prefix,
				row.CorrelationID, skills, row.Verdict, citations, string(row.Outcome),
				row.CreatedAt, row.ResolvedAt); err != nil {
				return fmt.Errorf("investigation memory: import row %s (tenant %s): %w", row.ID, row.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}
