package tac

// templateimport.go — the one-time file→Postgres cutover for the per-tenant TAC
// command templates (tracker 245 / the 2026-09-06 importer extension).
//
// Correlix's OWN defaults are generated from the authored plans and are not
// rows, so nothing of ours is at stake here; what a cutover would lose is the
// command sets a NOC admin wrote by hand for their own escalations. Those are
// the ones nobody can regenerate.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// templateImportTimeout bounds the whole-collection write (§9).
const templateImportTimeout = 2 * time.Minute

// CountTemplateRows reports how many template rows the Postgres target holds
// across every tenant.
//
// This is the ONE platform-scope read in the templates feature, and it exists
// only for the importer: the module deliberately has no fleet-wide consumer
// (migration 0045 says so), and nothing here exposes the rows themselves — only
// how many there are, to decide whether an import may run at all.
func CountTemplateRows(ctx context.Context, db TemplateDB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tac_templates`).Scan(&n)
	})
	return n, err
}

// ImportTemplateFile writes the file store into tac_templates, preserving each
// template's id, owning tenant, version and timestamps. Returns the number of
// rows written.
//
// Stricter than NewFileTemplateStore, which drops an invalid row and records
// LoadErr so a running install keeps serving: a migration refuses instead.
func ImportTemplateFile(ctx context.Context, db TemplateDB, raw []byte) (int, error) {
	var buckets map[string][]Template
	if err := json.Unmarshal(raw, &buckets); err != nil {
		return 0, fmt.Errorf("tac: the template file is malformed: %w", err)
	}
	type row struct {
		tpl  Template
		data []byte
	}
	rows := []row{}
	for rawTenant, list := range buckets {
		tenant, err := concreteTenantID(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("tac: the template file holds a non-concrete tenant bucket %q", rawTenant)
		}
		if len(list) > MaxTemplatesPerTenant {
			return 0, fmt.Errorf("tac: tenant %s holds %d templates, over the %d cap — refusing to import a truncated set",
				tenant, len(list), MaxTemplatesPerTenant)
		}
		for _, tpl := range list {
			// The BUCKET is authoritative for ownership, and Source is STAMPED:
			// a stored row can never claim to be a Correlix default (§3a rule 2).
			tpl.TenantID = tenant
			tpl.Source = SourceTenant
			switch {
			case tpl.ID == "" || !tplIDRE.MatchString(tpl.ID):
				return 0, fmt.Errorf("tac: tenant %s holds a template with an invalid id %q", tenant, tpl.ID)
			case IsDefaultTemplateID(tpl.ID):
				return 0, fmt.Errorf("tac: tenant %s holds a template whose id collides with a Correlix default (%s)", tenant, tpl.ID)
			case len(tpl.Steps) == 0:
				return 0, fmt.Errorf("tac: tenant %s template %s has no steps", tenant, tpl.ID)
			}
			if tpl.Version < 1 {
				tpl.Version = 1
			}
			data, merr := json.Marshal(tpl)
			if merr != nil {
				return 0, merr
			}
			rows = append(rows, row{tpl: tpl, data: data})
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, templateImportTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range rows {
			created, updated := r.tpl.CreatedAt, r.tpl.UpdatedAt
			if created.IsZero() {
				created = time.Now().UTC()
			}
			if updated.IsZero() {
				updated = created
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO tac_templates (tenant_id, template_id, dialect, name, based_on, version, data, created_by, created_at, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
				r.tpl.TenantID, r.tpl.ID, r.tpl.Dialect, r.tpl.Name, r.tpl.BasedOn,
				r.tpl.Version, r.data, r.tpl.CreatedBy, created, updated); err != nil {
				return fmt.Errorf("tac: import template %s (tenant %s): %w", r.tpl.ID, r.tpl.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}
