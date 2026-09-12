// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// import.go — the one-time file→Postgres cutover for the security control
// plane and the compliance-framework selection (tracker 245 / the 2026-09-06
// importer extension).
//
// Both registers are selected by STORE_BACKEND, and both encode a DELIBERATE
// operator choice whose absence is not neutral:
//
//   - security_rule_state: absent means DEFAULT-ON. A cutover that lost a
//     tenant's disabled rules would silently switch detections back on and
//     report findings the tenant had decided not to run.
//   - security_framework_state: absent means "has not chosen", which restores
//     the shipped default set. A cutover that lost a HIPAA/PCI selection would
//     show a scorecard for a regulation the customer is not subject to — an
//     implied compliance claim.
//
// Stricter than the file stores, which serve the shipped defaults over a corrupt
// file and record LoadErr: a migration must refuse rather than import a subset.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds a whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountControlPlaneRows reports how many control-plane rows the Postgres target
// holds — rule overrides plus saved views, across every tenant (platform
// scope). Both tables carry one file, so they share one count and one import
// decision.
func CountControlPlaneRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var rules, views int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_rule_state`).Scan(&rules); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM security_saved_views`).Scan(&views)
	})
	return rules + views, err
}

// ImportControlPlaneFile writes the file register into security_rule_state and
// security_saved_views, preserving the owning tenant, the view ids and every
// timestamp. Returns the total number of rows written.
//
// View ids are preserved rather than re-minted (AddView mints one): a saved
// view's id is what a bookmarked URL carries, and re-minting would break every
// one of them.
func ImportControlPlaneFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var p filePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, fmt.Errorf("secapi: the security control-plane state file is malformed: %w", err)
	}
	for i := range p.Rules {
		p.Rules[i].TenantID = NormTenant(p.Rules[i].TenantID)
		if p.Rules[i].RuleID == "" {
			return 0, fmt.Errorf("secapi: the control-plane file holds a rule override with no rule id (tenant %q)", p.Rules[i].TenantID)
		}
	}
	for i := range p.Views {
		p.Views[i].TenantID = NormTenant(p.Views[i].TenantID)
		if p.Views[i].ID == "" {
			return 0, fmt.Errorf("secapi: the control-plane file holds a saved view with no id (tenant %q)", p.Views[i].TenantID)
		}
		p.Views[i].Filters = defaultFilters(p.Views[i].Filters)
	}
	if len(p.Rules) == 0 && len(p.Views) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range p.Rules {
			at := r.UpdatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_rule_state
			        (tenant_id, rule_id, enabled, updated_by, updated_at)
			    VALUES ($1,$2,$3,$4,$5)`,
				r.TenantID, r.RuleID, r.Enabled, r.UpdatedBy, at); err != nil {
				return fmt.Errorf("secapi: import rule state %s (tenant %s): %w", r.RuleID, r.TenantID, err)
			}
		}
		for _, v := range p.Views {
			at := v.CreatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_saved_views
			        (id, tenant_id, name, filters, created_by, created_at)
			    VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
				v.ID, v.TenantID, v.Name, string(v.Filters), v.CreatedBy, at); err != nil {
				return fmt.Errorf("secapi: import saved view %s (tenant %s): %w", v.ID, v.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(p.Rules) + len(p.Views), nil
}

// CountFrameworkRows reports how many framework-selection rows the Postgres
// target holds across every tenant (platform scope).
func CountFrameworkRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM security_framework_state`).Scan(&n)
	})
	return n, err
}

// ImportFrameworkFile writes the file selection into security_framework_state,
// preserving the owning tenant and the audit shoulder (who chose, when).
// Returns the number of rows written.
func ImportFrameworkFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var p frameworkPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, fmt.Errorf("secapi: the security framework selection file is malformed: %w", err)
	}
	for i := range p.Frameworks {
		p.Frameworks[i].TenantID = NormTenant(p.Frameworks[i].TenantID)
		if p.Frameworks[i].FrameworkID == "" {
			return 0, fmt.Errorf("secapi: the framework file holds a row with no framework id (tenant %q)", p.Frameworks[i].TenantID)
		}
	}
	if len(p.Frameworks) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range p.Frameworks {
			at := r.UpdatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_framework_state
			        (tenant_id, framework_id, enabled, updated_by, updated_at)
			    VALUES ($1,$2,$3,$4,$5)`,
				r.TenantID, r.FrameworkID, r.Enabled, r.UpdatedBy, at); err != nil {
				return fmt.Errorf("secapi: import framework %s (tenant %s): %w", r.FrameworkID, r.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(p.Frameworks), nil
}
