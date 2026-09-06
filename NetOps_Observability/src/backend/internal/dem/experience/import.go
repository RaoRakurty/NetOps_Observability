package experience

// import.go — the one-time file→Postgres cutover for the journey catalogue and
// the change feed (tracker 245 / the 2026-09-06 importer extension).
//
// Both are selected by STORE_BACKEND. Losing the journeys loses the operator's
// declared definition of what "working" means for each business flow; losing the
// change feed loses the "what changed just before this got worse" evidence, and
// a correlation that cannot see a change is a correlation that blames the wrong
// thing.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many rows the Postgres target holds — journeys plus
// change events, across every tenant (platform scope). Both tables carry one
// file, so they share one count and one import decision.
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var journeys, changes int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM dem_journeys`).Scan(&journeys); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM dem_change_events`).Scan(&changes)
	})
	return journeys + changes, err
}

// ImportFile writes the file store into dem_journeys and dem_change_events,
// preserving ids, owners, versions and timestamps. Returns the total number of
// rows written.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var payload filePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, fmt.Errorf("experience: the store file is malformed: %w", err)
	}
	type journeyRow struct {
		j    JourneyDefinition
		data []byte
	}
	type changeRow struct {
		c    ChangeEvent
		data []byte
	}
	journeys := []journeyRow{}
	for rawTenant, list := range payload.Journeys {
		tenant, err := concreteTenant(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("experience: the store file holds a non-concrete journey tenant bucket %q", rawTenant)
		}
		if len(list) > MaxJourneysPerTenant {
			return 0, fmt.Errorf("experience: tenant %s holds %d journeys, over the %d cap — refusing to import a truncated catalogue",
				tenant, len(list), MaxJourneysPerTenant)
		}
		for _, j := range list {
			j.TenantID = tenant // the bucket is authoritative (§3a rule 2)
			if j.ID == "" {
				return 0, fmt.Errorf("experience: tenant %s holds a journey with no id", tenant)
			}
			if err := j.Validate(); err != nil {
				return 0, fmt.Errorf("experience: tenant %s journey %s is invalid: %w", tenant, j.ID, err)
			}
			data, merr := json.Marshal(j)
			if merr != nil {
				return 0, merr
			}
			journeys = append(journeys, journeyRow{j: j, data: data})
		}
	}
	changes := []changeRow{}
	for rawTenant, list := range payload.Changes {
		tenant, err := concreteTenant(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("experience: the store file holds a non-concrete change tenant bucket %q", rawTenant)
		}
		for _, c := range list {
			c.TenantID = tenant
			if c.ID == "" {
				return 0, fmt.Errorf("experience: tenant %s holds a change event with no id", tenant)
			}
			if err := c.Validate(); err != nil {
				return 0, fmt.Errorf("experience: tenant %s change %s is invalid: %w", tenant, c.ID, err)
			}
			data, merr := json.Marshal(c)
			if merr != nil {
				return 0, merr
			}
			changes = append(changes, changeRow{c: c, data: data})
		}
	}
	if len(journeys) == 0 && len(changes) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range journeys {
			if _, err := tx.Exec(ctx,
				`INSERT INTO dem_journeys (tenant_id, journey_id, name, app, importance, version, data, created_by, created_at, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
				r.j.TenantID, r.j.ID, r.j.Name, r.j.App, r.j.BusinessImportance, r.j.Version,
				r.data, r.j.CreatedBy, r.j.CreatedAt, r.j.UpdatedAt); err != nil {
				return fmt.Errorf("experience: import journey %s (tenant %s): %w", r.j.ID, r.j.TenantID, err)
			}
		}
		for _, r := range changes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO dem_change_events (tenant_id, change_id, change_type, app, site, event_at, data)
				 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				r.c.TenantID, r.c.ID, r.c.Type, r.c.App, r.c.Site, r.c.EventAt, r.data); err != nil {
				return fmt.Errorf("experience: import change %s (tenant %s): %w", r.c.ID, r.c.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(journeys) + len(changes), nil
}
