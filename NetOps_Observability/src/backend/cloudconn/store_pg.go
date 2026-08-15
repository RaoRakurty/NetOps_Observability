package cloudconn

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// PGStore is the Postgres-backed connector store. Every method runs
// inside withTenant so the tenant_iso FORCE-RLS policy (migration 0024) is the
// backstop under the application-level tenant checks.
type PGStore struct{ db DB }

var _ Repo = (*PGStore)(nil)

func scanConnector(row pgx.Row) (Connector, error) {
	var c Connector
	var identity, scopes, idHealth, telHealth, lastVal []byte
	err := row.Scan(
		&c.TenantID, &c.ConnectorID, &c.Provider, &c.DisplayName, &c.AuthMethod,
		&c.PackFullID, &c.State, &identity, &scopes, &idHealth, &telHealth, &lastVal,
		&c.Version, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return Connector{}, err
	}
	_ = json.Unmarshal(identity, &c.Identity)         // best-effort: engine-authored JSON; malformed decodes to zero value
	_ = json.Unmarshal(scopes, &c.Scopes)             // best-effort: engine-authored JSON; malformed decodes to zero value
	_ = json.Unmarshal(idHealth, &c.IdentityHealth)   // best-effort: engine-authored JSON; malformed decodes to zero value
	_ = json.Unmarshal(telHealth, &c.TelemetryHealth) // best-effort: engine-authored JSON; malformed decodes to zero value
	_ = json.Unmarshal(lastVal, &c.LastValidation)    // best-effort: engine-authored JSON; malformed decodes to zero value
	if c.Scopes == nil {
		c.Scopes = []Scope{}
	}
	return c, nil
}

const ccnCols = `tenant_id, connector_id, provider, display_name, auth_method, pack_full_id,
	state, identity, scopes, identity_health, telemetry_health, last_validation,
	row_version, created_at, updated_at`

func (st *PGStore) List(ctx context.Context, tenant string, cross bool) ([]Connector, error) {
	out := make([]Connector, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+ccnCols+` FROM cloud_connectors ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanConnector(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (st *PGStore) Get(ctx context.Context, tenant string, cross bool, id string) (Connector, bool, error) {
	var c Connector
	found := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+ccnCols+` FROM cloud_connectors WHERE connector_id=$1`, id)
		got, e := scanConnector(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		c, found = got, true
		return nil
	})
	return c, found, err
}

func (st *PGStore) Create(ctx context.Context, c Connector) (Connector, error) {
	err := st.db.WithTenant(ctx, c.TenantID, false, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`INSERT INTO cloud_connectors (tenant_id, connector_id, provider, display_name, auth_method,
				pack_full_id, state, identity, scopes, identity_health, telemetry_health, last_validation)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 RETURNING row_version, created_at, updated_at`,
			c.TenantID, c.ConnectorID, string(c.Provider), c.DisplayName, string(c.AuthMethod),
			c.PackFullID, string(c.State), ccnJSON(c.Identity), ccnJSON(c.Scopes),
			ccnJSON(c.IdentityHealth), ccnJSON(c.TelemetryHealth), ccnJSON(c.LastValidation))
		return row.Scan(&c.Version, &c.CreatedAt, &c.UpdatedAt)
	})
	return c, err
}

func (st *PGStore) Update(ctx context.Context, c Connector, expectVersion int64) (Connector, bool, error) {
	found := false
	err := st.db.WithTenant(ctx, c.TenantID, false, func(tx pgx.Tx) error {
		var curVersion int64
		err := tx.QueryRow(ctx, `SELECT row_version FROM cloud_connectors WHERE connector_id=$1 FOR UPDATE`, c.ConnectorID).Scan(&curVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		if expectVersion != 0 && curVersion != expectVersion {
			return ErrVersionConflict
		}
		row := tx.QueryRow(ctx,
			`UPDATE cloud_connectors SET provider=$2, display_name=$3, auth_method=$4, pack_full_id=$5,
				state=$6, identity=$7, scopes=$8, identity_health=$9, telemetry_health=$10,
				last_validation=$11, row_version=row_version+1, updated_at=now()
			 WHERE connector_id=$1 RETURNING row_version, created_at, updated_at`,
			c.ConnectorID, string(c.Provider), c.DisplayName, string(c.AuthMethod), c.PackFullID,
			string(c.State), ccnJSON(c.Identity), ccnJSON(c.Scopes), ccnJSON(c.IdentityHealth),
			ccnJSON(c.TelemetryHealth), ccnJSON(c.LastValidation))
		return row.Scan(&c.Version, &c.CreatedAt, &c.UpdatedAt)
	})
	if err != nil {
		return Connector{}, found, err
	}
	return c, found, nil
}

func (st *PGStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM cloud_secret_references WHERE connector_id=$1`, id); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx, `DELETE FROM cloud_connectors WHERE connector_id=$1`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

func (st *PGStore) PutSecretRef(ctx context.Context, ref SecretRef) error {
	return st.db.WithTenant(ctx, ref.TenantID, false, func(tx pgx.Tx) error {
		var rotated any
		if ref.RotatedAt != nil {
			rotated = *ref.RotatedAt
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO cloud_secret_references (tenant_id, secret_ref, connector_id, provider, kind,
				ciphertext, fields_set, key_hint, secret_version, rotated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			 ON CONFLICT (tenant_id, secret_ref) DO UPDATE SET
				ciphertext=EXCLUDED.ciphertext, fields_set=EXCLUDED.fields_set, key_hint=EXCLUDED.key_hint,
				secret_version=EXCLUDED.secret_version, rotated_at=EXCLUDED.rotated_at, updated_at=now()`,
			ref.TenantID, ref.SecretRef, ref.ConnectorID, string(ref.Provider), ref.Kind,
			ref.Ciphertext, ref.FieldsSet, ref.KeyHint, ref.Version, rotated)
		return err
	})
}

func (st *PGStore) GetSecretRef(ctx context.Context, tenant string, cross bool, ref string) (SecretRef, bool, error) {
	var r SecretRef
	found := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id, secret_ref, connector_id, provider, kind, ciphertext, fields_set,
				key_hint, secret_version, created_at, updated_at, rotated_at
			 FROM cloud_secret_references WHERE secret_ref=$1`, ref)
		var rotated *time.Time
		e := row.Scan(&r.TenantID, &r.SecretRef, &r.ConnectorID, &r.Provider, &r.Kind, &r.Ciphertext,
			&r.FieldsSet, &r.KeyHint, &r.Version, &r.CreatedAt, &r.UpdatedAt, &rotated)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		r.RotatedAt = rotated
		found = true
		return nil
	})
	return r, found, err
}

func (st *PGStore) ListSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) ([]SecretRef, error) {
	out := make([]SecretRef, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id, secret_ref, connector_id, provider, kind, '' AS ciphertext, fields_set,
				key_hint, secret_version, created_at, updated_at, rotated_at
			 FROM cloud_secret_references WHERE connector_id=$1 ORDER BY secret_ref`, connectorID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r SecretRef
			var rotated *time.Time
			var ct string
			if e := rows.Scan(&r.TenantID, &r.SecretRef, &r.ConnectorID, &r.Provider, &r.Kind, &ct,
				&r.FieldsSet, &r.KeyHint, &r.Version, &r.CreatedAt, &r.UpdatedAt, &rotated); e != nil {
				return e
			}
			r.RotatedAt = rotated
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (st *PGStore) DeleteSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) (int, error) {
	n := 0
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM cloud_secret_references WHERE connector_id=$1`, connectorID)
		if e != nil {
			return e
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}
