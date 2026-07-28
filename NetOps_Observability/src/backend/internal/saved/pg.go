package saved

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"strings"
)

// saved_pg.go — the Postgres saved-object repository (#33). One row per object in
// saved_objects, with PER-REQUEST RLS-scoped List reads (a scoped tenant sees
// only its own + global rows; the platform owner sees all) and per-row writes —
// replacing the load-all-into-memory + whole-collection rewrite of the blob
// bridge. Modeled on users_pg.go / audit_pg.go. Writes run platform-scoped (the
// HTTP layer already enforces per-object tenant authz); reads scope via withTenant.
type PGStore struct {
	errf func(component, msg string, fields map[string]any)
	db   DB
}

// normTenant mirrors the integrator's normalization (duplicated).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func NewPGStore(db DB, errf func(component, msg string, fields map[string]any)) *PGStore {
	if errf == nil {
		errf = func(string, string, map[string]any) {}
	}
	return &PGStore{db: db, errf: errf}
}

func (s *PGStore) List(typ, tenant string, cross bool) []Object {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sql := "SELECT data FROM saved_objects"
	var args []any
	if typ != "" {
		args = append(args, typ)
		sql += " WHERE type = $1"
	}
	sql += " ORDER BY updated_at DESC, id DESC"

	out := make([]Object, 0)
	if err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return err
			}
			var o Object
			if err := json.Unmarshal(data, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	}); err != nil {
		s.errf("saved", "list", map[string]any{"error": err.Error()})
		return nil
	}
	return out
}

func (s *PGStore) Get(id string) (Object, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var o Object
	found := false
	// Platform scope: the HTTP layer enforces per-object tenant authz (canSee/
	// canMutateSaved), and the report scheduler reads any tenant's report by id.
	if err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT data FROM saved_objects WHERE id=$1`, id).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &o); err != nil {
			return err
		}
		found = true
		return nil
	}); err != nil {
		s.errf("saved", "get", map[string]any{"error": err.Error()})
		return Object{}, false
	}
	return o, found
}

func (s *PGStore) Create(typ, name, owner, tenant string, body json.RawMessage) (Object, error) {
	if !validSavedTypes[typ] {
		return Object{}, errors.New("invalid type")
	}
	if name == "" {
		return Object{}, errors.New("name required")
	}
	now := time.Now().UTC()
	o := Object{ID: randID(), Type: typ, Name: name, Owner: owner, TenantID: tenant, Body: body, CreatedAt: now, UpdatedAt: now}
	data, err := json.Marshal(o)
	if err != nil {
		return Object{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO saved_objects (id, tenant_id, type, data, updated_at) VALUES ($1,$2,$3,$4,$5)`,
			o.ID, normTenant(o.TenantID), o.Type, data, o.UpdatedAt)
		return err
	}); err != nil {
		return Object{}, err
	}
	return o, nil
}

func (s *PGStore) Update(id, name string, body json.RawMessage) (Object, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out Object
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var data []byte
		if err := tx.QueryRow(ctx, `SELECT data FROM saved_objects WHERE id=$1 FOR UPDATE`, id).Scan(&data); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("not found")
			}
			return err
		}
		var o Object
		if err := json.Unmarshal(data, &o); err != nil {
			return err
		}
		if name != "" {
			o.Name = name
		}
		if len(body) > 0 {
			o.Body = body
		}
		o.UpdatedAt = time.Now().UTC()
		nd, err := json.Marshal(o)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE saved_objects SET data=$2, type=$3, tenant_id=$4, updated_at=$5 WHERE id=$1`,
			id, nd, o.Type, normTenant(o.TenantID), o.UpdatedAt)
		out = o
		return err
	})
	if err != nil {
		return Object{}, err
	}
	return out, nil
}

func (s *PGStore) Delete(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM saved_objects WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errors.New("not found")
		}
		return nil
	})
}

var _ Repo = (*PGStore)(nil)
