package nms

import (
	"context"
	"encoding/json"
	"errors"
	"netops/backend/internal/vault"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// nms_store.go — persistence for the NMS vendor-controller framework (#95 P3b,
// migration 0020). Two backends behind one interface (topology_store.go
// convention): memStore for the file/dev backend + tests, pgStore for
// production. Isolation is enforced IN the store (§3a): every read is scoped by
// the caller's tenant (PG via FORCE-RLS withTenant, mem via tenant-keyed maps);
// cross-tenant reads happen only on the explicit platform-scope methods the
// scheduler/webhook lookup use. Credentials are vault.Vault-encrypted per-tenant DEK
// and write-only: no method ever returns them to an API caller.

// Integration is one configured controller integration (integrations table).
// Secrets never live on this struct.
type Integration struct {
	Tenant        string    `json:"-"`
	ID            string    `json:"id"`
	Vendor        string    `json:"vendor"`
	Product       string    `json:"product,omitempty"`
	DisplayName   string    `json:"displayName"`
	Enabled       bool      `json:"enabled"`
	BaseURL       string    `json:"baseUrl"`
	AuthType      string    `json:"authType,omitempty"`
	PollIntervalS int       `json:"pollIntervalS"`
	Streams       []string  `json:"streams,omitempty"` // data_sources column; empty = connector defaults
	TLSSkipVerify bool      `json:"tlsSkipVerify,omitempty"`
	WebhookToken  string    `json:"-"` // opaque webhook path token; exposed only as a URL to the owner
	CreatedAt     time.Time `json:"createdAt,omitempty"`
	UpdatedAt     time.Time `json:"updatedAt,omitempty"`
}

// RunRecord is one poll/webhook run (connector_run_history row).
type RunRecord struct {
	Tenant        string    `json:"-"`
	IntegrationID string    `json:"-"`
	RunID         string    `json:"runId"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Status        string    `json:"status"` // ok | error
	Events        int64     `json:"events"`
	Error         string    `json:"error,omitempty"`
}

// Health is the connector_health snapshot + recent runs.
type Health struct {
	Healthy        bool        `json:"healthy"`
	LastSuccess    time.Time   `json:"lastSuccess,omitempty"`
	LastError      string      `json:"lastError,omitempty"`
	LastErrorAt    time.Time   `json:"lastErrorAt,omitempty"`
	EventsIngested int64       `json:"eventsIngested"`
	ErrorRate      float64     `json:"errorRate"`
	UpdatedAt      time.Time   `json:"updatedAt,omitempty"`
	Runs           []RunRecord `json:"runs,omitempty"`
}

// credFieldID is the vault.Vault AAD field-id for one credential field. Mirrors
// snmp_creds.go: static per-field ids, tenant DEK binds the ciphertext to the
// owning tenant.
func credFieldID(field string) string { return "" + field }

// credsFromFields maps the operator-supplied credential fields onto
// Credentials. Known keys populate the struct; everything else (org,
// domain, webhook_secret, …) rides in Extra.
func credsFromFields(fields map[string]string) Credentials {
	c := Credentials{}
	for k, v := range fields {
		switch k {
		case "api_key":
			c.APIKey = v
		case "username":
			c.Username = v
		case "password":
			c.Password = v
		case "token":
			c.Token = v
		case "client_id":
			c.ClientID = v
		case "client_secret":
			c.ClientSecret = v
		default:
			if c.Extra == nil {
				c.Extra = map[string]string{}
			}
			c.Extra[k] = v
		}
	}
	return c
}

// ConfigStore is the persistence seam the handlers + scheduler drive.
type ConfigStore interface {
	List(ctx context.Context, tenant string, cross bool) ([]Integration, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Integration, bool, error)
	// Upsert writes c for c.Tenant (already stamped by the caller from the
	// authenticated principal — never from the request body).
	Upsert(ctx context.Context, c Integration) error
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
	// SetCredentials replaces the stored credential fields (write-only surface).
	SetCredentials(ctx context.Context, tenant, id string, fields map[string]string) error
	// Credentials returns the DECRYPTED credentials (runtime use only — never
	// serialized to an API response) plus the set field names (UI display).
	Credentials(ctx context.Context, tenant, id string) (Credentials, []string, error)
	// ListEnabled returns every enabled integration across all tenants
	// (platform scope — the scheduler's work list).
	ListEnabled(ctx context.Context) ([]Integration, error)
	// ByWebhookToken resolves an integration from its opaque webhook token
	// (platform scope — the webhook is unauthenticated until verified).
	ByWebhookToken(ctx context.Context, token string) (Integration, bool, error)
	Checkpoints() CheckpointStore
	RecordRun(ctx context.Context, rec RunRecord) error
	UpsertStates(ctx context.Context, tenant, integrationID string, recs []StateRecord) error
	// States returns the tracked controller-state rows for one integration
	// (tenant-scoped read — the UI's state table).
	States(ctx context.Context, tenant string, cross bool, integrationID string) ([]StateRecord, error)
	Health(ctx context.Context, tenant string, cross bool, id string) (Health, bool, error)
}

// ── in-memory backend (dev/file backend + tests) ─────────────────────────────

type memStore struct {
	mu     sync.Mutex
	ints   map[string]Integration       // tenant\x00id
	creds  map[string]map[string]string // tenant\x00id → field→plaintext (mem = non-prod)
	health map[string]Health            // tenant\x00id
	runs   map[string][]RunRecord       // tenant\x00id, bounded
	states map[string]StateRecord       // tenant\x00id\x00entity\x00kind
	cks    *MemCheckpoints
}

func NewMemStore() *memStore {
	return &memStore{
		ints:   map[string]Integration{},
		creds:  map[string]map[string]string{},
		health: map[string]Health{},
		runs:   map[string][]RunRecord{},
		states: map[string]StateRecord{},
		cks:    NewMemCheckpoints(),
	}
}

// Key is the composite (tenant, id) map key the store and its integrator's
// scheduler bookkeeping share.
func Key(tenant, id string) string { return tenant + "\x00" + id }

func (m *memStore) List(_ context.Context, tenant string, cross bool) ([]Integration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Integration
	for _, c := range m.ints {
		if cross || c.Tenant == tenant {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memStore) Get(_ context.Context, tenant string, cross bool, id string) (Integration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.ints {
		if c.ID == id && (cross || c.Tenant == tenant) {
			return c, true, nil
		}
	}
	return Integration{}, false, nil
}

func (m *memStore) Upsert(_ context.Context, c Integration) error {
	if c.Tenant == "" || c.ID == "" {
		return errors.New("nms: tenant and id required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c.UpdatedAt = time.Now().UTC()
	if prev, ok := m.ints[Key(c.Tenant, c.ID)]; ok {
		c.CreatedAt = prev.CreatedAt
	} else if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	m.ints[Key(c.Tenant, c.ID)] = c
	return nil
}

func (m *memStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, c := range m.ints {
		if c.ID == id && (cross || c.Tenant == tenant) {
			delete(m.ints, k)
			delete(m.creds, k)
			delete(m.health, k)
			delete(m.runs, k)
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) SetCredentials(_ context.Context, tenant, id string, fields map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	m.creds[Key(tenant, id)] = cp
	return nil
}

func (m *memStore) Credentials(_ context.Context, tenant, id string) (Credentials, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fields := m.creds[Key(tenant, id)]
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	return credsFromFields(fields), names, nil
}

func (m *memStore) ListEnabled(_ context.Context) ([]Integration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Integration
	for _, c := range m.ints {
		if c.Enabled {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memStore) ByWebhookToken(_ context.Context, token string) (Integration, bool, error) {
	if token == "" {
		return Integration{}, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.ints {
		if c.WebhookToken == token {
			return c, true, nil
		}
	}
	return Integration{}, false, nil
}

func (m *memStore) Checkpoints() CheckpointStore { return m.cks }

const nmsRunHistoryCap = 50

func (m *memStore) RecordRun(_ context.Context, rec RunRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := Key(rec.Tenant, rec.IntegrationID)
	runs := append(m.runs[k], rec)
	if len(runs) > nmsRunHistoryCap {
		runs = runs[len(runs)-nmsRunHistoryCap:]
	}
	m.runs[k] = runs
	h := m.health[k]
	h.EventsIngested += rec.Events
	h.UpdatedAt = time.Now().UTC()
	if rec.Status == "ok" {
		h.Healthy = true
		h.LastSuccess = rec.Finished
	} else {
		h.Healthy = false
		h.LastError = rec.Error
		h.LastErrorAt = rec.Finished
	}
	var errs int
	for _, r := range runs {
		if r.Status != "ok" {
			errs++
		}
	}
	h.ErrorRate = float64(errs) / float64(len(runs))
	m.health[k] = h
	return nil
}

func (m *memStore) UpsertStates(_ context.Context, tenant, integrationID string, recs []StateRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		m.states[tenant+"\x00"+integrationID+"\x00"+r.EntityKey+"\x00"+r.StateKind] = r
	}
	return nil
}

func (m *memStore) States(_ context.Context, tenant string, cross bool, integrationID string) ([]StateRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StateRecord
	for k, r := range m.states {
		parts := strings.SplitN(k, "\x00", 3)
		if len(parts) < 3 {
			continue
		}
		if parts[1] != integrationID {
			continue
		}
		if !cross && parts[0] != tenant {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

func (m *memStore) Health(_ context.Context, tenant string, cross bool, id string) (Health, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, c := range m.ints {
		if c.ID == id && (cross || c.Tenant == tenant) {
			h := m.health[k]
			runs := m.runs[k]
			// newest first, capped for the API
			for i := len(runs) - 1; i >= 0 && len(h.Runs) < 20; i-- {
				h.Runs = append(h.Runs, runs[i])
			}
			return h, true, nil
		}
	}
	return Health{}, false, nil
}

// ── Postgres backend (migration 0020, FORCE-RLS) ─────────────────────────────

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security is scoped to tenant (or unscoped for a cross-tenant
// principal). Implemented by package main's rlsPG adapter (the portintel.DB
// idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct {
	db    DB
	vault *vault.Vault
}

func NewPGStore(db DB, vault *vault.Vault) *pgStore {
	return &pgStore{db: db, vault: vault}
}

const nmsIntCols = `tenant_id, integration_id, vendor, product, display_name, enabled, base_url, auth_type, poll_interval_s, data_sources, data, created_at, updated_at`

// rowData is the integrations.data JSONB payload (non-column extras).
type rowData struct {
	WebhookToken  string `json:"webhook_token,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

func scanNMSIntegration(row pgx.Row) (Integration, error) {
	var c Integration
	var data []byte
	err := row.Scan(&c.Tenant, &c.ID, &c.Vendor, &c.Product, &c.DisplayName, &c.Enabled,
		&c.BaseURL, &c.AuthType, &c.PollIntervalS, &c.Streams, &data, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	if len(data) > 0 {
		var d rowData
		if json.Unmarshal(data, &d) == nil {
			c.WebhookToken = d.WebhookToken
			c.TLSSkipVerify = d.TLSSkipVerify
		}
	}
	return c, nil
}

func (s *pgStore) queryIntegrations(ctx context.Context, tenant string, cross bool, where string, args ...any) ([]Integration, error) {
	var out []Integration
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+nmsIntCols+` FROM integrations `+where, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanNMSIntegration(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) List(ctx context.Context, tenant string, cross bool) ([]Integration, error) {
	return s.queryIntegrations(ctx, tenant, cross, `ORDER BY integration_id`)
}

func (s *pgStore) Get(ctx context.Context, tenant string, cross bool, id string) (Integration, bool, error) {
	rows, err := s.queryIntegrations(ctx, tenant, cross, `WHERE integration_id=$1`, id)
	if err != nil || len(rows) == 0 {
		return Integration{}, false, err
	}
	return rows[0], true, nil
}

func (s *pgStore) Upsert(ctx context.Context, c Integration) error {
	if c.Tenant == "" || c.ID == "" {
		return errors.New("nms: tenant and id required")
	}
	data, err := json.Marshal(rowData{WebhookToken: c.WebhookToken, TLSSkipVerify: c.TLSSkipVerify})
	if err != nil {
		return err
	}
	// System write at platform scope, stamping tenant_id (RLS WITH CHECK allows).
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO integrations
   (tenant_id, integration_id, vendor, product, display_name, enabled, base_url, auth_type, poll_interval_s, data_sources, data, created_at, updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now(), now())
 ON CONFLICT (tenant_id, integration_id) DO UPDATE SET
   vendor=EXCLUDED.vendor, product=EXCLUDED.product, display_name=EXCLUDED.display_name,
   enabled=EXCLUDED.enabled, base_url=EXCLUDED.base_url, auth_type=EXCLUDED.auth_type,
   poll_interval_s=EXCLUDED.poll_interval_s, data_sources=EXCLUDED.data_sources,
   data=EXCLUDED.data, updated_at=now()`,
			c.Tenant, c.ID, c.Vendor, c.Product, c.DisplayName, c.Enabled, c.BaseURL,
			c.AuthType, c.PollIntervalS, c.Streams, data)
		return err
	})
}

func (s *pgStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	var n int64
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// RLS bounds every statement to the caller's tenant.
		for _, q := range []string{
			`DELETE FROM integration_credentials_metadata WHERE integration_id=$1`,
			`DELETE FROM connector_checkpoints WHERE integration_id=$1`,
			`DELETE FROM connector_health WHERE integration_id=$1`,
			`DELETE FROM connector_run_history WHERE integration_id=$1`,
			`DELETE FROM controller_state_current WHERE integration_id=$1`,
		} {
			if _, err := tx.Exec(ctx, q, id); err != nil {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM integrations WHERE integration_id=$1`, id)
		n = tag.RowsAffected()
		return err
	})
	return n > 0, err
}

func (s *pgStore) SetCredentials(ctx context.Context, tenant, id string, fields map[string]string) error {
	// Encrypt each field under the OWNING tenant's DEK (AAD tenant|<field>).
	enc := make(map[string]string, len(fields))
	names := make([]string, 0, len(fields))
	for k, v := range fields {
		ct, err := s.vault.Encrypt(tenant, credFieldID(k), v)
		if err != nil {
			return err
		}
		enc[k] = ct
		names = append(names, k)
	}
	sort.Strings(names)
	blob, err := json.Marshal(enc)
	if err != nil {
		return err
	}
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO integration_credentials_metadata (tenant_id, integration_id, vault_ref, fields_set, rotated_at, updated_at)
 VALUES ($1,$2,$3,$4, now(), now())
 ON CONFLICT (tenant_id, integration_id) DO UPDATE SET
   vault_ref=EXCLUDED.vault_ref, fields_set=EXCLUDED.fields_set, rotated_at=now(), updated_at=now()`,
			tenant, id, string(blob), names)
		return err
	})
}

func (s *pgStore) Credentials(ctx context.Context, tenant, id string) (Credentials, []string, error) {
	var blob string
	var names []string
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT vault_ref, fields_set FROM integration_credentials_metadata WHERE integration_id=$1`, id)
		if err := row.Scan(&blob, &names); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil || blob == "" {
		return Credentials{}, names, err
	}
	var enc map[string]string
	if err := json.Unmarshal([]byte(blob), &enc); err != nil {
		return Credentials{}, names, err
	}
	fields := make(map[string]string, len(enc))
	for k, ct := range enc {
		pt, derr := s.vault.Decrypt(tenant, credFieldID(k), ct)
		if derr != nil {
			return Credentials{}, names, derr
		}
		fields[k] = pt
	}
	return credsFromFields(fields), names, nil
}

func (s *pgStore) ListEnabled(ctx context.Context) ([]Integration, error) {
	return s.queryIntegrations(ctx, "", true, `WHERE enabled ORDER BY tenant_id, integration_id`)
}

func (s *pgStore) ByWebhookToken(ctx context.Context, token string) (Integration, bool, error) {
	if token == "" {
		return Integration{}, false, nil
	}
	rows, err := s.queryIntegrations(ctx, "", true, `WHERE data->>'webhook_token' = $1`, token)
	if err != nil || len(rows) == 0 {
		return Integration{}, false, err
	}
	return rows[0], true, nil
}

// pgNMSCheckpoints implements CheckpointStore over connector_checkpoints.
type pgNMSCheckpoints struct{ db DB }

func (c pgNMSCheckpoints) Load(ctx context.Context, tenant, integrationID, stream string) (Checkpoint, error) {
	var cp Checkpoint
	var t *time.Time
	err := c.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT last_event_time, last_seq FROM connector_checkpoints
			WHERE integration_id=$1 AND stream=$2`, integrationID, stream)
		if err := row.Scan(&t, &cp.LastSeq); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		return nil
	})
	if t != nil {
		cp.LastEventTime = *t
	}
	return cp, err
}

func (c pgNMSCheckpoints) Save(ctx context.Context, tenant, integrationID, stream string, cp Checkpoint) error {
	return c.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO connector_checkpoints (tenant_id, integration_id, stream, last_event_time, last_seq, updated_at)
 VALUES ($1,$2,$3,$4,$5, now())
 ON CONFLICT (tenant_id, integration_id, stream) DO UPDATE SET
   last_event_time=EXCLUDED.last_event_time, last_seq=EXCLUDED.last_seq, updated_at=now()`,
			tenant, integrationID, stream, cp.LastEventTime, cp.LastSeq)
		return err
	})
}

func (s *pgStore) Checkpoints() CheckpointStore { return pgNMSCheckpoints{db: s.db} }

func (s *pgStore) RecordRun(ctx context.Context, rec RunRecord) error {
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO connector_run_history (tenant_id, integration_id, run_id, started_at, finished_at, status, events, error)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
 ON CONFLICT (tenant_id, integration_id, run_id) DO NOTHING`,
			rec.Tenant, rec.IntegrationID, rec.RunID, rec.Started, rec.Finished, rec.Status, rec.Events, rec.Error); err != nil {
			return err
		}
		// Bound the history (reliability §9: no unbounded growth).
		if _, err := tx.Exec(ctx, `DELETE FROM connector_run_history
			WHERE tenant_id=$1 AND integration_id=$2 AND started_at < now() - interval '14 days'`,
			rec.Tenant, rec.IntegrationID); err != nil {
			return err
		}
		var errRate float64
		row := tx.QueryRow(ctx, `SELECT COALESCE(avg(CASE WHEN status='ok' THEN 0.0 ELSE 1.0 END), 0)
			FROM (SELECT status FROM connector_run_history
			      WHERE tenant_id=$1 AND integration_id=$2
			      ORDER BY started_at DESC LIMIT $3) recent`,
			rec.Tenant, rec.IntegrationID, nmsRunHistoryCap)
		if err := row.Scan(&errRate); err != nil {
			return err
		}
		healthy := rec.Status == "ok"
		var lastSuccess, lastErrAt *time.Time
		var lastErr string
		if healthy {
			lastSuccess = &rec.Finished
		} else {
			lastErrAt = &rec.Finished
			lastErr = rec.Error
		}
		_, err := tx.Exec(ctx, `
INSERT INTO connector_health (tenant_id, integration_id, healthy, last_success, last_error, last_error_at, events_ingested, error_rate, updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
 ON CONFLICT (tenant_id, integration_id) DO UPDATE SET
   healthy=EXCLUDED.healthy,
   last_success=COALESCE(EXCLUDED.last_success, connector_health.last_success),
   last_error=CASE WHEN EXCLUDED.healthy THEN connector_health.last_error ELSE EXCLUDED.last_error END,
   last_error_at=COALESCE(EXCLUDED.last_error_at, connector_health.last_error_at),
   events_ingested=connector_health.events_ingested + EXCLUDED.events_ingested,
   error_rate=EXCLUDED.error_rate, updated_at=now()`,
			rec.Tenant, rec.IntegrationID, healthy, lastSuccess, lastErr, lastErrAt, rec.Events, errRate)
		return err
	})
}

func (s *pgStore) UpsertStates(ctx context.Context, tenant, integrationID string, recs []StateRecord) error {
	if len(recs) == 0 {
		return nil
	}
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range recs {
			if _, err := tx.Exec(ctx, `
INSERT INTO controller_state_current
   (tenant_id, integration_id, entity_key, state_kind, current_state, previous_state, first_seen, last_seen, flap_count, device_id, site_id, data)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}')
 ON CONFLICT (tenant_id, integration_id, entity_key, state_kind) DO UPDATE SET
   current_state=EXCLUDED.current_state, previous_state=EXCLUDED.previous_state,
   last_seen=EXCLUDED.last_seen, flap_count=EXCLUDED.flap_count,
   device_id=EXCLUDED.device_id, site_id=EXCLUDED.site_id`,
				tenant, integrationID, r.EntityKey, r.StateKind, r.CurrentState, r.PreviousState,
				r.FirstSeen, r.LastSeen, r.FlapCount, r.DeviceID, r.SiteID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *pgStore) States(ctx context.Context, tenant string, cross bool, integrationID string) ([]StateRecord, error) {
	var out []StateRecord
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT entity_key, state_kind, current_state, previous_state,
			first_seen, last_seen, flap_count, device_id, site_id
			FROM controller_state_current WHERE integration_id=$1
			ORDER BY last_seen DESC LIMIT 500`, integrationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r StateRecord
			if err := rows.Scan(&r.EntityKey, &r.StateKind, &r.CurrentState, &r.PreviousState,
				&r.FirstSeen, &r.LastSeen, &r.FlapCount, &r.DeviceID, &r.SiteID); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) Health(ctx context.Context, tenant string, cross bool, id string) (Health, bool, error) {
	var h Health
	var found bool
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// Health row may not exist yet for a never-run integration — the
		// integration row decides existence.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM integrations WHERE integration_id=$1`, id).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		found = true
		var lastSuccess, lastErrAt, updated *time.Time
		row := tx.QueryRow(ctx, `SELECT healthy, last_success, last_error, last_error_at, events_ingested, error_rate, updated_at
			FROM connector_health WHERE integration_id=$1`, id)
		if err := row.Scan(&h.Healthy, &lastSuccess, &h.LastError, &lastErrAt, &h.EventsIngested, &h.ErrorRate, &updated); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if lastSuccess != nil {
			h.LastSuccess = *lastSuccess
		}
		if lastErrAt != nil {
			h.LastErrorAt = *lastErrAt
		}
		if updated != nil {
			h.UpdatedAt = *updated
		}
		rows, err := tx.Query(ctx, `SELECT run_id, started_at, finished_at, status, events, error
			FROM connector_run_history WHERE integration_id=$1 ORDER BY started_at DESC LIMIT 20`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r RunRecord
			var fin *time.Time
			if err := rows.Scan(&r.RunID, &r.Started, &fin, &r.Status, &r.Events, &r.Error); err != nil {
				return err
			}
			if fin != nil {
				r.Finished = *fin
			}
			h.Runs = append(h.Runs, r)
		}
		return rows.Err()
	})
	return h, found, err
}

// ── non-durable guard (F-76) ────────────────────────────────────────────────

// ErrStorageNotDurable is returned when an NMS credential write is attempted
// against storage that cannot survive a restart.
var ErrStorageNotDurable = errors.New(
	"NMS integrations require the Postgres backend (STORE_BACKEND=postgres) to store credentials; " +
		"they are refused rather than held in memory")

// NonDurableStore is the in-memory store with credential writes REFUSED.
//
// F-76: on the file backend an operator pasted controller credentials, received
// 201 Created, and had them held as PLAINTEXT in a Go map until the next
// restart — after which the webhook URLs already registered with Meraki became
// permanent 404s. The integration list and the static connector catalog are
// still served (a fresh install renders its gallery, which is why the runtime is
// wired at all); only the credential write is refused, and it says why.
//
// Tests that need the permissive behaviour use NewMemStore() directly.
type NonDurableStore struct{ *memStore }

// NewNonDurableStore wraps a fresh in-memory store with credential writes
// refused (the file-backend deployment shape).
func NewNonDurableStore() NonDurableStore { return NonDurableStore{NewMemStore()} }

func (NonDurableStore) SetCredentials(_ context.Context, _, _ string, _ map[string]string) error {
	return ErrStorageNotDurable
}

// Durable reports whether credentials written here survive a restart.
func (NonDurableStore) Durable() bool { return false }
func (*memStore) Durable() bool       { return true }
func (*pgStore) Durable() bool        { return true }

// StoreDurable reports whether a store persists credentials across a
// restart. Stores that do not implement the probe are assumed durable — only
// the explicit non-durable wrapper opts out.
func StoreDurable(st ConfigStore) bool {
	if d, ok := st.(interface{ Durable() bool }); ok {
		return d.Durable()
	}
	return true
}
