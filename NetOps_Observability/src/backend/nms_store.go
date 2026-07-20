package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/nms"
)

// nms_store.go — persistence for the NMS vendor-controller framework (#95 P3b,
// migration 0020). Two backends behind one interface (topology_store.go
// convention): memNMSStore for the file/dev backend + tests, pgNMSStore for
// production. Isolation is enforced IN the store (§3a): every read is scoped by
// the caller's tenant (PG via FORCE-RLS withTenant, mem via tenant-keyed maps);
// cross-tenant reads happen only on the explicit platform-scope methods the
// scheduler/webhook lookup use. Credentials are Vault-encrypted per-tenant DEK
// and write-only: no method ever returns them to an API caller.

// nmsIntegration is one configured controller integration (integrations table).
// Secrets never live on this struct.
type nmsIntegration struct {
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

// nmsRunRecord is one poll/webhook run (connector_run_history row).
type nmsRunRecord struct {
	Tenant        string    `json:"-"`
	IntegrationID string    `json:"-"`
	RunID         string    `json:"runId"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Status        string    `json:"status"` // ok | error
	Events        int64     `json:"events"`
	Error         string    `json:"error,omitempty"`
}

// nmsHealth is the connector_health snapshot + recent runs.
type nmsHealth struct {
	Healthy        bool           `json:"healthy"`
	LastSuccess    time.Time      `json:"lastSuccess,omitempty"`
	LastError      string         `json:"lastError,omitempty"`
	LastErrorAt    time.Time      `json:"lastErrorAt,omitempty"`
	EventsIngested int64          `json:"eventsIngested"`
	ErrorRate      float64        `json:"errorRate"`
	UpdatedAt      time.Time      `json:"updatedAt,omitempty"`
	Runs           []nmsRunRecord `json:"runs,omitempty"`
}

// nmsCredFieldID is the Vault AAD field-id for one credential field. Mirrors
// snmp_creds.go: static per-field ids, tenant DEK binds the ciphertext to the
// owning tenant.
func nmsCredFieldID(field string) string { return "nms." + field }

// credsFromFields maps the operator-supplied credential fields onto
// nms.Credentials. Known keys populate the struct; everything else (org,
// domain, webhook_secret, …) rides in Extra.
func credsFromFields(fields map[string]string) nms.Credentials {
	c := nms.Credentials{}
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

// nmsConfigStore is the persistence seam the handlers + scheduler drive.
type nmsConfigStore interface {
	List(ctx context.Context, tenant string, cross bool) ([]nmsIntegration, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (nmsIntegration, bool, error)
	// Upsert writes c for c.Tenant (already stamped by the caller from the
	// authenticated principal — never from the request body).
	Upsert(ctx context.Context, c nmsIntegration) error
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
	// SetCredentials replaces the stored credential fields (write-only surface).
	SetCredentials(ctx context.Context, tenant, id string, fields map[string]string) error
	// Credentials returns the DECRYPTED credentials (runtime use only — never
	// serialized to an API response) plus the set field names (UI display).
	Credentials(ctx context.Context, tenant, id string) (nms.Credentials, []string, error)
	// ListEnabled returns every enabled integration across all tenants
	// (platform scope — the scheduler's work list).
	ListEnabled(ctx context.Context) ([]nmsIntegration, error)
	// ByWebhookToken resolves an integration from its opaque webhook token
	// (platform scope — the webhook is unauthenticated until verified).
	ByWebhookToken(ctx context.Context, token string) (nmsIntegration, bool, error)
	Checkpoints() nms.CheckpointStore
	RecordRun(ctx context.Context, rec nmsRunRecord) error
	UpsertStates(ctx context.Context, tenant, integrationID string, recs []nms.StateRecord) error
	// States returns the tracked controller-state rows for one integration
	// (tenant-scoped read — the UI's state table).
	States(ctx context.Context, tenant string, cross bool, integrationID string) ([]nms.StateRecord, error)
	Health(ctx context.Context, tenant string, cross bool, id string) (nmsHealth, bool, error)
}

// ── in-memory backend (dev/file backend + tests) ─────────────────────────────

type memNMSStore struct {
	mu     sync.Mutex
	ints   map[string]nmsIntegration    // tenant\x00id
	creds  map[string]map[string]string // tenant\x00id → field→plaintext (mem = non-prod)
	health map[string]nmsHealth         // tenant\x00id
	runs   map[string][]nmsRunRecord    // tenant\x00id, bounded
	states map[string]nms.StateRecord   // tenant\x00id\x00entity\x00kind
	cks    *nms.MemCheckpoints
}

func newMemNMSStore() *memNMSStore {
	return &memNMSStore{
		ints:   map[string]nmsIntegration{},
		creds:  map[string]map[string]string{},
		health: map[string]nmsHealth{},
		runs:   map[string][]nmsRunRecord{},
		states: map[string]nms.StateRecord{},
		cks:    nms.NewMemCheckpoints(),
	}
}

func nmsKey(tenant, id string) string { return tenant + "\x00" + id }

func (m *memNMSStore) List(_ context.Context, tenant string, cross bool) ([]nmsIntegration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []nmsIntegration
	for _, c := range m.ints {
		if cross || c.Tenant == tenant {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memNMSStore) Get(_ context.Context, tenant string, cross bool, id string) (nmsIntegration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.ints {
		if c.ID == id && (cross || c.Tenant == tenant) {
			return c, true, nil
		}
	}
	return nmsIntegration{}, false, nil
}

func (m *memNMSStore) Upsert(_ context.Context, c nmsIntegration) error {
	if c.Tenant == "" || c.ID == "" {
		return errors.New("nms: tenant and id required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c.UpdatedAt = time.Now().UTC()
	if prev, ok := m.ints[nmsKey(c.Tenant, c.ID)]; ok {
		c.CreatedAt = prev.CreatedAt
	} else if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	m.ints[nmsKey(c.Tenant, c.ID)] = c
	return nil
}

func (m *memNMSStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
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

func (m *memNMSStore) SetCredentials(_ context.Context, tenant, id string, fields map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	m.creds[nmsKey(tenant, id)] = cp
	return nil
}

func (m *memNMSStore) Credentials(_ context.Context, tenant, id string) (nms.Credentials, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fields := m.creds[nmsKey(tenant, id)]
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	return credsFromFields(fields), names, nil
}

func (m *memNMSStore) ListEnabled(_ context.Context) ([]nmsIntegration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []nmsIntegration
	for _, c := range m.ints {
		if c.Enabled {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memNMSStore) ByWebhookToken(_ context.Context, token string) (nmsIntegration, bool, error) {
	if token == "" {
		return nmsIntegration{}, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.ints {
		if c.WebhookToken == token {
			return c, true, nil
		}
	}
	return nmsIntegration{}, false, nil
}

func (m *memNMSStore) Checkpoints() nms.CheckpointStore { return m.cks }

const nmsRunHistoryCap = 50

func (m *memNMSStore) RecordRun(_ context.Context, rec nmsRunRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := nmsKey(rec.Tenant, rec.IntegrationID)
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

func (m *memNMSStore) UpsertStates(_ context.Context, tenant, integrationID string, recs []nms.StateRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		m.states[tenant+"\x00"+integrationID+"\x00"+r.EntityKey+"\x00"+r.StateKind] = r
	}
	return nil
}

func (m *memNMSStore) States(_ context.Context, tenant string, cross bool, integrationID string) ([]nms.StateRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []nms.StateRecord
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

func (m *memNMSStore) Health(_ context.Context, tenant string, cross bool, id string) (nmsHealth, bool, error) {
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
	return nmsHealth{}, false, nil
}

// ── Postgres backend (migration 0020, FORCE-RLS) ─────────────────────────────

type pgNMSStore struct {
	db    *pgDB
	vault *Vault
}

func newPGNMSStore(db *pgDB, vault *Vault) *pgNMSStore { return &pgNMSStore{db: db, vault: vault} }

const nmsIntCols = `tenant_id, integration_id, vendor, product, display_name, enabled, base_url, auth_type, poll_interval_s, data_sources, data, created_at, updated_at`

// nmsRowData is the integrations.data JSONB payload (non-column extras).
type nmsRowData struct {
	WebhookToken  string `json:"webhook_token,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

func scanNMSIntegration(row pgx.Row) (nmsIntegration, error) {
	var c nmsIntegration
	var data []byte
	err := row.Scan(&c.Tenant, &c.ID, &c.Vendor, &c.Product, &c.DisplayName, &c.Enabled,
		&c.BaseURL, &c.AuthType, &c.PollIntervalS, &c.Streams, &data, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	if len(data) > 0 {
		var d nmsRowData
		if json.Unmarshal(data, &d) == nil {
			c.WebhookToken = d.WebhookToken
			c.TLSSkipVerify = d.TLSSkipVerify
		}
	}
	return c, nil
}

func (s *pgNMSStore) queryIntegrations(ctx context.Context, tenant string, cross bool, where string, args ...any) ([]nmsIntegration, error) {
	var out []nmsIntegration
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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

func (s *pgNMSStore) List(ctx context.Context, tenant string, cross bool) ([]nmsIntegration, error) {
	return s.queryIntegrations(ctx, tenant, cross, `ORDER BY integration_id`)
}

func (s *pgNMSStore) Get(ctx context.Context, tenant string, cross bool, id string) (nmsIntegration, bool, error) {
	rows, err := s.queryIntegrations(ctx, tenant, cross, `WHERE integration_id=$1`, id)
	if err != nil || len(rows) == 0 {
		return nmsIntegration{}, false, err
	}
	return rows[0], true, nil
}

func (s *pgNMSStore) Upsert(ctx context.Context, c nmsIntegration) error {
	if c.Tenant == "" || c.ID == "" {
		return errors.New("nms: tenant and id required")
	}
	data, err := json.Marshal(nmsRowData{WebhookToken: c.WebhookToken, TLSSkipVerify: c.TLSSkipVerify})
	if err != nil {
		return err
	}
	// System write at platform scope, stamping tenant_id (RLS WITH CHECK allows).
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

func (s *pgNMSStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	var n int64
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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

func (s *pgNMSStore) SetCredentials(ctx context.Context, tenant, id string, fields map[string]string) error {
	// Encrypt each field under the OWNING tenant's DEK (AAD tenant|nms.<field>).
	enc := make(map[string]string, len(fields))
	names := make([]string, 0, len(fields))
	for k, v := range fields {
		ct, err := s.vault.Encrypt(tenant, nmsCredFieldID(k), v)
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
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO integration_credentials_metadata (tenant_id, integration_id, vault_ref, fields_set, rotated_at, updated_at)
 VALUES ($1,$2,$3,$4, now(), now())
 ON CONFLICT (tenant_id, integration_id) DO UPDATE SET
   vault_ref=EXCLUDED.vault_ref, fields_set=EXCLUDED.fields_set, rotated_at=now(), updated_at=now()`,
			tenant, id, string(blob), names)
		return err
	})
}

func (s *pgNMSStore) Credentials(ctx context.Context, tenant, id string) (nms.Credentials, []string, error) {
	var blob string
	var names []string
	err := s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
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
		return nms.Credentials{}, names, err
	}
	var enc map[string]string
	if err := json.Unmarshal([]byte(blob), &enc); err != nil {
		return nms.Credentials{}, names, err
	}
	fields := make(map[string]string, len(enc))
	for k, ct := range enc {
		pt, derr := s.vault.Decrypt(tenant, nmsCredFieldID(k), ct)
		if derr != nil {
			return nms.Credentials{}, names, derr
		}
		fields[k] = pt
	}
	return credsFromFields(fields), names, nil
}

func (s *pgNMSStore) ListEnabled(ctx context.Context) ([]nmsIntegration, error) {
	return s.queryIntegrations(ctx, "", true, `WHERE enabled ORDER BY tenant_id, integration_id`)
}

func (s *pgNMSStore) ByWebhookToken(ctx context.Context, token string) (nmsIntegration, bool, error) {
	if token == "" {
		return nmsIntegration{}, false, nil
	}
	rows, err := s.queryIntegrations(ctx, "", true, `WHERE data->>'webhook_token' = $1`, token)
	if err != nil || len(rows) == 0 {
		return nmsIntegration{}, false, err
	}
	return rows[0], true, nil
}

// pgNMSCheckpoints implements nms.CheckpointStore over connector_checkpoints.
type pgNMSCheckpoints struct{ db *pgDB }

func (c pgNMSCheckpoints) Load(ctx context.Context, tenant, integrationID, stream string) (nms.Checkpoint, error) {
	var cp nms.Checkpoint
	var t *time.Time
	err := c.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
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

func (c pgNMSCheckpoints) Save(ctx context.Context, tenant, integrationID, stream string, cp nms.Checkpoint) error {
	return c.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO connector_checkpoints (tenant_id, integration_id, stream, last_event_time, last_seq, updated_at)
 VALUES ($1,$2,$3,$4,$5, now())
 ON CONFLICT (tenant_id, integration_id, stream) DO UPDATE SET
   last_event_time=EXCLUDED.last_event_time, last_seq=EXCLUDED.last_seq, updated_at=now()`,
			tenant, integrationID, stream, cp.LastEventTime, cp.LastSeq)
		return err
	})
}

func (s *pgNMSStore) Checkpoints() nms.CheckpointStore { return pgNMSCheckpoints{db: s.db} }

func (s *pgNMSStore) RecordRun(ctx context.Context, rec nmsRunRecord) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

func (s *pgNMSStore) UpsertStates(ctx context.Context, tenant, integrationID string, recs []nms.StateRecord) error {
	if len(recs) == 0 {
		return nil
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

func (s *pgNMSStore) States(ctx context.Context, tenant string, cross bool, integrationID string) ([]nms.StateRecord, error) {
	var out []nms.StateRecord
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT entity_key, state_kind, current_state, previous_state,
			first_seen, last_seen, flap_count, device_id, site_id
			FROM controller_state_current WHERE integration_id=$1
			ORDER BY last_seen DESC LIMIT 500`, integrationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r nms.StateRecord
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

func (s *pgNMSStore) Health(ctx context.Context, tenant string, cross bool, id string) (nmsHealth, bool, error) {
	var h nmsHealth
	var found bool
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
			var r nmsRunRecord
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
