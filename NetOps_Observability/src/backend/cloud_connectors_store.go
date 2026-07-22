package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"netops/backend/cloudconn"
)

// ── domain model ─────────────────────────────────────────────────────────────

// ccnIDPrefix / csrIDPrefix are the stable opaque-id type tags for a cloud
// connector and a cloud secret reference. Kept next to the feature (not in
// identity_ids.go) to minimize cross-feature churn; minted via newOpaqueID.
const (
	ccnIDPrefix = "ccn_"
	csrIDPrefix = "csr_"
)

// healthStatus is a single health signal. Identity health (can we authenticate?)
// is tracked SEPARATELY from telemetry health (is data flowing?) — a successful
// auth must never imply data is flowing or permissions are complete.
type healthStatus struct {
	State   string    `json:"state"` // unknown|config_validated|healthy|degraded|failed|unverified
	Detail  string    `json:"detail,omitempty"`
	Checked time.Time `json:"checked,omitempty"`
}

// cloudConnector is the persisted connector. The five concerns are kept distinct:
// Identity (trust metadata, NO secrets), Authorization (PackFullID), CollectionScope
// (Scopes), DataSources (declared by the pack), Health (identity vs telemetry).
type cloudConnector struct {
	TenantID        string                     `json:"tenant_id"`
	ConnectorID     string                     `json:"connector_id"`
	Provider        cloudconn.Provider         `json:"provider"`
	DisplayName     string                     `json:"display_name"`
	AuthMethod      cloudconn.AuthMethod       `json:"auth_method"`
	PackFullID      string                     `json:"pack_full_id"`
	State           cloudconn.LifecycleState   `json:"state"`
	Identity        cloudconn.IdentityConfig   `json:"identity"`
	Scopes          []cloudconn.Scope          `json:"scopes"`
	IdentityHealth  healthStatus               `json:"identity_health"`
	TelemetryHealth healthStatus               `json:"telemetry_health"`
	LastValidation  cloudconn.ValidationResult `json:"last_validation"`
	Version         int64                      `json:"version"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

// cloudSecretRef is a vault-backed handle for an UNAVOIDABLE legacy secret. It
// holds the envelope-Vault ciphertext + non-secret metadata only. The plaintext
// and the Ciphertext are NEVER returned through the connector API — only the
// Identity Broker reads Ciphertext (to decrypt it at token-exchange time).
type cloudSecretRef struct {
	TenantID    string             `json:"tenant_id"`
	SecretRef   string             `json:"secret_ref"`
	ConnectorID string             `json:"connector_id"`
	Provider    cloudconn.Provider `json:"provider"`
	Kind        string             `json:"kind"`
	Ciphertext  string             `json:"-"` // v1: vault ciphertext — never serialized to API
	FieldsSet   []string           `json:"fields_set"`
	KeyHint     string             `json:"key_hint"` // non-secret (AccessKeyId / SA key id)
	Version     int64              `json:"version"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	RotatedAt   *time.Time         `json:"rotated_at,omitempty"`
}

var errCCNVersionConflict = errors.New("cloudconn: version conflict (stale update)")

// cloudConnRepo is the storage seam. Both implementations enforce tenant scoping
// default-closed: a non-cross caller can never see another tenant's rows.
type cloudConnRepo interface {
	List(ctx context.Context, tenant string, cross bool) ([]cloudConnector, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (cloudConnector, bool, error)
	Create(ctx context.Context, c cloudConnector) (cloudConnector, error)
	// Update writes c, requiring the stored row_version to equal expectVersion
	// (0 = skip check). Returns found=false if the row is absent/invisible.
	Update(ctx context.Context, c cloudConnector, expectVersion int64) (cloudConnector, bool, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)

	PutSecretRef(ctx context.Context, ref cloudSecretRef) error
	GetSecretRef(ctx context.Context, tenant string, cross bool, ref string) (cloudSecretRef, bool, error)
	ListSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) ([]cloudSecretRef, error)
	DeleteSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) (int, error)
}

// newCloudConnStore returns the pg store on the postgres backend, and NIL
// otherwise — which makes the handlers' existing `if s.cloudConn == nil { 501 }`
// guards reachable for the first time.
//
// F-76: this used to fall back to an in-memory store, so an operator on the
// file backend pasted an AWS/Azure/GCP credential, received 201 Created, and
// had it held in RAM until the next restart. Nothing said so. Webhook URLs
// already handed to the provider became permanent 404s after a restart, and the
// credential — the whole point of the record — was simply gone.
//
// Refusing is the honest answer, and the codebase already had the pattern: the
// integration platform returns 501/409 "requires the Postgres backend" rather
// than pretending. A credential store that cannot persist should not accept
// credentials. Tests that need the in-memory behaviour construct
// newMemCloudConnStore() directly.
func newCloudConnStore() cloudConnRepo {
	if ps, ok := backend.(*pgStore); ok {
		return &pgCloudConnStore{db: ps.db}
	}
	logWarn("cloud", "cloud connectors disabled: durable storage required", map[string]any{
		"reason": "STORE_BACKEND is not postgres; credentials would live only in RAM",
	})
	return nil
}

// ── in-memory backend (dev/file backend + tests) ─────────────────────────────

type memCloudConnStore struct {
	mu    sync.Mutex
	conns map[string]cloudConnector // tenant\x00id
	refs  map[string]cloudSecretRef // tenant\x00ref
}

func newMemCloudConnStore() *memCloudConnStore {
	return &memCloudConnStore{
		conns: map[string]cloudConnector{},
		refs:  map[string]cloudSecretRef{},
	}
}

func ccnKey(tenant, id string) string { return normTenant(tenant) + "\x00" + id }

func (m *memCloudConnStore) List(_ context.Context, tenant string, cross bool) ([]cloudConnector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]cloudConnector, 0)
	for _, c := range m.conns {
		if cross || sameTenantStrict(c.TenantID, tenant) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *memCloudConnStore) Get(_ context.Context, tenant string, cross bool, id string) (cloudConnector, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		if c.ConnectorID == id && (cross || sameTenantStrict(c.TenantID, tenant)) {
			return c, true, nil
		}
	}
	return cloudConnector{}, false, nil
}

func (m *memCloudConnStore) Create(_ context.Context, c cloudConnector) (cloudConnector, error) {
	if c.TenantID == "" || c.ConnectorID == "" {
		return cloudConnector{}, errors.New("cloudconn: tenant and connector id required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt, c.Version = now, now, 1
	m.conns[ccnKey(c.TenantID, c.ConnectorID)] = c
	return c, nil
}

func (m *memCloudConnStore) Update(_ context.Context, c cloudConnector, expectVersion int64) (cloudConnector, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ccnKey(c.TenantID, c.ConnectorID)
	prev, ok := m.conns[k]
	if !ok {
		return cloudConnector{}, false, nil
	}
	if expectVersion != 0 && prev.Version != expectVersion {
		return cloudConnector{}, true, errCCNVersionConflict
	}
	c.CreatedAt = prev.CreatedAt
	c.Version = prev.Version + 1
	c.UpdatedAt = time.Now().UTC()
	m.conns[k] = c
	return c, true, nil
}

func (m *memCloudConnStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, c := range m.conns {
		if c.ConnectorID == id && (cross || sameTenantStrict(c.TenantID, tenant)) {
			delete(m.conns, k)
			for rk, r := range m.refs {
				if r.ConnectorID == id && sameTenantStrict(r.TenantID, c.TenantID) {
					delete(m.refs, rk)
				}
			}
			return true, nil
		}
	}
	return false, nil
}

func (m *memCloudConnStore) PutSecretRef(_ context.Context, ref cloudSecretRef) error {
	if ref.TenantID == "" || ref.SecretRef == "" {
		return errors.New("cloudconn: tenant and secret ref required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	k := ccnKey(ref.TenantID, ref.SecretRef)
	if prev, ok := m.refs[k]; ok {
		ref.CreatedAt = prev.CreatedAt
	} else {
		ref.CreatedAt = now
	}
	ref.UpdatedAt = now
	m.refs[k] = ref
	return nil
}

func (m *memCloudConnStore) GetSecretRef(_ context.Context, tenant string, cross bool, ref string) (cloudSecretRef, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.refs {
		if r.SecretRef == ref && (cross || sameTenantStrict(r.TenantID, tenant)) {
			return r, true, nil
		}
	}
	return cloudSecretRef{}, false, nil
}

func (m *memCloudConnStore) ListSecretRefs(_ context.Context, tenant string, cross bool, connectorID string) ([]cloudSecretRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]cloudSecretRef, 0)
	for _, r := range m.refs {
		if r.ConnectorID == connectorID && (cross || sameTenantStrict(r.TenantID, tenant)) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecretRef < out[j].SecretRef })
	return out, nil
}

func (m *memCloudConnStore) DeleteSecretRefs(_ context.Context, tenant string, cross bool, connectorID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, r := range m.refs {
		if r.ConnectorID == connectorID && (cross || sameTenantStrict(r.TenantID, tenant)) {
			delete(m.refs, k)
			n++
		}
	}
	return n, nil
}

// ── json (un)marshal helpers for the JSONB columns ───────────────────────────

func ccnJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
