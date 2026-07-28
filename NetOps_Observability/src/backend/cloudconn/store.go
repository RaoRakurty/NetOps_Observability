package cloudconn

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── domain model ─────────────────────────────────────────────────────────────

// ConnectorIDPrefix / SecretRefIDPrefix are the stable opaque-id type tags for a cloud
// connector and a cloud secret reference. Kept next to the feature (not in
// identity_ids.go) to minimize cross-feature churn; minted via newOpaqueID.
const (
	ConnectorIDPrefix = "ccn_"
	SecretRefIDPrefix = "csr_"
)

// HealthStatus is a single health signal. Identity health (can we authenticate?)
// is tracked SEPARATELY from telemetry health (is data flowing?) — a successful
// auth must never imply data is flowing or permissions are complete.
type HealthStatus struct {
	State   string    `json:"state"` // unknown|config_validated|healthy|degraded|failed|unverified
	Detail  string    `json:"detail,omitempty"`
	Checked time.Time `json:"checked,omitempty"`
}

// Connector is the persisted connector. The five concerns are kept distinct:
// Identity (trust metadata, NO secrets), Authorization (PackFullID), CollectionScope
// (Scopes), DataSources (declared by the pack), Health (identity vs telemetry).
type Connector struct {
	TenantID        string           `json:"tenant_id"`
	ConnectorID     string           `json:"connector_id"`
	Provider        Provider         `json:"provider"`
	DisplayName     string           `json:"display_name"`
	AuthMethod      AuthMethod       `json:"auth_method"`
	PackFullID      string           `json:"pack_full_id"`
	State           LifecycleState   `json:"state"`
	Identity        IdentityConfig   `json:"identity"`
	Scopes          []Scope          `json:"scopes"`
	IdentityHealth  HealthStatus     `json:"identity_health"`
	TelemetryHealth HealthStatus     `json:"telemetry_health"`
	LastValidation  ValidationResult `json:"last_validation"`
	Version         int64            `json:"version"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// SecretRef is a vault-backed handle for an UNAVOIDABLE legacy secret. It
// holds the envelope-Vault ciphertext + non-secret metadata only. The plaintext
// and the Ciphertext are NEVER returned through the connector API — only the
// Identity Broker reads Ciphertext (to decrypt it at token-exchange time).
type SecretRef struct {
	TenantID    string     `json:"tenant_id"`
	SecretRef   string     `json:"secret_ref"`
	ConnectorID string     `json:"connector_id"`
	Provider    Provider   `json:"provider"`
	Kind        string     `json:"kind"`
	Ciphertext  string     `json:"-"` // v1: vault ciphertext — never serialized to API
	FieldsSet   []string   `json:"fields_set"`
	KeyHint     string     `json:"key_hint"` // non-secret (AccessKeyId / SA key id)
	Version     int64      `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
}

var ErrVersionConflict = errors.New("cloudconn: version conflict (stale update)")

// Repo is the storage seam. Both implementations enforce tenant scoping
// default-closed: a non-cross caller can never see another tenant's rows.
type Repo interface {
	List(ctx context.Context, tenant string, cross bool) ([]Connector, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Connector, bool, error)
	Create(ctx context.Context, c Connector) (Connector, error)
	// Update writes c, requiring the stored row_version to equal expectVersion
	// (0 = skip check). Returns found=false if the row is absent/invisible.
	Update(ctx context.Context, c Connector, expectVersion int64) (Connector, bool, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)

	PutSecretRef(ctx context.Context, ref SecretRef) error
	GetSecretRef(ctx context.Context, tenant string, cross bool, ref string) (SecretRef, bool, error)
	ListSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) ([]SecretRef, error)
	DeleteSecretRefs(ctx context.Context, tenant string, cross bool, connectorID string) (int, error)
}

// ── in-memory backend (dev/file backend + tests) ─────────────────────────────

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewPGStore builds the FORCE-RLS pg repository over the injected seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

// normTenant / sameTenantStrict mirror the integrator's tenancy helpers
// (duplicated per the no-shared-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func sameTenantStrict(resourceTenant, principalTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}

type MemStore struct {
	mu    sync.Mutex
	conns map[string]Connector // tenant\x00id
	refs  map[string]SecretRef // tenant\x00ref
}

func NewMemStore() *MemStore {
	return &MemStore{
		conns: map[string]Connector{},
		refs:  map[string]SecretRef{},
	}
}

func storeKey(tenant, id string) string { return normTenant(tenant) + "\x00" + id }

func (m *MemStore) List(_ context.Context, tenant string, cross bool) ([]Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Connector, 0)
	for _, c := range m.conns {
		if cross || sameTenantStrict(c.TenantID, tenant) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) Get(_ context.Context, tenant string, cross bool, id string) (Connector, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		if c.ConnectorID == id && (cross || sameTenantStrict(c.TenantID, tenant)) {
			return c, true, nil
		}
	}
	return Connector{}, false, nil
}

func (m *MemStore) Create(_ context.Context, c Connector) (Connector, error) {
	if c.TenantID == "" || c.ConnectorID == "" {
		return Connector{}, errors.New("cloudconn: tenant and connector id required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt, c.Version = now, now, 1
	m.conns[storeKey(c.TenantID, c.ConnectorID)] = c
	return c, nil
}

func (m *MemStore) Update(_ context.Context, c Connector, expectVersion int64) (Connector, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := storeKey(c.TenantID, c.ConnectorID)
	prev, ok := m.conns[k]
	if !ok {
		return Connector{}, false, nil
	}
	if expectVersion != 0 && prev.Version != expectVersion {
		return Connector{}, true, ErrVersionConflict
	}
	c.CreatedAt = prev.CreatedAt
	c.Version = prev.Version + 1
	c.UpdatedAt = time.Now().UTC()
	m.conns[k] = c
	return c, true, nil
}

func (m *MemStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
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

func (m *MemStore) PutSecretRef(_ context.Context, ref SecretRef) error {
	if ref.TenantID == "" || ref.SecretRef == "" {
		return errors.New("cloudconn: tenant and secret ref required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	k := storeKey(ref.TenantID, ref.SecretRef)
	if prev, ok := m.refs[k]; ok {
		ref.CreatedAt = prev.CreatedAt
	} else {
		ref.CreatedAt = now
	}
	ref.UpdatedAt = now
	m.refs[k] = ref
	return nil
}

func (m *MemStore) GetSecretRef(_ context.Context, tenant string, cross bool, ref string) (SecretRef, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.refs {
		if r.SecretRef == ref && (cross || sameTenantStrict(r.TenantID, tenant)) {
			return r, true, nil
		}
	}
	return SecretRef{}, false, nil
}

func (m *MemStore) ListSecretRefs(_ context.Context, tenant string, cross bool, connectorID string) ([]SecretRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SecretRef, 0)
	for _, r := range m.refs {
		if r.ConnectorID == connectorID && (cross || sameTenantStrict(r.TenantID, tenant)) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecretRef < out[j].SecretRef })
	return out, nil
}

func (m *MemStore) DeleteSecretRefs(_ context.Context, tenant string, cross bool, connectorID string) (int, error) {
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
