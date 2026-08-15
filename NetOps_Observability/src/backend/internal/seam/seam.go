package seam

// seams.go — the canonical seam inventory (#67 build ⑤ / #68 §4). A seam is an
// OWNERSHIP TRANSITION in packet-forwarding responsibility; instances of the
// five canonical types are the entities the correlation engine grounds edges
// against. Postgres holds the inventory (lifecycle/catalog state per the #67
// CH↔PG ownership split); the correlation service pulls the active set via
// GET /api/seams?state=active. Modeled on incidents_pg.go.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SeamTypes are the five canonical ownership-transition types (#68 §4, FINAL).
var SeamTypes = []string{"DX", "VPN", "SDWAN", "DIA", "CLOUD_BACKBONE"}

// SeamStates is the suggest → confirm → active lifecycle; rejected is terminal
// memory (its suggestion_key blocks re-raising), retired removes an active seam
// from grounding without forgetting it.
var SeamStates = []string{"suggested", "confirmed", "active", "rejected", "retired"}

var SeamOwners = []string{"enterprise", "isp", "cloud", "sdwan_controller"}
var SeamVisibilities = []string{"full", "partial", "blind"}
var SeamRedundancyModels = []string{"single", "active_active", "active_standby", "hybrid_fallback"}

// seamTransitions is the allowed state machine. suggested→active is permitted
// so the UI can offer one-click "confirm & activate"; rejected has no exits.
var seamTransitions = map[string][]string{
	"suggested": {"confirmed", "active", "rejected"},
	"confirmed": {"active", "rejected", "retired"},
	"active":    {"retired"},
	"retired":   {"active"},
	"rejected":  {},
}

// seamVisibilityDefault is the HONEST per-type default (#68 §4.1: "visibility
// defaulted honestly — DIA = partial at best"). 'full' is never assumed: it is
// earned when bidirectional probes are confirmed, by owner edit.
var seamVisibilityDefault = map[string]string{
	"DX":             "partial",
	"VPN":            "partial", // underlay invisible through the tunnel
	"SDWAN":          "partial", // controller-driven path selection is opaque
	"DIA":            "partial", // enterprise control ends at the edge
	"CLOUD_BACKBONE": "blind",   // nothing without cloud vantage agents
}

// seamProbeDefault mirrors the probe-strategy column of the canonical seam
// table (#68 §4).
var seamProbeDefault = map[string][]string{
	"DX":             {"stamp"},
	"VPN":            {"icmp", "http_synthetic"},
	"SDWAN":          {"stamp", "icmp"},
	"DIA":            {"icmp", "http_synthetic"},
	"CLOUD_BACKBONE": {"stamp"},
}

// Seam is one inventory row — the unified seam object of #68 §4 plus the
// suggest→confirm lifecycle and bootstrap provenance.
type Seam struct {
	SeamID            string            `json:"seam_id"`
	TenantID          string            `json:"tenant_id"`
	SeamType          string            `json:"seam_type"`
	State             string            `json:"state"`
	DisplayName       string            `json:"display_name"`
	Endpoints         map[string]string `json:"endpoints"`
	ControlPlaneOwner string            `json:"control_plane_owner"`
	Visibility        string            `json:"visibility"`
	ProbeStrategy     []string          `json:"probe_strategy"`
	SuggestedBy       string            `json:"suggested_by"`
	Evidence          map[string]any    `json:"evidence"`
	Confidence        float64           `json:"confidence"`
	SuggestionKey     string            `json:"suggestion_key,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	UpdatedBy         string            `json:"updated_by"`
}

// SeamMember is one member of a redundancy group. Role is owner-assigned at
// confirm time (primary/secondary/fallback); bootstrap suggests "member"
// because it cannot honestly know roles.
type SeamMember struct {
	MemberID string `json:"member_id"`
	Role     string `json:"role"`
	SeamType string `json:"seam_type,omitempty"` // set when it differs from the group (cross-type fallback)
}

// SeamGroup models redundancy at the instance level (#68 §4): same five types,
// fault/impact semantics vary via redundancy_model + members.
type SeamGroup struct {
	GroupID         string         `json:"group_id"`
	TenantID        string         `json:"tenant_id"`
	SeamType        string         `json:"seam_type"`
	RedundancyModel string         `json:"redundancy_model"`
	State           string         `json:"state"`
	DisplayName     string         `json:"display_name"`
	Members         []SeamMember   `json:"members"`
	SuggestedBy     string         `json:"suggested_by"`
	Evidence        map[string]any `json:"evidence"`
	Confidence      float64        `json:"confidence"`
	SuggestionKey   string         `json:"suggestion_key,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	UpdatedBy       string         `json:"updated_by"`
}

var ErrNotFound = errors.New("seam not found")

func ValidEnum(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// TransitionAllowed reports whether from→to is a legal lifecycle step.
// from→from (no state change in a PATCH) is always fine.
func TransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	for _, t := range seamTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// IDForKey derives the deterministic row id for a suggestion, so the same
// evidence always maps to the same (tenant_id, seam_id) and re-suggesting is a
// clean ON CONFLICT no-op against either the PK or the suggestion_key index.
func IDForKey(tenant, key string) string {
	sum := sha256.Sum256([]byte(tenant + "|" + key))
	return "sm-" + hex.EncodeToString(sum[:6])
}

func GroupIDForKey(tenant, key string) string {
	sum := sha256.Sum256([]byte(tenant + "|" + key))
	return "sg-" + hex.EncodeToString(sum[:6])
}

// ── store ─────────────────────────────────────────────────────────────────────

// DB is the injected Postgres seam (§5): the integrator supplies the
// tenant-scoped transaction runner (withTenant + FORCE-RLS on its side), the
// store supplies the SQL. Mirrors the portintel.DB idiom.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// Store is the Postgres-backed canonical seam inventory.
type Store struct {
	db DB
}

// NewPGStore wires the inventory onto an injected DB.
func NewPGStore(db DB) *Store { return &Store{db: db} }

// actorOr returns a or "system" (local copy; original in incidents_pg.go).
func actorOr(a string) string {
	if strings.TrimSpace(a) == "" {
		return "system"
	}
	return a
}

// randHex returns nBytes of crypto randomness, hex-encoded (local copy;
// original in refresh.go).
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}

const selectSeamCols = `
SELECT seam_id, tenant_id, seam_type, state, display_name, endpoints,
       control_plane_owner, visibility, probe_strategy, suggested_by,
       evidence, confidence, suggestion_key, created_at, updated_at, updated_by`

func scanSeam(row pgx.Row) (Seam, bool, error) {
	var s Seam
	var endpoints, probes, evidence []byte
	err := row.Scan(&s.SeamID, &s.TenantID, &s.SeamType, &s.State, &s.DisplayName,
		&endpoints, &s.ControlPlaneOwner, &s.Visibility, &probes, &s.SuggestedBy,
		&evidence, &s.Confidence, &s.SuggestionKey, &s.CreatedAt, &s.UpdatedAt, &s.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Seam{}, false, nil
	}
	if err != nil {
		return Seam{}, false, err
	}
	// JSONB columns are NOT NULL with object/array defaults; a decode failure
	// here means the row was corrupted outside the API — surface it.
	if err := json.Unmarshal(endpoints, &s.Endpoints); err != nil {
		return Seam{}, false, fmt.Errorf("seam %s endpoints: %w", s.SeamID, err)
	}
	if err := json.Unmarshal(probes, &s.ProbeStrategy); err != nil {
		return Seam{}, false, fmt.Errorf("seam %s probe_strategy: %w", s.SeamID, err)
	}
	if err := json.Unmarshal(evidence, &s.Evidence); err != nil {
		return Seam{}, false, fmt.Errorf("seam %s evidence: %w", s.SeamID, err)
	}
	return s, true, nil
}

// List returns seams visible to the principal, newest first, optionally
// filtered by state and/or type. RLS scopes rows; filters are belt-and-braces.
func (st *Store) List(ctx context.Context, tenant string, cross bool, state, seamType string) ([]Seam, error) {
	out := make([]Seam, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		sql := selectSeamCols + ` FROM seams WHERE ($1 = '' OR state = $1) AND ($2 = '' OR seam_type = $2)
		       ORDER BY updated_at DESC LIMIT 2000`
		rows, err := tx.Query(ctx, sql, state, seamType)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, ok, err := scanSeam(rows)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, s)
			}
		}
		return rows.Err()
	})
	return out, err
}

func (st *Store) Get(ctx context.Context, tenant string, cross bool, id string) (Seam, bool, error) {
	var s Seam
	var found bool
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectSeamCols+` FROM seams WHERE seam_id = $1`, id)
		r, ok, err := scanSeam(row)
		if err != nil {
			return err
		}
		s, found = r, ok
		return nil
	})
	return s, found, err
}

// Create inserts an owner-authored seam (state defaults to active — a manually
// defined seam IS the inventory; there is nobody upstream to confirm it).
func (st *Store) Create(ctx context.Context, tenant string, cross bool, s Seam) (Seam, error) {
	if err := NormalizeForWrite(&s); err != nil {
		return Seam{}, err
	}
	if s.SeamID == "" {
		s.SeamID = "sm-" + randHex(6)
	}
	if s.State == "" {
		s.State = "active"
	}
	if s.SuggestedBy == "" {
		s.SuggestedBy = "manual"
	}
	endpoints, probes, evidence, err := seamJSONCols(s)
	if err != nil {
		return Seam{}, err
	}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO seams (seam_id, tenant_id, seam_type, state, display_name, endpoints,
                   control_plane_owner, visibility, probe_strategy, suggested_by,
                   evidence, confidence, suggestion_key, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			s.SeamID, s.TenantID, s.SeamType, s.State, s.DisplayName, endpoints,
			s.ControlPlaneOwner, s.Visibility, probes, s.SuggestedBy,
			evidence, s.Confidence, s.SuggestionKey, s.UpdatedBy)
		return err
	})
	if err != nil {
		return Seam{}, err
	}
	created, _, err := st.Get(ctx, tenant, cross, s.SeamID)
	return created, err
}

// Suggest upserts a bootstrap suggestion at platform scope, stamping the row's
// tenant. ON CONFLICT DO NOTHING against the suggestion_key index is both the
// idempotency and the rejection memory: once a key exists — in ANY state,
// including rejected — it is never raised again. Returns whether a new row
// was inserted.
func (st *Store) Suggest(ctx context.Context, s Seam) (bool, error) {
	if s.SuggestionKey == "" {
		return false, errors.New("suggestion requires a suggestion_key")
	}
	if err := NormalizeForWrite(&s); err != nil {
		return false, err
	}
	s.SeamID = IDForKey(s.TenantID, s.SuggestionKey)
	s.State = "suggested"
	endpoints, probes, evidence, err := seamJSONCols(s)
	if err != nil {
		return false, err
	}
	var inserted bool
	err = st.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO seams (seam_id, tenant_id, seam_type, state, display_name, endpoints,
                   control_plane_owner, visibility, probe_strategy, suggested_by,
                   evidence, confidence, suggestion_key, updated_by)
VALUES ($1,$2,$3,'suggested',$4,$5,$6,$7,$8,$9,$10,$11,$12,'seam-bootstrap')
ON CONFLICT (tenant_id, suggestion_key) WHERE suggestion_key <> '' DO NOTHING`,
			s.SeamID, s.TenantID, s.SeamType, s.DisplayName, endpoints,
			s.ControlPlaneOwner, s.Visibility, probes, s.SuggestedBy,
			evidence, s.Confidence, s.SuggestionKey)
		if err != nil {
			return err
		}
		inserted = tag.RowsAffected() > 0
		return nil
	})
	return inserted, err
}

// SeamPatch is the owner-editable subset plus the lifecycle transition. nil
// pointer = field untouched.
type SeamPatch struct {
	State             *string            `json:"state"`
	SeamType          *string            `json:"seam_type"`
	DisplayName       *string            `json:"display_name"`
	Endpoints         *map[string]string `json:"endpoints"`
	ControlPlaneOwner *string            `json:"control_plane_owner"`
	Visibility        *string            `json:"visibility"`
	ProbeStrategy     *[]string          `json:"probe_strategy"`
}

// Update applies a patch under the lifecycle state machine. The read and write
// share one transaction so concurrent transitions serialize on the row.
func (st *Store) Update(ctx context.Context, tenant string, cross bool, id, actor string, p SeamPatch) (Seam, error) {
	var out Seam
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectSeamCols+` FROM seams WHERE seam_id = $1 FOR UPDATE`, id)
		s, ok, err := scanSeam(row)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		if p.State != nil {
			if !ValidEnum(*p.State, SeamStates) {
				return fmt.Errorf("invalid state %q", *p.State)
			}
			if !TransitionAllowed(s.State, *p.State) {
				return fmt.Errorf("illegal transition %s → %s", s.State, *p.State)
			}
			s.State = *p.State
		}
		if p.SeamType != nil {
			s.SeamType = *p.SeamType
		}
		if p.DisplayName != nil {
			s.DisplayName = *p.DisplayName
		}
		if p.Endpoints != nil {
			s.Endpoints = *p.Endpoints
		}
		if p.ControlPlaneOwner != nil {
			s.ControlPlaneOwner = *p.ControlPlaneOwner
		}
		if p.Visibility != nil {
			s.Visibility = *p.Visibility
		}
		if p.ProbeStrategy != nil {
			s.ProbeStrategy = *p.ProbeStrategy
		}
		if err := NormalizeForWrite(&s); err != nil {
			return err
		}
		endpoints, probes, evidence, err := seamJSONCols(s)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
UPDATE seams SET seam_type=$2, state=$3, display_name=$4, endpoints=$5,
       control_plane_owner=$6, visibility=$7, probe_strategy=$8, evidence=$9,
       updated_at=now(), updated_by=$10
 WHERE seam_id=$1`,
			id, s.SeamType, s.State, s.DisplayName, endpoints,
			s.ControlPlaneOwner, s.Visibility, probes, evidence, actorOr(actor))
		out = s
		out.UpdatedBy = actorOr(actor)
		return err
	})
	return out, err
}

// NormalizeForWrite validates enums and fills honest per-type defaults for
// anything the caller left empty. All external input passes through here.
func NormalizeForWrite(s *Seam) error {
	s.SeamType = strings.ToUpper(strings.TrimSpace(s.SeamType))
	if !ValidEnum(s.SeamType, SeamTypes) {
		return fmt.Errorf("invalid seam_type %q (want one of %s)", s.SeamType, strings.Join(SeamTypes, "|"))
	}
	if s.State != "" && !ValidEnum(s.State, SeamStates) {
		return fmt.Errorf("invalid state %q", s.State)
	}
	if s.ControlPlaneOwner == "" {
		s.ControlPlaneOwner = "enterprise"
	}
	if !ValidEnum(s.ControlPlaneOwner, SeamOwners) {
		return fmt.Errorf("invalid control_plane_owner %q", s.ControlPlaneOwner)
	}
	if s.Visibility == "" {
		s.Visibility = seamVisibilityDefault[s.SeamType]
	}
	if !ValidEnum(s.Visibility, SeamVisibilities) {
		return fmt.Errorf("invalid visibility %q", s.Visibility)
	}
	if len(s.ProbeStrategy) == 0 {
		s.ProbeStrategy = seamProbeDefault[s.SeamType]
	}
	if s.Confidence < 0 || s.Confidence > 1 {
		return fmt.Errorf("confidence %v out of [0,1]", s.Confidence)
	}
	if s.Endpoints == nil {
		s.Endpoints = map[string]string{}
	}
	if s.Evidence == nil {
		s.Evidence = map[string]any{}
	}
	if len(s.DisplayName) > 200 {
		s.DisplayName = s.DisplayName[:200]
	}
	return nil
}

func seamJSONCols(s Seam) (endpoints, probes, evidence []byte, err error) {
	if endpoints, err = json.Marshal(s.Endpoints); err != nil {
		return nil, nil, nil, err
	}
	if probes, err = json.Marshal(s.ProbeStrategy); err != nil {
		return nil, nil, nil, err
	}
	if evidence, err = json.Marshal(s.Evidence); err != nil {
		return nil, nil, nil, err
	}
	// Evidence is bounded: suggestions embed telemetry excerpts, and an
	// unbounded blob would bloat the lifecycle table (queues bounded, §9).
	if len(evidence) > 8192 {
		return nil, nil, nil, errors.New("evidence too large (8 KiB cap)")
	}
	return endpoints, probes, evidence, nil
}

// ── groups ────────────────────────────────────────────────────────────────────

const selectGroupCols = `
SELECT group_id, tenant_id, seam_type, redundancy_model, state, display_name,
       members, suggested_by, evidence, confidence, suggestion_key,
       created_at, updated_at, updated_by`

func scanSeamGroup(row pgx.Row) (SeamGroup, bool, error) {
	var g SeamGroup
	var members, evidence []byte
	err := row.Scan(&g.GroupID, &g.TenantID, &g.SeamType, &g.RedundancyModel, &g.State,
		&g.DisplayName, &members, &g.SuggestedBy, &evidence, &g.Confidence,
		&g.SuggestionKey, &g.CreatedAt, &g.UpdatedAt, &g.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return SeamGroup{}, false, nil
	}
	if err != nil {
		return SeamGroup{}, false, err
	}
	if err := json.Unmarshal(members, &g.Members); err != nil {
		return SeamGroup{}, false, fmt.Errorf("seam group %s members: %w", g.GroupID, err)
	}
	if err := json.Unmarshal(evidence, &g.Evidence); err != nil {
		return SeamGroup{}, false, fmt.Errorf("seam group %s evidence: %w", g.GroupID, err)
	}
	return g, true, nil
}

func (st *Store) ListGroups(ctx context.Context, tenant string, cross bool, state string) ([]SeamGroup, error) {
	out := make([]SeamGroup, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectGroupCols+` FROM seam_groups
		       WHERE ($1 = '' OR state = $1) ORDER BY updated_at DESC LIMIT 500`, state)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, ok, err := scanSeamGroup(rows)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, g)
			}
		}
		return rows.Err()
	})
	return out, err
}

func normalizeGroupForWrite(g *SeamGroup) error {
	g.SeamType = strings.ToUpper(strings.TrimSpace(g.SeamType))
	if !ValidEnum(g.SeamType, SeamTypes) {
		return fmt.Errorf("invalid seam_type %q", g.SeamType)
	}
	if g.RedundancyModel == "" {
		g.RedundancyModel = "single"
	}
	if !ValidEnum(g.RedundancyModel, SeamRedundancyModels) {
		return fmt.Errorf("invalid redundancy_model %q", g.RedundancyModel)
	}
	if g.State != "" && !ValidEnum(g.State, SeamStates) {
		return fmt.Errorf("invalid state %q", g.State)
	}
	if g.Confidence < 0 || g.Confidence > 1 {
		return fmt.Errorf("confidence %v out of [0,1]", g.Confidence)
	}
	if g.Members == nil {
		g.Members = []SeamMember{}
	}
	if g.Evidence == nil {
		g.Evidence = map[string]any{}
	}
	if len(g.DisplayName) > 200 {
		g.DisplayName = g.DisplayName[:200]
	}
	return nil
}

// SuggestGroup mirrors Suggest for redundancy groups (same idempotency +
// rejection-memory mechanism).
func (st *Store) SuggestGroup(ctx context.Context, g SeamGroup) (bool, error) {
	if g.SuggestionKey == "" {
		return false, errors.New("group suggestion requires a suggestion_key")
	}
	if err := normalizeGroupForWrite(&g); err != nil {
		return false, err
	}
	g.GroupID = GroupIDForKey(g.TenantID, g.SuggestionKey)
	members, err := json.Marshal(g.Members)
	if err != nil {
		return false, err
	}
	evidence, err := json.Marshal(g.Evidence)
	if err != nil {
		return false, err
	}
	if len(evidence) > 8192 {
		return false, errors.New("evidence too large (8 KiB cap)")
	}
	var inserted bool
	err = st.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO seam_groups (group_id, tenant_id, seam_type, redundancy_model, state,
                         display_name, members, suggested_by, evidence, confidence,
                         suggestion_key, updated_by)
VALUES ($1,$2,$3,$4,'suggested',$5,$6,$7,$8,$9,$10,'seam-bootstrap')
ON CONFLICT (tenant_id, suggestion_key) WHERE suggestion_key <> '' DO NOTHING`,
			g.GroupID, g.TenantID, g.SeamType, g.RedundancyModel, g.DisplayName,
			members, g.SuggestedBy, evidence, g.Confidence, g.SuggestionKey)
		if err != nil {
			return err
		}
		inserted = tag.RowsAffected() > 0
		return nil
	})
	return inserted, err
}

// GroupPatch mirrors SeamPatch for groups.
type GroupPatch struct {
	State           *string       `json:"state"`
	SeamType        *string       `json:"seam_type"`
	RedundancyModel *string       `json:"redundancy_model"`
	DisplayName     *string       `json:"display_name"`
	Members         *[]SeamMember `json:"members"`
}

func (st *Store) UpdateGroup(ctx context.Context, tenant string, cross bool, id, actor string, p GroupPatch) (SeamGroup, error) {
	var out SeamGroup
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectGroupCols+` FROM seam_groups WHERE group_id = $1 FOR UPDATE`, id)
		g, ok, err := scanSeamGroup(row)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		if p.State != nil {
			if !ValidEnum(*p.State, SeamStates) {
				return fmt.Errorf("invalid state %q", *p.State)
			}
			if !TransitionAllowed(g.State, *p.State) {
				return fmt.Errorf("illegal transition %s → %s", g.State, *p.State)
			}
			g.State = *p.State
		}
		if p.SeamType != nil {
			g.SeamType = *p.SeamType
		}
		if p.RedundancyModel != nil {
			g.RedundancyModel = *p.RedundancyModel
		}
		if p.DisplayName != nil {
			g.DisplayName = *p.DisplayName
		}
		if p.Members != nil {
			g.Members = *p.Members
		}
		if err := normalizeGroupForWrite(&g); err != nil {
			return err
		}
		members, err := json.Marshal(g.Members)
		if err != nil {
			return err
		}
		evidence, err := json.Marshal(g.Evidence)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
UPDATE seam_groups SET seam_type=$2, redundancy_model=$3, state=$4, display_name=$5,
       members=$6, evidence=$7, updated_at=now(), updated_by=$8
 WHERE group_id=$1`,
			id, g.SeamType, g.RedundancyModel, g.State, g.DisplayName,
			members, evidence, actorOr(actor))
		out = g
		out.UpdatedBy = actorOr(actor)
		return err
	})
	return out, err
}
