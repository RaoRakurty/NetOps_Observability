// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_ingest_service.go — Wave 1 #2 (per-tenant ingestion): the poller-facing
// service surface over the ALREADY-SHIPPED connector store + identity broker.
//
// The cloud-ingest poller stops being a one-ambient-credential lab sidecar and
// becomes a per-connector collector:
//
//	GET  /api/cloud/ingest/connectors                  → which connectors to poll
//	POST /api/cloud/ingest/connectors/{id}/credentials → short-lived provider creds
//	PUT  /api/cloud/ingest/connectors/{id}/inventory   → discovered inventory
//
// Zero-trust posture (§3): the poller authenticates like every other
// non-interactive client in this repo — a scoped API key (apikeys.go) — with a
// DEDICATED scope (`ingest:cloud`) that must live in the platform/global realm.
// This surface is platform-GLOBAL plumbing (§3a.3): it enumerates every
// tenant's enabled connectors, so a tenant-bound credential must NEVER pass,
// no matter what scopes it carries.
//
// Tenant stamping is server-side and non-negotiable (§3a.2): the tenant on the
// credentials response and on every ingested inventory row is derived from the
// CONNECTOR ROW, never from anything the poller sends. A poller can only ever
// write data under the tenant that owns the connector it is writing through.
//
// Secrets: the credentials response necessarily carries short-lived provider
// credentials (that is its purpose); it is served with Cache-Control: no-store,
// is never logged, and every mint is audited by the broker (TOKEN_ISSUED).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/cloudconn"
)

// cloudIngestScope is the dedicated API-key scope for the ingest service. The
// key must ALSO be bound to the platform/global realm — the scope alone is not
// enough (a tenant admin can mint keys for its own tenant, and such a key must
// never enumerate other tenants' connectors).
const cloudIngestScope = "ingest:cloud"

// Reliability bounds (§9): every request body is capped, every broker call has
// a deadline, and one inventory snapshot can never exceed the store's own cap.
const (
	ingestCredBodyMax = 64 << 10 // credentials request body cap
	ingestInvBodyMax  = 32 << 20 // inventory snapshot body cap (32 MiB)
	ingestInvResMax   = 20000    // resources per connector snapshot
	ingestCredTimeout = 20 * time.Second
)

var errIngestForbidden = errors.New("cloud ingest requires a platform-realm service credential with the ingest:cloud scope")

// isPlatformRealm reports whether a token tenant denotes the platform/global
// realm (the only realm the ingest service credential may live in).
func isPlatformRealm(tenant string) bool {
	t := strings.ToLower(strings.TrimSpace(tenant))
	return t == "" || t == TenantGlobal
}

// requireCloudIngestService gates the poller-facing surface: an API-key
// principal carrying the ingest:cloud scope AND bound to the platform realm,
// or the human platform owner (debugging). Everything else fails closed —
// including a tenant-bound key that happens to carry the scope, and any
// principal whose effective tenant was narrowed via as_tenant.
func (s *server) requireCloudIngestService(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return jwtClaims{}, false
	}
	if isPlatformOwner(claims) {
		return claims, true
	}
	if claims.HasScope(cloudIngestScope) && isPlatformRealm(claims.Tenant) {
		return claims, true
	}
	writeError(w, http.StatusForbidden, errIngestForbidden)
	return jwtClaims{}, false
}

// ── connector list: GET /api/cloud/ingest/connectors ─────────────────────────

// ingestConnectorView is what the poller needs to plan a cycle — identity
// TRUST METADATA IS DELIBERATELY ABSENT (no role ARN, no external id, no client
// id): the poller never authenticates to a provider itself, it only asks the
// broker for a finished credential.
type ingestConnectorView struct {
	ID             string             `json:"id"`
	Tenant         string             `json:"tenant"` // derived from the connector row
	Provider       cloudconn.Provider `json:"provider"`
	DisplayName    string             `json:"display_name"`
	CapabilityPack string             `json:"capability_pack"`
	Scopes         []cloudconn.Scope  `json:"scopes"` // provider accounts/regions to poll
	// Org marks an ENUMERABLE org-level connector (Wave 5 #17 slice 2): the
	// poller may re-run member enumeration through the connector's
	// discover-scopes surface, but it POLLS ONLY the operator-approved Scopes —
	// enumeration never silently widens collection. Member scopes inherit the
	// connector row's tenant (§3a; the stamping source stays this row).
	Org *cloudconn.OrgScopeAnchor `json:"org,omitempty"`
}

func (s *server) handleCloudIngestConnectors(w http.ResponseWriter, r *http.Request) {
	if !s.cloudStoreReady(w) {
		return
	}
	if s.cloudConn == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if _, ok := s.requireCloudIngestService(w, r); !ok {
		return
	}
	// Platform-service read: deliberately cross-tenant (this surface EXISTS to
	// fan one poller out across every tenant's enabled connectors). Gated above.
	list, err := s.cloudConn.List(r.Context(), "", true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]ingestConnectorView, 0, len(list))
	for _, c := range list {
		if !c.State.Collecting() {
			continue // only ACTIVE connectors are pollable
		}
		scopes := c.Scopes
		if scopes == nil {
			scopes = []cloudconn.Scope{}
		}
		views = append(views, ingestConnectorView{
			ID: c.ConnectorID, Tenant: c.TenantID, Provider: c.Provider,
			DisplayName: c.DisplayName, CapabilityPack: c.PackFullID, Scopes: scopes,
			Org: c.Identity.Org,
		})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Tenant != views[j].Tenant {
			return views[i].Tenant < views[j].Tenant
		}
		return views[i].ID < views[j].ID
	})
	writeJSON(w, http.StatusOK, map[string]any{"connectors": views})
}

// ── by-id subtree: /api/cloud/ingest/connectors/{id}/{action} ─────────────────

func (s *server) handleCloudIngestConnectorByID(w http.ResponseWriter, r *http.Request) {
	if !s.cloudStoreReady(w) {
		return
	}
	if s.cloudConn == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	if _, ok := s.requireCloudIngestService(w, r); !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/cloud/ingest/connectors/")
	id, action, _ := strings.Cut(rest, "/")
	if !strings.HasPrefix(id, cloudconn.ConnectorIDPrefix) {
		writeError(w, http.StatusBadRequest, errors.New("invalid connector id"))
		return
	}
	// The service is platform-scoped, so the row is loaded cross-tenant BY ID
	// and the owning tenant is taken from the row — the single source of truth
	// for everything stamped downstream.
	c, found, err := s.cloudConn.Get(r.Context(), "", true, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, errCCNNotFound)
		return
	}
	switch action {
	case "credentials":
		s.serveIngestCredentials(w, r, c)
	case "inventory":
		s.serveIngestInventory(w, r, c)
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown ingest action"))
	}
}

// ── credentials: POST /api/cloud/ingest/connectors/{id}/credentials ──────────

type ingestCredentialsReq struct {
	Account string `json:"account"` // optional narrowing; defaults from scopes
	Region  string `json:"region"`
}

// ingestCredentialsResp carries ONE short-lived provider credential. AWS needs
// the STS triplet; Azure/GCP are single bearer tokens. Tenant is derived from
// the connector row server-side — the poller stamps its emissions with it.
type ingestCredentialsResp struct {
	ConnectorID        string    `json:"connector_id"`
	Tenant             string    `json:"tenant"`
	Provider           string    `json:"provider"`
	Expiry             time.Time `json:"expiry"`
	TokenType          string    `json:"token_type,omitempty"`
	Token              string    `json:"token,omitempty"` // azure/gcp bearer token
	AWSAccessKeyID     string    `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string    `json:"aws_secret_access_key,omitempty"`
	AWSSessionToken    string    `json:"aws_session_token,omitempty"`
}

func (s *server) serveIngestCredentials(w http.ResponseWriter, r *http.Request, c cloudconn.Connector) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	if s.cloudBroker == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	var req ingestCredentialsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ingestCredBodyMax)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	account, region := cloudconn.DefaultScope(c)
	if a := strings.TrimSpace(req.Account); a != "" {
		account = a
	}
	if rg := strings.TrimSpace(req.Region); rg != "" {
		region = rg
	}

	ctx, cancel := context.WithTimeout(r.Context(), ingestCredTimeout)
	defer cancel()
	tok, err := s.cloudBroker.TokenFor(ctx, cloudconn.ScopedTokenRequest{
		Tenant:          c.TenantID, // from the row — NEVER from the request
		ConnectorID:     c.ConnectorID,
		ProviderAccount: account,
		Region:          region,
		CapabilitySetID: c.PackFullID,
	})
	if err != nil {
		switch {
		case errors.Is(err, cloudconn.ErrBrokerNotFound):
			writeError(w, http.StatusNotFound, errCCNNotFound)
		case errors.Is(err, cloudconn.ErrBrokerNotActive):
			writeJSONError(w, http.StatusConflict, "connector cannot exchange tokens in its current state", "NOT_ACTIVE")
		case errors.Is(err, cloudconn.ErrPlatformCredentialsMissing),
			errors.Is(err, cloudconn.ErrWorkloadAssertionMissing),
			errors.Is(err, cloudconn.ErrProviderExchangeDeferred):
			// Deployment-side deferral, not a provider denial. Sanitized by contract.
			writeJSONError(w, http.StatusServiceUnavailable, err.Error(), "EXCHANGE_DEFERRED")
		default:
			// ExchangeError is sanitized by contract — safe to surface, never a secret.
			writeJSONError(w, http.StatusBadGateway, err.Error(), "EXCHANGE_FAILED")
		}
		return
	}

	resp := ingestCredentialsResp{
		ConnectorID: c.ConnectorID,
		Tenant:      c.TenantID,
		Provider:    string(c.Provider),
		Expiry:      tok.Expiry,
		TokenType:   tok.TokenType,
	}
	if tok.AWS != nil {
		resp.AWSAccessKeyID = tok.AWS.AccessKeyID
		resp.AWSSecretAccessKey = tok.AWS.SecretAccessKey
		resp.AWSSessionToken = tok.AWS.SessionToken
	} else {
		resp.Token = tok.Value
	}
	// Short-lived secret material: never cached, never logged.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// ── inventory: PUT /api/cloud/ingest/connectors/{id}/inventory ───────────────

// ingestInventoryDoc is the wire shape of one connector inventory snapshot —
// the SAME provider+account header over a resource list the fixture files use
// (the poller already produces it), so both paths exercise identical parsing.
// Any tenant_id inside the payload is IGNORED: the owner is the connector row.
type ingestInventoryDoc struct {
	Provider   string                `json:"provider"`
	AccountID  string                `json:"account_id"`
	Collection *cloud.Collection     `json:"collection"`
	Resources  []cloud.CloudResource `json:"resources"`
}

func (s *server) serveIngestInventory(w http.ResponseWriter, r *http.Request, c cloudconn.Connector) {
	if !s.cloudStoreReady(w) {
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("PUT or POST"))
		return
	}
	if s.cloud == nil || s.cloudIngestInv == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	var doc ingestInventoryDoc
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ingestInvBodyMax)).Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Zero-trust on the payload: the snapshot must be FOR this connector's
	// provider — a poller bug must not write azure rows through an aws connector.
	if !strings.EqualFold(strings.TrimSpace(doc.Provider), string(c.Provider)) {
		writeJSONError(w, http.StatusBadRequest, "snapshot provider does not match the connector", "PROVIDER_MISMATCH")
		return
	}
	if len(doc.Resources) > ingestInvResMax {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "snapshot exceeds the per-connector resource cap", "TOO_MANY_RESOURCES")
		return
	}

	// Normalize + STAMP: tenant from the connector row (never the payload),
	// provider/account defaults from the header, then the same attribution the
	// fixture loader applies — both paths land identically shaped rows.
	now := time.Now().UTC()
	res, maps := cloud.NormalizeIngestedResources(doc.Resources, c.TenantID, cloud.Provider(c.Provider), doc.AccountID, now)

	// Fold this connector's snapshot into its tenant's merged inventory (a
	// tenant can hold several connectors — one PUT must never clobber siblings).
	mergedRes, mergedMaps := s.cloudIngestInv.Put(c.TenantID, c.ConnectorID, res, maps)
	if err := s.cloud.ReplaceInventory(r.Context(), c.TenantID, mergedRes, mergedMaps); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Telemetry health: inventory landing is MEASURED proof of data flow for
	// this connector (identity health stays separate). Best-effort persist.
	c.TelemetryHealth = cloudconn.HealthStatus{State: "healthy", Detail: "inventory snapshot received", Checked: now}
	if _, _, err := s.cloudConn.Update(r.Context(), c, 0); err != nil {
		logError("cloud", "ingest telemetry-health update failed", map[string]any{
			"connector": c.ConnectorID, "err": err.Error(),
		})
	}

	logInfo("cloud", "connector inventory ingested", map[string]any{
		"connector": c.ConnectorID, "tenant": c.TenantID,
		"provider": string(c.Provider), "resources": len(res),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"connector_id": c.ConnectorID,
		"tenant":       c.TenantID,
		"resources":    len(res),
	})
}

// The snapshot registry + tenant-stamping normalizer live in
// cloud/ingest_inventory.go; the default-scope derivation in cloudconn
// (P2 RA.16).

type cloudIngestInventory = cloud.IngestInventory

func newCloudIngestInventory() *cloudIngestInventory { return cloud.NewIngestInventory() }
