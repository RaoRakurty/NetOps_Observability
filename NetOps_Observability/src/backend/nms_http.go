// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/nms"
)

// nms_http.go — HTTP surface of the NMS vendor-controller framework (#95 P3b):
//
//   GET  /api/nms/connectors                 — connector catalog (specs, no secrets)
//   GET  /api/nms/integrations               — tenant's integrations
//   POST /api/nms/integrations               — create (tenant stamped from token)
//   GET  /api/nms/integrations/{id}          — one integration (+ cred fields set)
//   PUT  /api/nms/integrations/{id}          — update config and/or credentials (write-only)
//   DELETE /api/nms/integrations/{id}        — delete (cascades checkpoints/health/state)
//   POST /api/nms/integrations/{id}/test     — live auth check against the controller
//   GET  /api/nms/integrations/{id}/health   — health snapshot + recent runs
//   POST /api/nms/webhook/{token}            — inbound controller webhook (JWT-exempt;
//        authenticated by opaque token + the connector's signature verification)
//
// Tenancy (§3a): every read/write derives (tenant, cross) from the principal;
// a cross-tenant id returns 404. Credentials are write-only: responses carry
// only the SET FIELD NAMES, never values. All routes 404 when the feature is
// dormant (srv.nms == nil) so the surface doesn't exist unless enabled.

type nmsIntegrationInput struct {
	Vendor        string   `json:"vendor"`
	DisplayName   string   `json:"displayName"`
	Enabled       *bool    `json:"enabled,omitempty"`
	BaseURL       string   `json:"baseUrl"`
	AuthType      string   `json:"authType,omitempty"`
	PollIntervalS int      `json:"pollIntervalS,omitempty"`
	Streams       []string `json:"streams,omitempty"`
	TLSSkipVerify *bool    `json:"tlsSkipVerify,omitempty"`
	// Credentials is write-only: fields are Vault-encrypted under the owning
	// tenant's DEK and never returned.
	Credentials map[string]string `json:"credentials,omitempty"`
}

// nmsIntegrationPublic is the API projection — config + cred field names, never values.
func (s *server) nmsIntegrationPublic(ctx context.Context, c nms.Integration) map[string]any {
	out := map[string]any{
		"id":            c.ID,
		"vendor":        c.Vendor,
		"displayName":   c.DisplayName,
		"enabled":       c.Enabled,
		"baseUrl":       c.BaseURL,
		"authType":      c.AuthType,
		"pollIntervalS": c.PollIntervalS,
		"streams":       c.Streams,
		"tlsSkipVerify": c.TLSSkipVerify,
		"createdAt":     c.CreatedAt,
		"updatedAt":     c.UpdatedAt,
	}
	if spec, ok := s.nms.Registry().Get(c.Vendor); ok {
		out["product"] = spec.Spec().Product
	}
	if c.WebhookToken != "" {
		out["webhookUrl"] = "/api/nms/webhook/" + c.WebhookToken
	}
	if _, names, err := s.nms.Store().Credentials(ctx, c.Tenant, c.ID); err == nil {
		out["credentialFieldsSet"] = names
	}
	return out
}

// handleNMSConnectors lists the connector catalog (static specs).
func (s *server) handleNMSConnectors(w http.ResponseWriter, r *http.Request) {
	if s.nms == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	vendors := s.nms.Registry().Vendors()
	sort.Strings(vendors)
	out := make([]map[string]any, 0, len(vendors))
	for _, v := range vendors {
		conn, ok := s.nms.Registry().Get(v)
		if !ok {
			continue
		}
		spec := conn.Spec()
		out = append(out, map[string]any{
			"vendor":        spec.Vendor,
			"product":       spec.Product,
			"supportedAuth": spec.SupportedAuth,
			"preferredAuth": spec.PreferredAuth,
			"webhook":       spec.Webhook,
			"poll":          spec.Poll,
			"streams":       spec.Streams,
			"defaultPollS":  int(spec.DefaultPoll / time.Second),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectors": out})
}

// handleNMSIntegrations serves the collection: GET list, POST create.
func (s *server) handleNMSIntegrations(w http.ResponseWriter, r *http.Request) {
	if s.nms == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		list, err := s.nms.Store().List(r.Context(), tenant, cross)
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, c := range list {
			out = append(out, s.nmsIntegrationPublic(r.Context(), c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"integrations": out})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		if tenant == TenantGlobal {
			http.Error(w, "select a tenant to own the integration", http.StatusBadRequest)
			return
		}
		body, err := readBounded(w, r, 256<<10)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var in nmsIntegrationInput
		if err := json.Unmarshal(body, &in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		conn, ok := s.nms.Registry().Get(in.Vendor)
		if !ok {
			http.Error(w, "unknown vendor", http.StatusBadRequest)
			return
		}
		c := nms.Integration{
			Tenant:      tenant, // stamped from the principal, NEVER the payload (§3a)
			ID:          "nmsi-" + randHex(8),
			Vendor:      in.Vendor,
			Product:     conn.Spec().Product,
			DisplayName: in.DisplayName,
			BaseURL:     in.BaseURL,
			AuthType:    in.AuthType,
		}
		applyNMSInput(&c, in, conn.Spec())
		// LICENCE-BEGIN (tracker 256) — an integration that polls wireless
		// inventory brings controllers and access points into the monitored
		// fleet, one entitlement each. A new integration starts from "off", so
		// creating it already enabled IS the activation transition and takes
		// the same ceiling question the switch below takes.
		if c.Enabled {
			if err := s.nmsWirelessActivationCeiling(conn.Spec()); err != nil {
				if !entitlement.WriteRefusal(w, err) {
					writeError(w, http.StatusInternalServerError, errors.New("integration was not saved"))
				}
				return
			}
		}
		// LICENCE-END
		if conn.Spec().Webhook {
			c.WebhookToken = randHex(24)
		}
		// F-76: refuse BEFORE writing the integration row, so a refused
		// credential cannot leave a half-created, unusable integration behind.
		if len(in.Credentials) > 0 && !nms.StoreDurable(s.nms.Store()) {
			writeError(w, http.StatusNotImplemented, nms.ErrStorageNotDurable)
			return
		}
		if err := s.nms.Store().Upsert(r.Context(), c); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		if len(in.Credentials) > 0 {
			if err := s.nms.Store().SetCredentials(r.Context(), tenant, c.ID, in.Credentials); err != nil {
				if errors.Is(err, nms.ErrStorageNotDurable) {
					writeError(w, http.StatusNotImplemented, err)
					return
				}
				http.Error(w, "credential save failed", http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, http.StatusCreated, s.nmsIntegrationPublic(r.Context(), c))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyNMSInput folds updatable fields into c, defaulting from the spec.
func applyNMSInput(c *nms.Integration, in nmsIntegrationInput, spec nms.ConnectorSpec) {
	if in.DisplayName != "" {
		c.DisplayName = in.DisplayName
	}
	if in.BaseURL != "" {
		c.BaseURL = in.BaseURL
	}
	if in.AuthType != "" {
		c.AuthType = in.AuthType
	}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	if in.TLSSkipVerify != nil {
		c.TLSSkipVerify = *in.TLSSkipVerify
	}
	if in.PollIntervalS > 0 {
		c.PollIntervalS = in.PollIntervalS
	}
	if c.PollIntervalS <= 0 {
		c.PollIntervalS = int(spec.DefaultPoll / time.Second)
	}
	if in.Streams != nil {
		c.Streams = in.Streams
	}
}

// handleNMSIntegrationItem serves /api/nms/integrations/{id}[/test|/health].
func (s *server) handleNMSIntegrationItem(w http.ResponseWriter, r *http.Request) {
	if s.nms == nil {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/nms/integrations/")
	id, action, _ := strings.Cut(rest, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "":
		s.nmsIntegrationCRUD(w, r, id)
	case "test":
		s.nmsIntegrationTest(w, r, id)
	case "health":
		s.nmsIntegrationHealth(w, r, id)
	case "poll":
		s.nmsIntegrationPollNow(w, r, id)
	case "states":
		s.nmsIntegrationStates(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// nmsIntegrationPollNow runs one poll cycle synchronously — the operator's
// "Poll now" button. Works even on a disabled integration (explicit action),
// so a setup can be exercised before it is enabled for the scheduler.
func (s *server) nmsIntegrationPollNow(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	c, found, err := s.nms.Store().Get(r.Context(), tenant, cross, id)
	if err != nil || !found {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	rec := s.nms.PollIntegration(ctx, c)
	out := map[string]any{
		"status":     rec.Status,
		"events":     rec.Events,
		"durationMs": rec.Finished.Sub(rec.Started).Milliseconds(),
	}
	if rec.Error != "" {
		out["error"] = rec.Error
	}
	writeJSON(w, http.StatusOK, out)
}

// nmsIntegrationStates returns the tracked controller-state rows (§3.2 view).
func (s *server) nmsIntegrationStates(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	// Existence check first so a cross-tenant id 404s (never an empty 200).
	if _, found, err := s.nms.Store().Get(r.Context(), tenant, cross, id); err != nil || !found {
		http.NotFound(w, r)
		return
	}
	states, err := s.nms.Store().States(r.Context(), tenant, cross, id)
	if err != nil {
		http.Error(w, "states read failed", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(states))
	for _, st := range states {
		out = append(out, map[string]any{
			"entityKey":     st.EntityKey,
			"stateKind":     st.StateKind,
			"currentState":  st.CurrentState,
			"previousState": st.PreviousState,
			"firstSeen":     st.FirstSeen,
			"lastSeen":      st.LastSeen,
			"flapCount":     st.FlapCount,
			"deviceId":      st.DeviceID,
			"siteId":        st.SiteID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"states": out})
}

func (s *server) nmsIntegrationCRUD(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		c, found, err := s.nms.Store().Get(r.Context(), tenant, cross, id)
		if err != nil || !found {
			http.NotFound(w, r) // cross-tenant id is indistinguishable from absent (§3a)
			return
		}
		writeJSON(w, http.StatusOK, s.nmsIntegrationPublic(r.Context(), c))
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		c, found, err := s.nms.Store().Get(r.Context(), tenant, cross, id)
		if err != nil || !found {
			http.NotFound(w, r)
			return
		}
		body, err := readBounded(w, r, 256<<10)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var in nmsIntegrationInput
		if err := json.Unmarshal(body, &in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.Vendor != "" && in.Vendor != c.Vendor {
			http.Error(w, "vendor is immutable", http.StatusBadRequest)
			return
		}
		conn, _ := s.nms.Registry().Get(c.Vendor)
		wasEnabled := c.Enabled
		applyNMSInput(&c, in, conn.Spec())
		// LICENCE-BEGIN (tracker 256) — the wireless activation transition. The
		// ceiling is asked ONLY on off→on: re-saving an integration that is
		// already enabled changes nothing about what is collected, and turning
		// one OFF can only free capacity.
		if c.Enabled && !wasEnabled {
			if err := s.nmsWirelessActivationCeiling(conn.Spec()); err != nil {
				if !entitlement.WriteRefusal(w, err) {
					writeError(w, http.StatusInternalServerError, errors.New("integration was not enabled"))
				}
				return
			}
		}
		// LICENCE-END
		// F-76: same refusal as the create path — check before the config write.
		if len(in.Credentials) > 0 && !nms.StoreDurable(s.nms.Store()) {
			writeError(w, http.StatusNotImplemented, nms.ErrStorageNotDurable)
			return
		}
		if err := s.nms.Store().Upsert(r.Context(), c); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		if len(in.Credentials) > 0 {
			if err := s.nms.Store().SetCredentials(r.Context(), c.Tenant, c.ID, in.Credentials); err != nil {
				if errors.Is(err, nms.ErrStorageNotDurable) {
					writeError(w, http.StatusNotImplemented, err)
					return
				}
				http.Error(w, "credential save failed", http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, http.StatusOK, s.nmsIntegrationPublic(r.Context(), c))
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		deleted, err := s.nms.Store().Delete(r.Context(), tenant, cross, id)
		if err != nil {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		if !deleted {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// nmsIntegrationTest performs a LIVE authentication against the controller and
// reports success/failure — the wizard's "Test connection" button.
func (s *server) nmsIntegrationTest(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	c, found, err := s.nms.Store().Get(r.Context(), tenant, cross, id)
	if err != nil || !found {
		http.NotFound(w, r)
		return
	}
	conn, ok := s.nms.Registry().Get(c.Vendor)
	if !ok {
		http.Error(w, "unknown vendor", http.StatusInternalServerError)
		return
	}
	creds, _, err := s.nms.Store().Credentials(r.Context(), c.Tenant, c.ID)
	if err != nil {
		http.Error(w, "credential resolve failed", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	do := nms.NewRetryDoer(s.nms.HTTPClient(c), nms.NewTokenBucket(conn.Spec().RatePerSec), nms.DefaultRetry())
	if _, err := conn.Auth().Authenticate(ctx, c.BaseURL, creds, do); err != nil {
		// The vendor error is safe to surface (no secrets in auth errors by design).
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) nmsIntegrationHealth(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	h, found, err := s.nms.Store().Health(r.Context(), tenant, cross, id)
	if err != nil || !found {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

// handleNMSWebhook receives inbound controller webhooks (Meraki, generic).
// UNAUTHENTICATED by JWT (auth.go allowlists the prefix); authenticated by the
// opaque path token + the connector's own signature verification — fail-closed:
// unknown token → 404 (no existence leak), bad signature → 401.
func (s *server) handleNMSWebhook(w http.ResponseWriter, r *http.Request) {
	if s.nms == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/nms/webhook/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	ic, found, err := s.nms.Store().ByWebhookToken(r.Context(), token)
	if err != nil || !found || !ic.Enabled {
		http.NotFound(w, r)
		return
	}
	conn, ok := s.nms.Registry().Get(ic.Vendor)
	if !ok || conn.Webhook() == nil {
		http.NotFound(w, r)
		return
	}
	body, err := readBounded(w, r, 512<<10)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	creds, _, err := s.nms.Store().Credentials(r.Context(), ic.Tenant, ic.ID)
	if err != nil {
		http.Error(w, "verification unavailable", http.StatusInternalServerError)
		return
	}
	secret := ""
	if creds.Extra != nil {
		secret = creds.Extra["webhook_secret"]
	}
	if err := conn.Webhook().Verify(r, body, []byte(secret)); err != nil {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}
	payloads, err := conn.Webhook().Extract(body)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	var accepted int64
	for _, raw := range payloads {
		batch, terr := conn.Transformer().Transform(ic.Tenant, ic.ID, raw)
		if terr != nil {
			continue // one malformed payload must not reject the batch
		}
		accepted += s.nms.IngestBatch(r.Context(), ic, batch)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": accepted})
}
