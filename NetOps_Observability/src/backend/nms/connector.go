// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"net/http"
	"time"
)

// connector.go — the framework interfaces. A vendor connector is assembled from
// these; the runtime drives them. Adding a vendor = implement Connector +
// register it. The core never imports a vendor package (no tight coupling), and
// vendor code never imports the correlation engine.

// AuthKind enumerates the auth flows the runtime supports.
type AuthKind string

const (
	AuthAPIKey  AuthKind = "api_key" // e.g. Meraki X-Cisco-Meraki-API-Key
	AuthToken   AuthKind = "token"   // e.g. Catalyst /auth/token, NDFC login → JWT
	AuthSession AuthKind = "session" // e.g. vManage JSESSIONID + XSRF
	AuthBasic   AuthKind = "basic"   // e.g. Prime, Versa Director
	AuthOAuth   AuthKind = "oauth"   // e.g. Versa bearer
)

// ConnectorSpec is a connector's static description — what it is and how it's
// driven. Purely declarative; no secrets.
//
// AUTH POLICY (owner, 2026-07-03):
//   - Every connector supports a simple credential auth for TESTING — Basic
//     (username/password) wherever the vendor has that concept. The one
//     exception is Meraki, which has no username/password at all: its simple
//     test-path credential is the API key (we do not invent a Basic flow a
//     vendor doesn't expose).
//   - OAuth is implemented FULLY for every vendor that supports it (verified
//     2026: Meraki OAuth 2.0, Versa Director/Concerto). Where OAuth exists it is
//     the PreferredAuth; the runtime falls back to the supported list otherwise.
//   - The other Cisco platforms expose no OAuth (verified): they use
//     username/password → short-lived JWT/token (Catalyst Center, vManage,
//     NDFC) or session (older vManage) or raw Basic (Prime, legacy). Basic /
//     credential login is therefore always a supported path for them.
type ConnectorSpec struct {
	Vendor        string        // meraki | catalyst_center | vmanage | ndfc | versa_director | versa_concerto | prime | generic
	Product       string        // human product name
	SourceSystem  string        // maps to Signal source_system
	SupportedAuth []AuthKind    // all auth flows this connector implements (Basic/API-key always present for testing)
	PreferredAuth AuthKind      // the flow the wizard defaults to (OAuth where the vendor supports it)
	Webhook       bool          // supports inbound webhooks
	Poll          bool          // supports REST polling
	Streams       []string      // logical streams it can poll (alarms, inventory, tunnels, …)
	DefaultPoll   time.Duration // recommended poll interval
	// RatePerSec bounds outbound calls (0 = connector default). E.g. Meraki 10/s.
	RatePerSec float64
	// Capabilities declares what the vendor can actually report and how proven
	// each mapping is (capability.go, #128). Absent capability = FidelityNone
	// (fail closed): "not observable here", never assumed healthy.
	Capabilities []CapabilityDecl
}

// SupportsAuth reports whether the connector implements an auth kind.
func (s ConnectorSpec) SupportsAuth(k AuthKind) bool {
	for _, a := range s.SupportedAuth {
		if a == k {
			return true
		}
	}
	return false
}

// Credentials is the resolved (decrypted) secret material handed to an
// AuthProvider at runtime. The runtime resolves it from the Vault; connectors
// never read it from anywhere else. Fields are populated per AuthKind.
type Credentials struct {
	APIKey       string
	Username     string
	Password     string
	Token        string
	ClientID     string
	ClientSecret string
	// Extra carries vendor-specific fields (e.g. org id) without widening the
	// struct per vendor.
	Extra map[string]string
}

// Session is an authenticated context an AuthProvider produces and refreshes:
// the headers/cookies to attach and when they expire.
type Session struct {
	Header    http.Header
	ExpiresAt time.Time // zero = non-expiring (e.g. static API key)
}

// Valid reports whether the session is still usable at t (with a small skew).
func (s Session) Valid(t time.Time) bool {
	return s.ExpiresAt.IsZero() || t.Before(s.ExpiresAt.Add(-30*time.Second))
}

// AuthProvider establishes and refreshes an authenticated Session. Refresh is
// called by the runtime when a Session is invalid or a request 401s.
type AuthProvider interface {
	// Authenticate performs the login/token exchange and returns a Session.
	Authenticate(ctx context.Context, base string, creds Credentials, do Doer) (Session, error)
}

// Doer is the minimal HTTP surface the runtime hands to connectors — the
// rate-limited/retried client. Connectors never construct their own client.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// PollInput is what the runtime gives a Poller for one stream.
type PollInput struct {
	Base       string
	Stream     string
	Session    Session
	Checkpoint Checkpoint
	Backfill   time.Duration // >0 on first run
	Do         Doer
	// Params resolves vendor path placeholders (e.g. Meraki {org}); the runtime
	// populates it from Credentials.Extra.
	Params map[string]string
}

// Poller fetches raw payloads for one stream. It returns the raw bytes (handed
// to the Transformer) plus the advanced checkpoint. Poller does NOT normalize.
type Poller interface {
	Poll(ctx context.Context, in PollInput) (raw [][]byte, next Checkpoint, err error)
}

// WebhookHandler verifies and extracts the body of an inbound webhook. It must
// authenticate (shared secret / HMAC) and must not mutate global state.
type WebhookHandler interface {
	Verify(r *http.Request, body, secret []byte) error
	// Extract returns the raw payloads to normalize (a webhook may batch).
	Extract(body []byte) ([][]byte, error)
}

// Transformer turns one raw payload into a normalized Batch (the three signal
// classes). This is the ONLY vendor-specific normalization seam. Pure: no IO.
type Transformer interface {
	Transform(tenant, integrationID string, raw []byte) (Batch, error)
}

// Connector bundles a vendor's pieces. Poll-only connectors return nil for
// Webhook(); webhook-only connectors return nil for Poller().
type Connector interface {
	Spec() ConnectorSpec
	Auth() AuthProvider
	Poller() Poller
	Webhook() WebhookHandler
	Transformer() Transformer
}

// Checkpoint is a resume cursor for a stream.
type Checkpoint struct {
	LastEventTime time.Time
	LastSeq       int64
}

// CheckpointStore persists resume cursors per (tenant, integration, stream).
type CheckpointStore interface {
	Load(ctx context.Context, tenant, integrationID, stream string) (Checkpoint, error)
	Save(ctx context.Context, tenant, integrationID, stream string, cp Checkpoint) error
}

// RateLimiter bounds outbound call rate per integration.
type RateLimiter interface {
	// Wait blocks until a token is available or ctx is done.
	Wait(ctx context.Context) error
}

// RetryPolicy decides whether/when to retry a failed attempt.
type RetryPolicy interface {
	// Next returns the delay before retry attempt n (1-based) and whether to
	// retry at all. retryAfter is the parsed Retry-After (0 if absent).
	Next(attempt int, status int, retryAfter time.Duration) (delay time.Duration, retry bool)
}

// HealthReporter records connector health + run outcomes.
type HealthReporter interface {
	RunStarted(ctx context.Context, tenant, integrationID, runID string, at time.Time)
	RunFinished(ctx context.Context, tenant, integrationID, runID string, at time.Time, events int, err error)
}
