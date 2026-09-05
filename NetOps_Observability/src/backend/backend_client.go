package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/internal/dataprotect"
	"netops/backend/tlsconfig"
)

// backend_client.go — hardened HTTP client for the API's INTERNAL backends
// (OpenSearch / ClickHouse / VictoriaMetrics / correlation / stack probes).
// #18 phase 3.
//
// When an internal trust bundle is configured (TLS_BACKEND_CA_FILE, defaulting to
// the mesh CA in TLS_CLIENT_CA_FILE), https calls to those backends verify against
// THAT explicit CA — never the system pool — and optionally present a client SVID
// for mTLS (TLS_BACKEND_CERT_FILE/KEY). Plain http is unaffected. Dormant (plain
// client, current behavior) when no bundle is set.
//
// External services (Anthropic/OpenAI copilot, the OIDC issuer/JWKS, NetBox) are
// PUBLIC-CA endpoints and deliberately keep the default system-pool client — they
// must NOT route through this internal-CA transport.

// backendTr is the shared hardened transport, set once at startup by
// initBackendTransport. nil = no internal TLS configured → default client.
var backendTr *http.Transport

// initBackendTransport builds the internal-backend transport from env. Fail
// closed: a configured-but-unloadable bundle/cert is a fatal startup error
// (returned to the caller), never a silent downgrade to the system pool.
func initBackendTransport() error {
	caFile := strings.TrimSpace(envOr("TLS_BACKEND_CA_FILE", os.Getenv("TLS_CLIENT_CA_FILE")))
	if caFile == "" {
		return nil // dormant — default client (unchanged behavior)
	}
	// FIRST-BOOT ORDERING (2026-08-04). This runs early in main, but when
	// TLS_INTERNAL_CA=true the bundle it needs is MINTED LATER by
	// bootstrapInternalCA (which needs the Vault, built with the server). On a
	// virgin deployment the file therefore does not exist yet, and failing
	// closed here crash-looped the API — enabling internal TLS bricked the
	// stack. Proven live on the lab, 2026-08-04.
	//
	// Defer, never skip: main calls initBackendTransport AGAIN after the CA
	// bootstrap, and THAT call fails closed normally. The narrow tolerance is
	// (a) only when the internal CA is enabled — i.e. something is about to
	// create this exact file — and (b) only for "not exists", never for a
	// malformed or unreadable bundle.
	if os.Getenv("TLS_INTERNAL_CA") == "true" {
		if _, statErr := os.Stat(caFile); os.IsNotExist(statErr) {
			logInfo("tls", "backend trust bundle not present yet — deferring until the internal CA mints it", map[string]any{"path": caFile})
			return nil
		}
	}
	// SPIFFE federation (#18 phase 5): fold federated roots into BOTH the combined
	// pool (chain building) and the registry (domain binding) — invariant
	// anchorable ⊇ registered — so an outbound backend in another trust domain
	// can't impersonate a local identity.
	fedEntries, err := parseFederationBundles(os.Getenv("TLS_FEDERATED_BUNDLES"))
	if err != nil {
		return err
	}
	bundle, err := tlsconfig.LoadTrustBundle(append([]string{caFile}, federationPaths(fedEntries)...)...)
	if err != nil {
		return err
	}
	opts := tlsconfig.ClientOptions{RootCAs: bundle}
	if len(fedEntries) > 0 {
		// Register the local domain too, so local backend servers (same-domain
		// SVIDs) still bind once federation is on. See ensureLocalDomain.
		fed, err := tlsconfig.LoadFederationTrust(ensureLocalDomain(fedEntries, caFile))
		if err != nil {
			return err
		}
		opts.Peer = tlsconfig.PeerPolicy{
			Federation: fed,
			OnReject: func(identity string, rerr error) {
				logError("tls", "backend SPIFFE federation rejected", map[string]any{"peer_identity": identity, "reason": rerr.Error()})
			},
		}
	}
	// Optional mTLS: present the API's client SVID to backends that require it.
	if cf, kf := os.Getenv("TLS_BACKEND_CERT_FILE"), os.Getenv("TLS_BACKEND_KEY_FILE"); cf != "" && kf != "" {
		// Same first-boot ordering hazard as the trust bundle above: on a
		// virgin TLS-enabled deployment the API's own SVID is minted by
		// bootstrapInternalCA AFTER this first call. Under exactly the same
		// narrow condition (internal CA on + file not yet present) build the
		// transport WITHOUT the client certificate — server-verified TLS to
		// the stores still works — and let the post-CA re-initialization
		// load it, failing closed as usual. (APP-001 made this path
		// load-bearing: the api presents this SVID to correlation.)
		deferSVID := false
		if os.Getenv("TLS_INTERNAL_CA") == "true" {
			if _, statErr := os.Stat(cf); os.IsNotExist(statErr) {
				logInfo("tls", "backend client SVID not present yet — deferring until the internal CA mints it", map[string]any{"path": cf})
				deferSVID = true
			}
		}
		if !deferSVID {
			rl, err := tlsconfig.NewCertReloader(cf, kf)
			if err != nil {
				return err
			}
			opts.Reloader = rl
		}
	}
	tr, err := tlsconfig.HTTPTransport(opts)
	if err != nil {
		return err
	}
	backendTr = tr
	return nil
}

// authURLTransport honors credentials embedded in a backend URL's userinfo
// (e.g. VICTORIA_URL=https://svc-api:<pw>@vmauth:8427, SEC-010): net/http
// deliberately does NOT apply URL userinfo itself, so the shared transport
// does — one seam instead of auth code in nine call sites. The userinfo is
// stripped from the outgoing request so the credential can never leak into a
// proxy log, Location echo, or error string that prints the URL.
type authURLTransport struct{ base http.RoundTripper }

func (t authURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u := req.URL.User; u != nil {
		user := u.Username()
		pass, _ := u.Password()
		// Clone before mutating — a RoundTripper must not modify the caller's
		// request (net/http contract).
		req = req.Clone(req.Context())
		req.URL.User = nil
		req.SetBasicAuth(user, pass)
	}
	return t.base.RoundTrip(req)
}

// backendHTTPClient returns an *http.Client for an internal-backend call with the
// given timeout, sharing the one hardened transport (connection pooling) when
// internal TLS is configured, else a plain client. Either way the transport
// honors URL-userinfo credentials (authURLTransport).
func backendHTTPClient(timeout time.Duration) *http.Client {
	// http.DefaultTransport is declared as http.RoundTripper upstream, so the
	// inferred type is already the interface (QF1011).
	base := http.DefaultTransport
	if backendTr != nil {
		base = backendTr
	}
	return &http.Client{Timeout: timeout, Transport: authURLTransport{base: base}}
}

// ── OpenSearch request plumbing ─────────────────────────────────────────────
//
// The api is the ONLY thing that speaks to OpenSearch: the browser never does,
// the proxy carries the service identity, and the admin certificate never
// leaves the host. These three helpers are the shared request path — the
// quarantine restore loop (pipeline_processors.go) and the Data Protection
// adapter (internal/dataprotect, wired in main.go) both go through them, so a
// transport or error-shape change lands in exactly one place.

// osBase is the search cluster's base URL, trailing slash trimmed.
func (s *server) osBase() string {
	return strings.TrimRight(envOr("OPENSEARCH_URL", "http://opensearch:9200"), "/")
}

// osDo performs one OpenSearch request with an EXPLICIT per-call timeout and
// decodes the JSON reply into out (nil = discard the body).
//
// A non-2xx status comes back as a *dataprotect.StatusError carrying both the
// status and a BOUNDED slice of the body: the 2026-08-27 repository incident
// was diagnosable ONLY from the NoSuchFileException text, and a bare status
// line would have thrown it away again. Callers turn that into an honest
// Detail string, never a silent zero value.
func (s *server) osDo(ctx context.Context, method, path string, body []byte, out any, timeout time.Duration) error {
	var rd io.Reader = strings.NewReader("")
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, s.osBase()+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := backendHTTPClient(timeout).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// best-effort: a read error just leaves the snippet empty; the status line is already actionable
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := "opensearch " + resp.Status + " on " + path
		if t := strings.TrimSpace(string(snippet)); t != "" {
			msg += ": " + t
		}
		return &dataprotect.StatusError{Status: resp.StatusCode, StatusText: resp.Status, Msg: msg}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// osJSON is osDo with the fixed document/policy deadline. 10s is right for a
// document write and catastrophically wrong for a restore, which is why the
// long operations pass their own timeout to osDo instead of borrowing this.
func (s *server) osJSON(ctx context.Context, method, path string, body []byte, out any) error {
	return s.osDo(ctx, method, path, body, out, 10*time.Second)
}
