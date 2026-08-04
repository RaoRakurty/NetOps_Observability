package backend

import (
	"context"
	"errors"
	"fmt"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netops/backend/internalca"
)

// tls_ca.go — internal-CA custody + boot bootstrap (#18 phase 2). The CA root is
// load-or-created once; its PRIVATE KEY is sealed at rest by the #17 Vault
// (platform DEK), while the CA cert (a public trust anchor) is stored plaintext.
// When TLS_INTERNAL_CA=true the API self-bootstraps the mesh on boot: it issues
// its own server SVID to the serving paths, the nginx client SVID, and writes the
// CA trust bundle — so `tlsconfig` (server + mTLS) has real certs with zero manual
// PKI. Short TTLs + re-issue-on-boot are the rotation story (no CRL/OCSP).
//
// Dormant unless TLS_INTERNAL_CA=true. When the Vault is also dormant the CA key
// is stored plaintext (passthrough) — turning on SEAL_PROVIDER=swtpm seals it.
//
// Multi-region / SPIFFE federation (#18 phase 5) is verifier-side only and lives
// in tlsconfig (FederationTrust) + the TLS_FEDERATED_BUNDLES wiring — issuance
// here is unchanged. To federate, each region exports its CA bundle (the file
// written via TLS_CLIENT_CA_FILE) and the operator wires the OTHER region's
// exported root into TLS_FEDERATED_BUNDLES (domain=/path/root.pem) on the peers.

const (
	caKeyField = "tls.ca.key"              // Vault AAD field-id (platform DEK)
	caValidity = 10 * 365 * 24 * time.Hour // CA root lifetime (long; leaves are short)
)

// kv keys for the CA material — vars (not consts) so tests redirect them to temp
// paths (the file backend treats a kv key as a path).
var (
	kvCACertKey = "tls_internal_ca_cert.pem" // public trust anchor (plaintext)
	kvCAKeyKey  = "tls_internal_ca_key.enc"  // CA private key, Vault-sealed
)

type caManager struct {
	vault       *vault.Vault
	ca          *internalca.CA
	trustDomain string
	ttl         time.Duration // SVID lifetime (set at bootstrap; the re-issue loop reuses it)
}

// loadOrCreateCA loads the internal CA from the kv store (cert plaintext, key
// Vault-decrypted) or, on first run, generates one and persists it (key sealed).
func loadOrCreateCA(vault *vault.Vault, trustDomain string) (*caManager, error) {
	m := &caManager{vault: vault, trustDomain: trustDomain}
	certPEM, cerr := platformdb.Load(kvCACertKey)
	keyEnc, kerr := platformdb.Load(kvCAKeyKey)
	if cerr == nil && kerr == nil && len(certPEM) > 0 && len(keyEnc) > 0 {
		keyPEM, err := vault.Decrypt("", caKeyField, string(keyEnc))
		if err != nil {
			return nil, fmt.Errorf("tls ca: decrypt CA key: %w", err)
		}
		ca, err := internalca.FromPEM(certPEM, []byte(keyPEM))
		if err != nil {
			return nil, err
		}
		m.ca = ca
		return m, nil
	}
	ca, err := internalca.Generate("netops internal CA ("+trustDomain+")", caValidity)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	sealed, err := vault.Encrypt("", caKeyField, string(keyPEM))
	if err != nil {
		return nil, err
	}
	if err := platformdb.Save(kvCACertKey, ca.CertPEM()); err != nil {
		return nil, err
	}
	if err := platformdb.Save(kvCAKeyKey, []byte(sealed)); err != nil {
		return nil, err
	}
	m.ca = ca
	return m, nil
}

func (m *caManager) spiffeID(svc string) string {
	return "spiffe://" + m.trustDomain + "/ns/default/sa/" + svc
}

// issueService mints a SVID for svc and writes cert (0644) + key (0600) to the
// given paths. Re-issued each boot (short TTL) — atomic-ish via write+rename.
func (m *caManager) issueService(certPath, keyPath, svc string, ttl time.Duration, dns []string, client, server bool) error {
	svid, err := m.ca.Issue(internalca.Request{
		SPIFFEID: m.spiffeID(svc), DNSNames: dns, TTL: ttl, Client: client, Server: server,
	})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(certPath, svid.CertPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, svid.KeyPEM, 0o600)
}

// writeBundle writes the CA trust anchor (clients verify peers against it).
func (m *caManager) writeBundle(path string) error {
	return writeFileAtomic(path, m.ca.CertPEM(), 0o644)
}

// bootstrapInternalCA self-provisions the mesh on boot when TLS_INTERNAL_CA=true:
// CA bundle + the API's own server SVID (at the serving paths) + the nginx client
// SVID. Fail-closed — TLS was explicitly requested, so an error aborts boot.
func bootstrapInternalCA(vault *vault.Vault) (*caManager, error) {
	if os.Getenv("TLS_INTERNAL_CA") != "true" {
		return nil, nil
	}
	// SEAL GATE (fail closed) — the foot-gun this file's own header describes:
	// "When the Vault is also dormant the CA key is stored plaintext". That CA
	// root is a 10-year credential that can mint an identity for EVERY service
	// in the mesh, so enabling the mesh without custody is strictly worse than
	// leaving TLS off — it manufactures a high-value key and leaves it in the
	// clear. Refuse, in the same shape as ensureSigningSecret (SR-017).
	if !vault.Sealed() && os.Getenv("ALLOW_DEV_SECRETS") != "true" {
		return nil, errors.New("TLS_INTERNAL_CA=true but no sealing provider is active — refusing to create a 10-year CA private key in plaintext. Set SEAL_PROVIDER (e.g. swtpm) so the key is sealed at rest, or set ALLOW_DEV_SECRETS=true for local development only")
	}
	if !vault.Sealed() {
		logWarn("tls", "internal CA key will be stored UNSEALED (ALLOW_DEV_SECRETS=true) — local development only; this key can mint an identity for every service", nil)
	}
	td := envOr("TLS_TRUST_DOMAIN", "netops")
	m, err := loadOrCreateCA(vault, td)
	if err != nil {
		return nil, err
	}
	m.ttl = durationOr("TLS_SVID_TTL", 24*time.Hour)
	if err := m.provisionFromEnv(); err != nil {
		return nil, err
	}
	logInfo("tls", "internal CA bootstrapped", map[string]any{
		"trust_domain": td, "svid_ttl": m.ttl.String(), "ca_not_after": m.ca.NotAfter().Format(time.RFC3339)})
	return m, nil
}

// provisionFromEnv (re)issues the API + nginx SVIDs and rewrites the CA bundle at
// the env-configured paths. Idempotent to re-run — that's exactly what the
// re-issue loop does to rotate before expiry.
func (m *caManager) provisionFromEnv() error {
	if p := os.Getenv("TLS_CLIENT_CA_FILE"); p != "" {
		if err := m.writeBundle(p); err != nil {
			return err
		}
	}
	if cf, kf := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE"); cf != "" && kf != "" {
		if err := m.issueService(cf, kf, "api", m.ttl, []string{"api", "localhost"}, false, true); err != nil {
			return err
		}
	}
	if dir := os.Getenv("TLS_NGINX_CERT_DIR"); dir != "" {
		certPath, keyPath := filepath.Join(dir, "nginx.crt"), filepath.Join(dir, "nginx.key")
		if err := m.issueService(certPath, keyPath,
			"nginx", m.ttl, []string{"nginx"}, true, false); err != nil {
			return err
		}
		// CROSS-UID HANDOFF. This key is MINTED by the API (uid 65532) but READ
		// by nginx (nginx-unprivileged, uid 101). A 0600 key owned by us is
		// unreadable there and nginx refuses to boot —
		//   "cannot load certificate key ...: Permission denied"
		// — so enabling mTLS takes the edge down. Proven live, 2026-08-04.
		//
		// We cannot fix it by chown: this process is deliberately non-root, so
		// os.Chown to another uid returns EPERM. The two honest options are
		// (a) align the uids at deploy time (chown the mount, or run nginx with
		// a matching user), or (b) widen the key mode for a mount that only
		// these two containers see.
		//
		// The mode is therefore EXPLICIT and defaults to the safe value.
		// TLS_NGINX_KEY_MODE=0644 opts into (b) and logs a warning naming the
		// tradeoff — a private key readable by anything that can read the mount.
		// Never silently widened.
		if mode := envOr("TLS_NGINX_KEY_MODE", ""); mode != "" && mode != "0600" {
			m64, perr := strconv.ParseUint(strings.TrimPrefix(mode, "0o"), 8, 32)
			if perr != nil {
				return fmt.Errorf("tls ca: TLS_NGINX_KEY_MODE %q is not an octal file mode: %w", mode, perr)
			}
			if err := os.Chmod(keyPath, os.FileMode(m64)); err != nil {
				return fmt.Errorf("tls ca: set nginx key mode: %w", err)
			}
			logWarn("tls", "nginx SVID key mode widened by TLS_NGINX_KEY_MODE — the private key is readable beyond its owner; acceptable only when the mount is shared solely with nginx",
				map[string]any{"path": keyPath, "mode": mode})
		}
	}
	return nil
}

// startReissueLoop re-issues the SVIDs at ~half the TTL (a generous renewal
// margin) until ctx is done. The API's CertReloader hot-swaps its new cert with
// no restart; nginx needs a reload to pick up its file (see the runbook).
func (m *caManager) startReissueLoop(ctx context.Context) {
	every := m.ttl / 2
	if every < time.Minute {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.provisionFromEnv(); err != nil {
				logError("tls", "SVID re-issue", errf(err))
				continue
			}
			logInfo("tls", "SVIDs re-issued", map[string]any{"svid_ttl": m.ttl.String()})
		}
	}
}

// writeFileAtomic writes via a temp file + rename so a reader (or the cert
// reloader) never sees a half-written cert/key.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
