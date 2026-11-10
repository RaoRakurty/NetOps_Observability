// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"netops/backend/internal/workloadid"
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
//
// First-run is ONLY "both blobs absent" (os.ErrNotExist) — the same discipline
// the Vault applies to its KEK (ErrNoKEK, nothing else). Any other load shape
// (one blob present, a transient read error, a present-but-empty file, a decrypt
// failure) is fatal: silently minting a fresh 10-year root here would RE-ROOT
// the mesh — every previously issued SVID stops chaining, and a truncated cert
// file becomes an authenticated trust-anchor swap.
func loadOrCreateCA(vault *vault.Vault, trustDomain string) (*caManager, error) {
	m := &caManager{vault: vault, trustDomain: trustDomain}
	certPEM, cerr := platformdb.Load(kvCACertKey)
	keyEnc, kerr := platformdb.Load(kvCAKeyKey)
	switch {
	case cerr == nil && kerr == nil && len(certPEM) > 0 && len(keyEnc) > 0:
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
	case errors.Is(cerr, os.ErrNotExist) && errors.Is(kerr, os.ErrNotExist):
		// Genuine first run: neither blob exists yet → generate below.
	default:
		return nil, fmt.Errorf("tls ca: CA state is present but unreadable (cert err=%w len=%d, key err=%w len=%d) — refusing to mint a NEW root over it; restore or explicitly delete BOTH %s and %s to re-root",
			cerr, len(certPEM), kerr, len(keyEnc), kvCACertKey, kvCAKeyKey)
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
	return m.issueServiceKeyMode(certPath, keyPath, svc, ttl, dns, client, server, keyModeOwnerOnly)
}

// issueServiceKeyMode is issueService with an explicit key mode. The mode is set
// on the temp file before the rename, so no reader ever sees the key at a mode
// other than its final one.
func (m *caManager) issueServiceKeyMode(certPath, keyPath, svc string, ttl time.Duration, dns []string, client, server bool, keyMode os.FileMode) error {
	svid, err := m.ca.Issue(internalca.Request{
		SPIFFEID: m.spiffeID(svc), DNSNames: dns, TTL: ttl, Client: client, Server: server,
	})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(certPath, svid.CertPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, svid.KeyPEM, keyMode)
}

// Key custody modes (docs/design/OPENSEARCH_ACCESS_2026-11-09.md). The reader
// table is deployment/docker/tls-key-readers.json; the registry's KeyGroupRead
// flag and tls_ca_custody_test.go keep the mint in line with it.
const (
	// keyModeOwnerOnly is the default for every key.
	keyModeOwnerOnly os.FileMode = 0o600
	// keyModeCeiling bounds what TLS_SERVICE_KEY_MODE and TLS_NGINX_KEY_MODE may
	// ask for: owner read/write and group read. No other bits, ever.
	keyModeCeiling os.FileMode = 0o640
	// A directory holding a key only the owner or root reads.
	keyDirOwnerOnly os.FileMode = 0o700
	// A directory holding a key a group_add reader must reach: it is the root of
	// that reader's bind mount, so the group needs to enter it.
	keyDirGroupRead os.FileMode = 0o750
)

// keyModeFromEnv resolves a key mode from the named variable. Unset means owner
// only. The value applies only to readers that cannot read a 0600 key this
// process owns, and those readers get it through the group, so a mode with any
// bit above keyModeCeiling is refused: an "other" bit makes a private key
// readable by every local user, which is what every TLS install did until
// 2026-11-09. ALLOW_DEV_SECRETS=true is the one way past it, the same dev escape
// hatch the seal gate honours, and secprofile reports it at boot.
func keyModeFromEnv(name string) (os.FileMode, error) {
	mv := envOr(name, "")
	if mv == "" {
		return keyModeOwnerOnly, nil
	}
	m64, err := strconv.ParseUint(strings.TrimPrefix(mv, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("tls ca: %s %q is not an octal file mode: %w", name, mv, err)
	}
	if m64 > 0o777 {
		return 0, fmt.Errorf("tls ca: %s %q sets more than the permission bits", name, mv)
	}
	mode := os.FileMode(m64)
	if mode&0o400 == 0 {
		return 0, fmt.Errorf("tls ca: %s %q leaves the key unreadable by its owner", name, mv)
	}
	if mode&^keyModeCeiling == 0 {
		return mode, nil
	}
	if os.Getenv("ALLOW_DEV_SECRETS") == "true" {
		logWarn("tls", "SVID key mode widened past owner and group by ALLOW_DEV_SECRETS — local development only; other local users may read this private key",
			map[string]any{"variable": name, "mode": mv})
		return mode, nil
	}
	return 0, fmt.Errorf("tls ca: %s %q refused: a private key must not carry bits beyond %04o. Readers that need more than the owner hold the key through group_add; set it to 0640 (installs before 2026-11-09 carried 0644: re-run scripts/update.sh or install.py)",
		name, mv, keyModeCeiling)
}

// serviceKeyMode resolves the mode for the registry rows that read through the
// group (workloadid.Entry.KeyGroupRead). Every other row stays owner only.
func serviceKeyMode() (os.FileMode, error) {
	return keyModeFromEnv("TLS_SERVICE_KEY_MODE")
}

// keyDirModeFor is the directory mode a key at keyMode needs.
func keyDirModeFor(keyMode os.FileMode) os.FileMode {
	if keyMode&0o077 == 0 {
		return keyDirOwnerOnly
	}
	return keyDirGroupRead
}

// adminDirMode is the mode of the directory holding the OpenSearch admin key.
const adminDirMode = keyDirOwnerOnly

// ensureCustodyDir creates dir if it is missing and forces its mode. It runs
// before the key is written, and on every re-issue, so an install that predates
// the mode converges at the next boot. A failure is returned, never swallowed:
// a key directory this process cannot secure is one it should not mint into.
func ensureCustodyDir(dir string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create key directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("set key directory %s to %04o: %w", dir, mode, err)
	}
	return nil
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
	// The whole mint tree is owner only: containers reach their keys through
	// their own bind mounts, which Docker resolves as root, so nothing but this
	// process and root ever traverses it. This also keeps a host user who shares
	// CORRELIX_GID away from the group-readable keys below.
	if root := os.Getenv("TLS_MINT_ROOT"); root != "" {
		if err := ensureCustodyDir(root, keyDirOwnerOnly); err != nil {
			return fmt.Errorf("tls ca: mint root: %w", err)
		}
	}
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
		// CROSS-UID HANDOFF. This key is MINTED by the API (CORRELIX_UID) but READ
		// by nginx (uid 101, cap_drop ALL). A 0600 key owned by us is unreadable
		// there and nginx refuses to boot —
		//   "cannot load certificate key ...: Permission denied"
		// — so enabling mTLS takes the edge down. Proven live, 2026-08-04.
		//
		// We cannot fix it by chown: this process is deliberately non-root, so
		// os.Chown to another uid returns EPERM. nginx instead holds this
		// process's gid through group_add (compose.tls.yml) and the key is group
		// readable. TLS_NGINX_KEY_MODE=0640 opts into that; the default stays
		// 0600, and a mode with other bits is refused (keyModeFromEnv).
		mode, err := keyModeFromEnv("TLS_NGINX_KEY_MODE")
		if err != nil {
			return err
		}
		if err := ensureCustodyDir(dir, keyDirModeFor(mode)); err != nil {
			return fmt.Errorf("tls ca: nginx identity: %w", err)
		}
		if err := m.issueServiceKeyMode(filepath.Join(dir, "nginx.crt"), filepath.Join(dir, "nginx.key"),
			"nginx", m.ttl, []string{"nginx"}, true, false, mode); err != nil {
			return err
		}
	}
	// VictoriaMetrics client SVID (#149): once the API listens mTLS-only, the
	// self-metrics scraper must present an identity too or every netops_* API
	// metric goes dark (proven live 2026-08-04 — the api:8080 scrape sat at
	// up==0 from the moment mTLS shipped). Same shape as nginx above; no
	// key-mode escape hatch is offered because the stock victoria-metrics
	// image runs as root, which reads the 0600 key regardless of owner. The
	// operator also adds spiffe://<td>/ns/default/sa/victoria to
	// TLS_CLIENT_ALLOWED_URIS and points the scrape job at the mTLS variant
	// config (vmscrape-mtls.yml) — see the tls-mtls runbook.
	if dir := os.Getenv("TLS_VICTORIA_CERT_DIR"); dir != "" {
		if err := ensureCustodyDir(dir, keyDirOwnerOnly); err != nil {
			return fmt.Errorf("tls ca: victoria identity: %w", err)
		}
		if err := m.issueService(filepath.Join(dir, "victoria.crt"), filepath.Join(dir, "victoria.key"),
			"victoria", m.ttl, []string{"victoria"}, true, false); err != nil {
			return err
		}
	}
	// SEC-008: the OpenSearch security ADMIN identity. Deliberately NOT a
	// workloadid.Registry row — the registry's completeness ratchet requires
	// every row to name a real compose service, and "opensearch-admin" is a
	// credential, not a workload. It is the identity securityadmin.sh
	// presents to write the security index, mapped by DN in admin_dn
	// (internalca sets Subject CN = the SPIFFE ID, which IS that DN).
	//
	// CUSTODY (2026-11-09): this DN bypasses every role and index check, so the
	// key is 0600 in a 0700 directory and NO environment variable can widen it.
	// Its one reader, opensearch-security-init, runs as this process's uid and
	// mounts only this directory. Do not add a key-mode escape hatch here.
	if dir := os.Getenv("TLS_OS_ADMIN_CERT_DIR"); dir != "" {
		if err := ensureCustodyDir(dir, adminDirMode); err != nil {
			return fmt.Errorf("tls ca: opensearch admin identity: %w", err)
		}
		if err := m.issueService(filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key"),
			"opensearch-admin", m.ttl, nil, true, false); err != nil {
			return fmt.Errorf("tls ca: opensearch admin identity: %w", err)
		}
		if err := m.writeBundle(filepath.Join(dir, "ca.pem")); err != nil {
			return fmt.Errorf("tls ca: admin trust bundle: %w", err)
		}
	}
	// SEC-003.3: table-driven issuance for EVERY registered workload
	// (internal/workloadid — the identity registry with its own completeness
	// guards). Additive and dormant — nothing reads
	// <root>/<service>/<service>.{crt,key} until that service's consuming
	// epic mounts it — so minting cannot break a running stack. Re-issued by
	// the same TTL/2 loop that calls this method.
	if root := os.Getenv("TLS_SERVICE_CERT_ROOT"); root != "" {
		// Cross-uid handoff, same as the nginx SVID above: these keys are MINTED by
		// the api (CORRELIX_UID), this process is non-root so os.Chown is EPERM,
		// and only the rows flagged KeyGroupRead have a reader that cannot read a
		// 0600 file of ours. Those hold this process's gid through group_add and
		// get the configured group mode. Every other row stays 0600: its reader is
		// root with Docker's default capabilities, or a wrapper that stages the
		// key as root, or nothing at all yet.
		groupMode, err := serviceKeyMode()
		if err != nil {
			return err
		}
		if err := ensureCustodyDir(root, keyDirOwnerOnly); err != nil {
			return fmt.Errorf("tls ca: service cert root: %w", err)
		}
		for _, e := range workloadid.Registry {
			dir := filepath.Join(root, e.Service)
			keyMode := keyModeOwnerOnly
			if e.KeyGroupRead {
				keyMode = groupMode
			}
			if err := ensureCustodyDir(dir, keyDirModeFor(keyMode)); err != nil {
				return fmt.Errorf("tls ca: svid registry: %s: %w", e.Service, err)
			}
			if err := m.issueServiceKeyMode(
				filepath.Join(dir, e.Service+".crt"), filepath.Join(dir, e.Service+".key"),
				e.Service, m.ttl, e.DNS, e.Client, e.Server, keyMode); err != nil {
				return fmt.Errorf("tls ca: svid registry: %s: %w", e.Service, err)
			}
			// Each service dir is SELF-CONTAINED: cert + key + the trust
			// anchor. Consumers can then mount one directory read-only and
			// find everything they need — several (OpenSearch) reject config
			// paths outside their own config dir, and docker cannot nest a
			// file mount inside a read-only directory mount anyway.
			if err := m.writeBundle(filepath.Join(dir, "ca.pem")); err != nil {
				return fmt.Errorf("tls ca: %s trust bundle: %w", e.Service, err)
			}
		}
	}
	return nil
}

// reissueJitterFrac spreads each re-issue interval by a uniform ±10%. Every
// mesh vendor staggers renewals (Istio SECRET_GRACE_PERIOD_RATIO_JITTER,
// step-ca's built-in daemon jitter, Vault Agent's ± jitter at its renewal
// threshold) so that a fleet whose loops started together cannot thundering-
// herd the CA nor trigger synchronized reload waves across the stack
// (TLS benchmark 2026-08-23, delta #1).
const reissueJitterFrac = 0.10

// jitteredInterval returns base shifted by a uniform random offset within
// ±(frac·base). crypto/rand because gosec forbids math/rand and the call rate
// (twice per TTL) makes the cost irrelevant; on any rand failure the plain
// base is returned — jitter is best-effort, the schedule must never fail.
func jitteredInterval(base time.Duration, frac float64) time.Duration {
	if base <= 0 || frac <= 0 {
		return base
	}
	span := int64(float64(base) * frac * 2)
	if span <= 0 {
		return base
	}
	n, err := crand.Int(crand.Reader, big.NewInt(span))
	if err != nil {
		return base
	}
	return base - time.Duration(int64(float64(base)*frac)) + time.Duration(n.Int64())
}

// startReissueLoop re-issues the SVIDs at ~half the TTL (a generous renewal
// margin, the SPIRE/Istio default rotation point) until ctx is done, each
// interval independently jittered by reissueJitterFrac. The API's CertReloader
// hot-swaps its new cert with no restart; nginx needs a reload to pick up its
// file (see the runbook).
func (m *caManager) startReissueLoop(ctx context.Context) {
	base := m.ttl / 2
	if base < time.Minute {
		base = time.Minute
	}
	t := time.NewTimer(jitteredInterval(base, reissueJitterFrac))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.provisionFromEnv(); err != nil {
				logError("tls", "SVID re-issue", errf(err))
			} else {
				logInfo("tls", "SVIDs re-issued", map[string]any{"svid_ttl": m.ttl.String()})
			}
			t.Reset(jitteredInterval(base, reissueJitterFrac))
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
	return platformdb.WriteFileAtomic(path, data, perm)
}
