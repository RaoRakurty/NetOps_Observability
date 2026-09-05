package metering

// reportkey.go — the PER-INSTALLATION report signing key.
//
// WHY A SECOND KEY EXISTS AT ALL. Correlix's licence signing key lives offline
// on a signing host and is NOT on any customer machine — that is the whole
// custody story in docs/runbooks/licensing.md, and it must stay true. A usage
// report is produced ON the customer's installation, so it cannot be signed by
// a key that is not there. It gets its own identity: generated locally the
// first time a report is produced, stored 0600 beside the licence, never sent
// anywhere, and never used for anything but usage reports.
//
// WHAT THE SIGNATURE DOES AND DOES NOT PROVE. It proves that a report was
// produced by THIS installation and has not been altered since — which is what
// a true-up conversation needs, because both sides can then compute the same
// numbers over the same bytes. It does not prove the numbers are true in some
// absolute sense: a customer who edits their own installation's state changes
// what it honestly reports. That is not a hole to be plugged with cryptography,
// and pretending otherwise would be the dishonest part.
//
// FAILING SOFT. A key that cannot be written still signs — in memory, for this
// process — and the failure is reported rather than swallowed. A key that
// cannot be GENERATED refuses the report with the reason, because an unsigned
// document offered as a signed one is worse than no document.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Fingerprint is a public key's identity: the first 8 bytes of its SHA-256,
// hex. The same construction the licence keys use, so an operator reading two
// key ids on the same page reads them the same way.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ReportKeyPathFor is where the key lives for a given licence path: beside the
// licence and its overage register, because an operator copying /data/api out
// should get the whole commercial state or none of it.
func ReportKeyPathFor(licencePath string) string {
	return filepath.Join(filepath.Dir(licencePath), "licence-report-key.json")
}

// keyFile is the on-disk shape.
type keyFile struct {
	KeyID     string    `json:"key_id"`
	Public    string    `json:"public"`
	Private   string    `json:"private"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

// ReportKey is the installation's report signing identity, loaded or generated
// on first use.
//
// Safe for concurrent use: the Licence page reads the public half while a
// download signs with the private one.
type ReportKey struct {
	path string
	// warn reports a persistence problem to the platform's logger. Optional.
	warn func(msg string, err error)
	// now is injected so the created-at stamp is testable.
	now func() time.Time
	// rnd is the key source. Injected only by tests; production is crypto/rand.
	rnd func() (ed25519.PublicKey, ed25519.PrivateKey, error)

	mu      sync.Mutex
	priv    ed25519.PrivateKey
	created time.Time
	lastErr error
	// ephemeral records that the key on hand was generated but could NOT be
	// stored, so every surface can say so instead of silently issuing reports
	// under an identity that changes at the next restart.
	ephemeral bool
}

// NewReportKey builds the key over path. It does NOT touch the disk:
// generation and loading happen on first use, so construction cannot fail and
// an installation that never asks for a report never grows a key.
//
// warn may be nil.
func NewReportKey(path string, warn func(msg string, err error)) *ReportKey {
	return &ReportKey{
		path: path,
		warn: warn,
		now:  func() time.Time { return time.Now().UTC() },
		rnd:  func() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) },
	}
}

// Path is where the key lives, for the runbook.
func (k *ReportKey) Path() string {
	if k == nil {
		return ""
	}
	return k.path
}

// Private returns the signing key, generating and storing it on first use.
func (k *ReportKey) Private() (ed25519.PrivateKey, time.Time, error) {
	if k == nil {
		return nil, time.Time{}, errors.New("metering: no report key configured — this build cannot sign a usage report")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensureLocked(); err != nil {
		return nil, time.Time{}, err
	}
	return k.priv, k.created, nil
}

// View returns the PUBLIC half for display, generating the key on first use.
// A build that cannot produce a key returns ok=false rather than an empty
// view, so a page can say why instead of showing a blank panel.
func (k *ReportKey) View() (ReportKeyView, bool) {
	if k == nil {
		return ReportKeyView{}, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensureLocked(); err != nil {
		return ReportKeyView{}, false
	}
	pub, ok := k.priv.Public().(ed25519.PublicKey)
	if !ok {
		return ReportKeyView{}, false
	}
	return ReportKeyView{
		ID:        Fingerprint(pub),
		Base64:    base64.StdEncoding.EncodeToString(pub),
		CreatedAt: k.created,
		Note:      ReportKeyNote,
	}, true
}

// Err is the last persistence problem, or nil. Exposed so an operator surface
// can say the key is not being kept rather than leaving a changing key id
// unexplained.
func (k *ReportKey) Err() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lastErr
}

// Ephemeral reports that the key on hand could not be stored and will not
// survive a restart.
func (k *ReportKey) Ephemeral() bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ephemeral
}

// ensureLocked loads the key, or generates and stores one.
func (k *ReportKey) ensureLocked() error {
	if k.priv != nil {
		return nil
	}
	if k.path != "" {
		if err := k.loadLocked(); err == nil {
			return nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			// A key file that exists but cannot be read is NOT quietly replaced:
			// generating a new one would silently change the identity every
			// report a customer has already filed was signed under.
			k.lastErr = err
			if k.warn != nil {
				k.warn("metering: the usage-report signing key could not be read; usage reports cannot be signed until it is repaired or removed", err)
			}
			return fmt.Errorf("metering: the usage-report signing key at %s could not be read: %w", k.path, err)
		}
	}
	pub, priv, err := k.rnd()
	if err != nil {
		return fmt.Errorf("metering: generating the usage-report signing key: %w", err)
	}
	k.priv = priv
	k.created = k.now()
	if k.path == "" {
		k.ephemeral = true
		return nil
	}
	f := keyFile{
		KeyID:     Fingerprint(pub),
		Public:    base64.StdEncoding.EncodeToString(pub),
		Private:   base64.StdEncoding.EncodeToString(priv),
		CreatedAt: k.created,
		Note:      ReportKeyNote,
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(k.path, append(body, '\n')); err != nil {
		// Sign with what we have, but say the identity is not durable.
		k.ephemeral = true
		k.lastErr = err
		if k.warn != nil {
			k.warn("metering: the usage-report signing key could not be stored; reports will be signed by a key that changes at the next restart", err)
		}
	}
	return nil
}

// loadLocked reads an existing key file.
func (k *ReportKey) loadLocked() error {
	// #nosec G304 G703 -- `k.path` is derived at construction from the licence
	// file's directory (ReportKeyPathFor), never from a request or a caller
	// string.
	raw, err := os.ReadFile(k.path)
	if err != nil {
		return err
	}
	var f keyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("%s is not a usage-report key file: %w", k.path, err)
	}
	priv, err := base64.StdEncoding.DecodeString(f.Private)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%s does not hold a %d-byte ed25519 private key", k.path, ed25519.PrivateKeySize)
	}
	k.priv = ed25519.PrivateKey(priv)
	k.created = f.CreatedAt.UTC()
	if k.created.IsZero() {
		k.created = k.now()
	}
	k.lastErr = nil
	k.ephemeral = false
	return nil
}
