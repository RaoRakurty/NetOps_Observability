package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// blob.go — the SEALED blob store: where the configuration bytes actually live.
//
// The invariant this file exists to hold is one sentence long: NO CONFIGURATION
// TEXT IS EVER WRITTEN TO DISK IN PLAINTEXT. It is enforced structurally, not by
// convention:
//
//   - Put takes ALREADY-SEALED bytes and additionally refuses anything that does
//     not carry the sealer's version marker, so a future caller cannot hand it a
//     plaintext string by mistake.
//   - The manager refuses to capture at all when the platform's sealing provider
//     is dormant (Sealer.Active() == false). A dormant vault passes plaintext
//     through unchanged, and "we quietly wrote every device's credentials to the
//     data volume in the clear" is not an acceptable default (§8). An operator
//     who wants config backup enables SEAL_PROVIDER; the refusal says so.
//   - The blob directory is created 0700 and every blob 0600, so even a
//     ciphertext file is not world-readable on the volume.

// Sealer is the platform's sealing mechanism as this module needs it (§5:
// interfaces for external deps). Production binds it to the secret-custody vault
// (per-tenant DEK, AES-256-GCM, AAD = tenant|fieldID); tests inject a fake.
type Sealer interface {
	// Seal encrypts plaintext for the owning tenant under fieldID.
	Seal(tenant, fieldID, plaintext string) (string, error)
	// Open reverses Seal.
	Open(tenant, fieldID, sealed string) (string, error)
	// Active reports whether real custody is configured. FALSE means the
	// provider is dormant and Seal is a passthrough — this module then refuses
	// to store anything rather than writing cleartext.
	Active() bool
	// Marker is the prefix a sealed value carries (the vault's "v1:"). Put
	// verifies it, so an unsealed value can never reach the disk.
	Marker() string
}

// BlobField renders the sealing AAD field id for one version. It binds the
// ciphertext to (tenant, device, version): a blob copied into another device's
// or another tenant's row fails to open — no confused deputy.
func BlobField(deviceID, sha string) string {
	return "configstore.config:" + deviceID + ":" + sha
}

// BlobStore persists sealed configuration blobs.
type BlobStore interface {
	// Put stores a sealed blob and returns its opaque reference.
	Put(tenant, deviceID, sha, sealed string) (string, error)
	// Get returns the sealed blob at ref. A missing ref is ErrNotFound.
	Get(ref string) (string, error)
	// Delete removes a blob (retention pruning). A missing blob is not an error.
	Delete(ref string) error
}

// FileBlobStore is the local backend from the design's "Local — encrypted blobs
// on the platform volume (default; air-gap friendly)".
type FileBlobStore struct {
	root   string
	marker string
}

// NewFileBlobStore creates (0700) and returns the local blob store. The marker
// is the sealer's version prefix; Put refuses a blob without it.
func NewFileBlobStore(root, marker string) (*FileBlobStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("configstore: blob directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("configstore: blob directory: %w", err)
	}
	// An existing directory may have been created with a wider mode by an older
	// build or an operator; tighten it rather than trusting what we found (§3).
	// #nosec G302 -- this is a DIRECTORY: 0700 is owner-only and is the tightest
	// mode that still permits traversal; gosec's 0600 expectation is a file rule.
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("configstore: blob directory mode: %w", err)
	}
	if marker == "" {
		return nil, errors.New("configstore: sealer marker is required")
	}
	return &FileBlobStore{root: root, marker: marker}, nil
}

// Root is the blob directory (tests assert on its mode and contents).
func (f *FileBlobStore) Root() string { return f.root }

// pathFor builds the on-disk path. Every component is SANITIZED (tenant/device
// through Seg, sha through validSHA at the caller and again here) so no request
// value can ever escape the root — a version id is untrusted input.
func (f *FileBlobStore) pathFor(tenant, deviceID, sha string) (string, error) {
	if !validSHA(sha) {
		return "", fmt.Errorf("configstore: invalid version id")
	}
	dir := filepath.Join(f.root, Seg(tenant), Seg(deviceID))
	return filepath.Join(dir, sha+".sealed"), nil
}

// Put writes a sealed blob 0600 under a 0700 directory tree.
func (f *FileBlobStore) Put(tenant, deviceID, sha, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, f.marker) {
		// The structural guarantee: an unsealed value never reaches the disk.
		return "", errors.New("configstore: refusing to store an unsealed configuration blob")
	}
	p, err := f.pathFor(tenant, deviceID, sha)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(sealed), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp) // best-effort: the rename already failed; leave no partial
		return "", err
	}
	rel, err := filepath.Rel(f.root, p)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// Get reads a sealed blob by the reference Put returned.
func (f *FileBlobStore) Get(ref string) (string, error) {
	p, err := f.resolve(ref)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p) // #nosec G304 -- ref is resolved and containment-checked by resolve()
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	return string(b), nil
}

// Delete removes a blob; an already-absent blob is success (retention is
// idempotent).
func (f *FileBlobStore) Delete(ref string) error {
	p, err := f.resolve(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// resolve maps a stored reference back to a path INSIDE the root and refuses
// anything that escapes it. The reference comes from a database row, and a
// database row is untrusted input the moment anything else can write to it (§3
// "never trust cached data without validation").
func (f *FileBlobStore) resolve(ref string) (string, error) {
	if ref == "" {
		return "", ErrNotFound
	}
	clean := filepath.Clean(filepath.Join(f.root, filepath.FromSlash(ref)))
	rootClean := filepath.Clean(f.root)
	if clean != rootClean && !strings.HasPrefix(clean, rootClean+string(os.PathSeparator)) {
		return "", errors.New("configstore: blob reference escapes the blob directory")
	}
	return clean, nil
}
