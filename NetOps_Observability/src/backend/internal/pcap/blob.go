package pcap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// blob.go — the sealed capture store.
//
// A PCAP is payload. It is therefore sealed under the OWNING TENANT's DEK before
// a byte reaches the disk, written 0600 under a 0700 tree, and the AAD binds the
// ciphertext to (tenant, device, capture) so a blob copied between tenants or
// devices fails to open — no confused deputy.

// Sealer is the platform sealing mechanism (production: the vault's per-tenant
// DEK, AES-256-GCM, AAD = tenant|fieldID); tests inject a fake.
type Sealer interface {
	// Seal encrypts plaintext for the owning tenant under fieldID.
	Seal(tenant, fieldID, plaintext string) (string, error)
	// Open reverses Seal.
	Open(tenant, fieldID, sealed string) (string, error)
	// Active reports whether real custody is configured. FALSE means the
	// provider is dormant and Seal is a passthrough — this module then refuses
	// to store anything rather than writing packet payload in cleartext.
	Active() bool
	// Marker is the prefix a sealed value carries (the vault's "v1:"). Put
	// verifies it, so an unsealed value can never reach the disk.
	Marker() string
}

// BlobField renders the sealing AAD field id for one capture.
func BlobField(deviceID, captureID string) string {
	return "pcap.capture:" + deviceID + ":" + captureID
}

// BlobStore persists sealed capture blobs.
type BlobStore interface {
	// Put stores a sealed blob and returns its opaque reference.
	Put(tenant, deviceID, captureID, sealed string) (string, error)
	// Get returns the sealed blob at ref. A missing ref is ErrNotFound.
	Get(ref string) (string, error)
	// Delete removes a blob. A missing blob is not an error (retention and
	// deletion are idempotent).
	Delete(ref string) error
}

// FileBlobStore is the local backend (the design's "local encrypted volume,
// default; air-gap friendly").
type FileBlobStore struct {
	root   string
	marker string
}

// NewFileBlobStore creates (0700) and returns the local blob store.
func NewFileBlobStore(root, marker string) (*FileBlobStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("pcap: capture directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("pcap: capture directory: %w", err)
	}
	// An existing directory may have been created with a wider mode by an older
	// build or an operator; tighten it rather than trusting what we found (§3).
	// #nosec G302 -- this is a DIRECTORY: 0700 is owner-only and is the tightest
	// mode that still permits traversal; gosec's 0600 expectation is a file rule.
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("pcap: capture directory mode: %w", err)
	}
	if marker == "" {
		return nil, errors.New("pcap: sealer marker is required")
	}
	return &FileBlobStore{root: root, marker: marker}, nil
}

// Root is the blob directory (tests assert on its mode and contents).
func (f *FileBlobStore) Root() string { return f.root }

// pathFor builds the on-disk path. Every component is sanitized — the capture id
// through ValidateCaptureID, tenant and device through Seg — so no request value
// can escape the root.
func (f *FileBlobStore) pathFor(tenant, deviceID, captureID string) (string, error) {
	if !ValidateCaptureID(captureID) {
		return "", errors.New("pcap: invalid capture id")
	}
	dir := filepath.Join(f.root, Seg(tenant), Seg(deviceID))
	return filepath.Join(dir, captureID+".sealed"), nil
}

// Put writes a sealed blob 0600 under a 0700 tree.
func (f *FileBlobStore) Put(tenant, deviceID, captureID, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, f.marker) {
		// The structural guarantee: an unsealed capture never reaches the disk.
		return "", errors.New("pcap: refusing to store an unsealed capture blob")
	}
	p, err := f.pathFor(tenant, deviceID, captureID)
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

// Delete removes a blob; an already-absent blob is success.
func (f *FileBlobStore) Delete(ref string) error {
	p, err := f.resolve(ref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	// #nosec G703 -- `p` is NOT the caller's string: resolve() joined it under
	// the store root, filepath.Clean'd it and REFUSED anything that escapes
	// (see resolve below), and the ref itself only ever reaches here after
	// ValidateCaptureID minted it. This is the same containment check gosec's
	// taint analysis cannot follow across the helper.
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
		return "", errors.New("pcap: capture reference escapes the capture directory")
	}
	return clean, nil
}
