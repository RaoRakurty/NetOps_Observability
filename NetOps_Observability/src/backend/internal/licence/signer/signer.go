// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package signer issues Correlix licence files: key generation, signing, and
// the file handling around a private key.
//
// It is a separate package from internal/licence for one reason that matters:
// the api NEVER imports it. The running product needs only the PUBLIC half —
// verification — and keeping the signing code out of its import graph means a
// bug in the api cannot reach signing material, and `go list` makes that
// checkable rather than a promise.
//
// The only consumer is cmd/correlix-licence (CLAUDE.md §2: entrypoints hold no
// business logic, so every decision below lives here and the command is
// argument parsing).
//
// # Key custody
//
// Production signing keys are held offline (HSM / air-gapped signer) with the
// ceremony recorded — docs/runbooks/licensing.md. This package deliberately
// offers no network, no key escrow and no key upload: a private key is a file
// on the machine doing the signing, mode 0600, and nothing here will read one
// that is more permissive than that.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netops/backend/internal/licence"
)

// KeyPair is a generated signing identity.
type KeyPair struct {
	ID      string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// PublicBase64 is the standard-base64 public key: what gets embedded in the
// binary and printed in the docs so customers can verify offline.
func (k KeyPair) PublicBase64() string { return base64.StdEncoding.EncodeToString(k.Public) }

// PrivateBase64 is the standard-base64 private key. It is written to a 0600
// file and never logged, never printed, never sent anywhere.
func (k KeyPair) PrivateBase64() string { return base64.StdEncoding.EncodeToString(k.Private) }

// GenerateKey creates a new ed25519 signing identity from crypto/rand.
func GenerateKey() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signer: generating key: %w", err)
	}
	return KeyPair{ID: licence.KeyID(pub), Public: pub, Private: priv}, nil
}

// ErrKeyPermissions is returned when a private key file is readable by anyone
// other than its owner. Refusing to sign with a world-readable key is the
// cheapest custody control there is, and it costs an operator one chmod.
var ErrKeyPermissions = errors.New("signer: private key file must be mode 0600")

// WritePrivateKey writes a private key at mode 0600, refusing to clobber an
// existing file.
//
// O_EXCL is the whole point: silently overwriting a signing key would strand
// every licence already issued under it, with no error and no way back.
func WritePrivateKey(path string, k KeyPair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// #nosec G304 -- writing a new signing key to the path the operator named is
	// this tool's job. O_EXCL is the control: an existing file is never touched.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("signer: %s already exists — refusing to overwrite a signing key (every licence issued under it would become unverifiable)", path)
		}
		return err
	}
	defer func() { _ = f.Close() }() // best-effort: the write error below is the one that matters
	if _, err := f.WriteString(k.PrivateBase64() + "\n"); err != nil {
		return err
	}
	return f.Close()
}

// LoadPrivateKey reads a private key, refusing anything more permissive than
// 0600.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is %#o", ErrKeyPermissions, path, perm)
	}
	// #nosec G304 -- reading the operator's signing key from the path they named
	// IS this tool's job; the mode check above is the control that matters, and
	// there is no fixed path a key-management tool could be restricted to.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("signer: %s is not a base64 private key: %w", path, err)
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: %s is %d bytes, want %d", path, len(dec), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}

// Sign validates a document and signs it, filling KeyID and Signature.
//
// Validation comes FIRST and is not optional: an invalid licence must be
// impossible to issue. A file with a tier or feature outside the closed
// vocabulary would verify cryptographically and then be refused at install
// time, i.e. the customer would discover our typo. Catching it here means the
// mistake never leaves the signing machine.
func Sign(d licence.Document, priv ed25519.PrivateKey) (licence.Document, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return licence.Document{}, errors.New("signer: private key is the wrong size")
	}
	d.Features = licence.NormaliseFeatures(d.Features)
	d.IssuedAt = d.IssuedAt.UTC().Truncate(time.Second)
	d.ExpiresAt = d.ExpiresAt.UTC().Truncate(time.Second)
	// Clear any signature carried in from a template before validating, so a
	// re-signed document cannot inherit a stale one.
	d.Signature, d.KeyID = "", ""
	if err := d.Validate(); err != nil {
		return licence.Document{}, err
	}
	payload, err := licence.CanonicalPayload(d)
	if err != nil {
		return licence.Document{}, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return licence.Document{}, errors.New("signer: private key has no ed25519 public half")
	}
	d.KeyID = licence.KeyID(pub)
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return d, nil
}
