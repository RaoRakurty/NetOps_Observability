// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// sign.go — the api↔prober records are SIGNED (Paths redesign P3, 2026-11-21).
//
// The channel itself is authenticated (Valkey password, TLS when the install
// turns TLS on), but every service that holds the Valkey password could write
// the switch key and turn the raw-socket prober on, or — from P3 on — point it
// at targets of its choosing. Zero trust (§3) means the prober believes a
// record only when it carries an HMAC-SHA256 over its exact bytes under a key
// only the api and the prober hold (PROBER_CONTROL_KEY, rendered by
// scripts/install.py into data/secrets/probercontrol/{api,prober}/password).
//
// The signature also binds the record's KIND, so a validly signed targets
// record copied into the switch key does not verify as a switch record.
//
// ROTATION. install.py --rotate-app-secrets re-renders both key files; each
// side re-reads its file within a second (internal/credfile). The two sides do
// not flip at the same instant, so the prober keeps accepting the PREVIOUS key
// for RotationGrace after it sees its own file change. The api always signs
// with its current key. Outside that window an old-key record is refused.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/credfile"
)

// Record kinds bound into the signature.
const (
	KindSwitches = "switches"
	KindTargets  = "targets"
)

// RotationGrace is how long the previous key is still accepted after a
// rotation is observed. It covers the api's next publish (PublishEvery) with a
// wide margin for a slow re-render, and is short enough that a leaked old key
// stops working within minutes.
const RotationGrace = 10 * time.Minute

// minKeyBytes refuses a key too short to be a real generated secret (a broken
// render, an operator's placeholder). Generated keys are 43 characters.
const minKeyBytes = 32

var (
	// ErrNoKey: no signing key is loaded. The api publishes nothing; the
	// prober reads every switch OFF.
	ErrNoKey = errors.New("probercontrol: no signing key is loaded")
	// ErrUnsigned: the record is not a signed envelope.
	ErrUnsigned = errors.New("probercontrol: the record is not signed")
	// ErrBadSignature: the signature does not verify under any accepted key.
	ErrBadSignature = errors.New("probercontrol: the record's signature does not verify")
)

// KeySource yields the current key. *credfile.File satisfies it.
type KeySource interface {
	Value() (string, error)
}

// Keyring holds the current key and, for RotationGrace after a change, the
// previous one.
type Keyring struct {
	src   KeySource
	now   func() time.Time
	grace time.Duration

	mu        sync.Mutex
	current   string
	previous  string
	prevUntil time.Time
}

// NewKeyring builds a keyring over src. A nil src holds no key (every Seal and
// Open fails with ErrNoKey).
func NewKeyring(src KeySource, now func() time.Time) *Keyring {
	if now == nil {
		now = time.Now
	}
	return &Keyring{src: src, now: now, grace: RotationGrace}
}

// refresh reads the source and notices a rotation.
func (k *Keyring) refresh() (string, error) {
	if k == nil || k.src == nil {
		return "", ErrNoKey
	}
	v, err := k.src.Value()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoKey, err)
	}
	if len(v) < minKeyBytes {
		return "", fmt.Errorf("%w: the key is shorter than %d bytes", ErrNoKey, minKeyBytes)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != "" && v != k.current {
		k.previous, k.prevUntil = k.current, k.now().Add(k.grace)
	}
	k.current = v
	return v, nil
}

// candidates returns the keys a record may verify under, current first.
func (k *Keyring) candidates() ([]string, error) {
	cur, err := k.refresh()
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []string{cur}
	if k.previous != "" && k.now().Before(k.prevUntil) {
		out = append(out, k.previous)
	}
	return out, nil
}

// EnvKeyFile names the rendered key file (data/secrets/probercontrol/<side>/
// password, mounted read-only as a directory so a rotation is live).
const EnvKeyFile = "PROBER_CONTROL_KEY_FILE"

// KeyringFromEnv builds the keyring both processes use. A missing or refused
// path yields a keyring with no key, so the api publishes nothing and the
// prober reads every switch OFF — the safe direction — and says why.
func KeyringFromEnv(getenv func(string) string, logf Logf) *Keyring {
	path := strings.TrimSpace(getenv(EnvKeyFile))
	if path == "" {
		if logf != nil {
			logf("prober-control: %s is not set, so no prober record can be signed or verified (render it with scripts/install.py)", EnvKeyFile)
		}
		return NewKeyring(nil, time.Now)
	}
	f, err := credfile.New(path, credfile.Options{OnStateChange: func(err error) {
		if err != nil && logf != nil {
			logf("prober-control: signing key unreadable at %s: %v", path, err)
		}
	}})
	if err != nil {
		if logf != nil {
			logf("prober-control: signing key path refused: %v", err)
		}
		return NewKeyring(nil, time.Now)
	}
	return NewKeyring(f, time.Now)
}

// envelope is the signed wire format.
//
// Payload is the record's exact JSON text carried as a JSON STRING. A string
// round-trips byte-for-byte through encoding/json whatever escaping the encoder
// applies; a json.RawMessage does not — json.Marshal compacts it and
// HTML-escapes &, < and >, so the bytes the prober verified were not the bytes
// the api signed and any record holding a URL query string, a space or an
// angle bracket failed as bad_signature (review of #310, 2026-11-21).
//
// V is the envelope version; any other is refused (ErrUnsigned), so a record
// in an older envelope shape reads OFF, never as something it is not.
type envelope struct {
	V       int    `json:"v"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// envelopeVersion is the signed-envelope wire version.
const envelopeVersion = 1

func mac(key, kind string, payload []byte) []byte {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("correlix-prober-control/" + kind + "\n")) // hash.Hash.Write never returns an error
	m.Write(payload)
	return m.Sum(nil)
}

// Seal signs payload as a record of kind under the current key.
func (k *Keyring) Seal(kind string, payload []byte) (string, error) {
	key, err := k.refresh()
	if err != nil {
		return "", err
	}
	if !json.Valid(payload) {
		return "", errors.New("probercontrol: the payload is not JSON")
	}
	b, err := json.Marshal(envelope{V: envelopeVersion, Payload: string(payload), Sig: hex.EncodeToString(mac(key, kind, payload))})
	if err != nil {
		return "", fmt.Errorf("probercontrol: seal: %w", err)
	}
	return string(b), nil
}

// Open verifies raw as a record of kind and returns its payload.
func (k *Keyring) Open(kind, raw string) ([]byte, error) {
	keys, err := k.candidates()
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil || env.V != envelopeVersion || env.Payload == "" || strings.TrimSpace(env.Sig) == "" {
		return nil, ErrUnsigned
	}
	got, err := hex.DecodeString(env.Sig)
	if err != nil {
		return nil, ErrBadSignature
	}
	payload := []byte(env.Payload)
	for _, key := range keys {
		if hmac.Equal(got, mac(key, kind, payload)) {
			if !json.Valid(payload) {
				// Signed, but not JSON: the api never seals that (Seal checks), so
				// the record is not one of ours to act on.
				return nil, ErrBadSignature
			}
			return payload, nil
		}
	}
	return nil, ErrBadSignature
}
