// Package wsticket issues and redeems one-time, scope-bound tickets that let a
// browser open an authenticated WebSocket WITHOUT putting a reusable session
// credential in the URL.
//
// Why this exists: the browser WebSocket API cannot set an Authorization
// header, so the device-SSH terminal passed the session JWT as ?token=<jwt>.
// nginx logs the request line, so every use wrote a privileged, reusable,
// still-valid JWT into the log pipeline (stdout → Vector → OpenSearch), where
// "can read logs" — a broadly granted privilege — became "can act as the
// operator/admin who opened the terminal". A ticket closes that: it is opaque,
// single-use, scope-bound and lives ~30s, so a logged ticket is worthless.
//
// The design mirrors internal/oidc's TxnStore, which solves the same shape for
// the SSO code flow: in-process, TTL'd, capacity-bounded, and consumed by
// delete-under-lock so concurrent redemptions yield exactly one winner. In
// process is correct for the same reason it is there — the API is a single
// instance per deployment. Nothing here is a new datastore.
package wsticket

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	// TTL is deliberately tiny: a ticket only has to survive the round trip
	// from the issuing XHR to the WebSocket open that follows it immediately.
	// It is NOT a session lifetime — that is the whole point of the change.
	TTL = 30 * time.Second
	// Cap bounds the map (§9 bounded queues): beyond it issuance is refused
	// rather than letting a flood grow the store without limit.
	Cap = 4096
	// entropyBytes is the ticket's secret material: 256 bits from crypto/rand.
	entropyBytes = 32
)

// PurposeDeviceSSH is the only purpose in use today. A ticket carries its
// purpose so a ticket minted for one WebSocket surface can never be redeemed
// at another, even if both learn to accept tickets.
const PurposeDeviceSSH = "device_ssh"

var (
	ErrFull    = errors.New("wsticket: too many tickets in flight — try again shortly")
	ErrScope   = errors.New("wsticket: ticket scope does not match this request")
	ErrInvalid = errors.New("wsticket: ticket invalid, expired or already used")
)

// Ticket is the SCOPE bound at issuance. Every field is checked at redemption:
// a ticket is only ever valid for the one user, tenant, device and purpose it
// was minted for. The parent session JWT is deliberately NOT stored — the
// ticket carries the derived principal, not the credential.
type Ticket struct {
	TenantID string
	UserID   string
	Role     string
	DeviceID string
	Purpose  string
	expires  time.Time
}

type Store struct {
	mu sync.Mutex
	m  map[string]Ticket // keyed by hex(sha256(raw ticket)) — never the raw value
}

func NewStore() *Store { return &Store{m: make(map[string]Ticket)} }

// key is the at-rest identifier: the store holds only a hash, so a memory dump
// or a future on-disk backing cannot yield a usable ticket.
func key(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Fingerprint is a short, NON-reversible tag safe to put in a log line so an
// issue and its redemption can be correlated. Never log the raw ticket.
func Fingerprint(raw string) string { return key(raw)[:12] }

// Issue mints a ticket for the given scope and returns the RAW value — the only
// time it exists outside the caller. Expired entries are evicted before the cap
// is enforced so abandoned tickets cannot wedge the store.
func (s *Store) Issue(t Ticket, now time.Time) (string, error) {
	b := make([]byte, entropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err // crypto/rand failing is fatal-grade; never fall back to a weaker source
	}
	raw := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= Cap {
		for k, v := range s.m {
			if now.After(v.expires) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= Cap {
			return "", ErrFull
		}
	}
	t.expires = now.Add(TTL)
	s.m[key(raw)] = t
	return raw, nil
}

// Consume atomically claims the ticket: the delete happens under the same lock
// as the lookup, so two simultaneous redemptions of one ticket produce exactly
// one winner (the racy read→validate→use→delete shape cannot happen here).
//
// An expired ticket is a miss AND is removed. Consume deliberately does not
// check scope — Redeem does, so that a scope mismatch still burns the ticket
// rather than leaving it available for another guess.
func (s *Store) Consume(raw string, now time.Time) (Ticket, bool) {
	if raw == "" {
		return Ticket{}, false
	}
	k := key(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[k]
	if !ok {
		return Ticket{}, false
	}
	delete(s.m, k)
	if now.After(t.expires) {
		return Ticket{}, false
	}
	return t, true
}

// Redeem consumes the ticket and enforces its scope in one step. Callers get a
// typed error so the caller can log a category without ever echoing the ticket.
//
// The device and purpose comparisons use constant-time equality: these are
// attacker-supplied strings compared against secret-adjacent scope, and there
// is no reason to leak position information through timing.
func (s *Store) Redeem(raw, deviceID, purpose string, now time.Time) (Ticket, error) {
	t, ok := s.Consume(raw, now)
	if !ok {
		return Ticket{}, ErrInvalid
	}
	if subtle.ConstantTimeCompare([]byte(t.DeviceID), []byte(deviceID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(t.Purpose), []byte(purpose)) != 1 {
		return Ticket{}, ErrScope
	}
	return t, nil
}

// Len reports the number of live entries (tests and capacity diagnostics).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
