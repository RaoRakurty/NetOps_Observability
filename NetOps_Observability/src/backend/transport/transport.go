// Package transport groups the low-level connection helpers each
// collector relies on. Keeping them here makes it easy to share retry
// behaviour, TLS configuration, and connection pooling across protocols.
package transport

import (
	"context"
	"time"
)

// Dialer is the common contract — open a session to a device, return a
// handle the caller can use, or surface an error. Concrete implementations
// (SNMP, gRPC, SSH/NETCONF, HTTP) live in sibling files.
type Dialer interface {
	Name() string
	Dial(ctx context.Context, target string) (Session, error)
}

// Session is intentionally a black-box handle. Callers in each collector
// type-assert to the protocol-specific session they need.
type Session interface {
	Close() error
}

// DefaultTimeout is applied when callers don't set their own deadline.
const DefaultTimeout = 5 * time.Second
