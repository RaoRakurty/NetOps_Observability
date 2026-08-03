package oidc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// txn_test.go — the transaction store is what makes SSO state single-use and
// keeps the nonce + PKCE verifier server-side. The properties under test are
// the #135-hardening acceptance criteria: create/expire/consume, exactly one
// winner under concurrent consumption, and a bounded map that evicts only
// expired entries before refusing new logins.

func TestTxnConsumeIsSingleUse(t *testing.T) {
	st := NewTxnStore()
	now := time.Now()
	if err := st.Create("st1", "n1", "v1", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	txn, ok := st.Consume("st1", now)
	if !ok || txn.Nonce != "n1" || txn.Verifier != "v1" {
		t.Fatalf("first consume = (%+v, %v), want the stored nonce+verifier", txn, ok)
	}
	if _, ok := st.Consume("st1", now); ok {
		t.Fatal("second consume succeeded — state must be single-use")
	}
	if _, ok := st.Consume("never-created", now); ok {
		t.Fatal("consume of an unknown state succeeded")
	}
}

func TestTxnExpiryIsExact(t *testing.T) {
	st := NewTxnStore()
	now := time.Now()
	if err := st.Create("st1", "n1", "v1", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	// One nanosecond past the TTL: no grace window — skew tolerances are for
	// IdP assertions, never our own transaction lifetimes (design §7.1).
	if _, ok := st.Consume("st1", now.Add(txnTTL+time.Nanosecond)); ok {
		t.Fatal("consume succeeded past expiry — transaction TTL must be exact")
	}
	// The expired entry must also be gone (not resurrectable at an earlier now).
	if _, ok := st.Consume("st1", now); ok {
		t.Fatal("expired transaction was resurrected by a second consume")
	}
}

func TestTxnConcurrentConsumeHasOneWinner(t *testing.T) {
	st := NewTxnStore()
	now := time.Now()
	if err := st.Create("st1", "n1", "v1", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	const goroutines = 32
	var wins int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := st.Consume("st1", now); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1 — concurrent callbacks must not double-login", wins)
	}
}

func TestTxnCapEvictsExpiredThenRefuses(t *testing.T) {
	st := NewTxnStore()
	now := time.Now()
	// Fill to the cap with entries that will be expired by the time we add more.
	for i := 0; i < txnCap; i++ {
		if err := st.Create(fmt.Sprintf("old-%d", i), "n", "v", now.Add(-2*txnTTL)); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	// At cap, but everything is expired: the new login must land after eviction.
	if err := st.Create("fresh", "n", "v", now); err != nil {
		t.Fatalf("create after expired-full: %v — expired entries must be evicted first", err)
	}
	// Now fill with LIVE entries and confirm the cap actually refuses.
	for i := 1; len(st.m) < txnCap; i++ {
		if err := st.Create(fmt.Sprintf("live-%d", i), "n", "v", now); err != nil {
			t.Fatalf("live fill: %v", err)
		}
	}
	if err := st.Create("over-cap", "n", "v", now); err == nil {
		t.Fatal("create beyond a cap of live transactions succeeded — the store must be bounded")
	}
	if _, ok := st.Consume("fresh", now); !ok {
		t.Fatal("live transaction lost during cap handling")
	}
}
