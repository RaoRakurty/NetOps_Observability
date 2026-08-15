package wsticket

import (
	"sync"
	"testing"
	"time"
)

func mk(dev string) Ticket {
	return Ticket{TenantID: "acme", UserID: "op@acme", Role: "operator", DeviceID: dev, Purpose: PurposeDeviceSSH}
}

// WS-2 (store half): a freshly issued ticket redeems once for its scope.
func TestIssueThenRedeemOnce(t *testing.T) {
	s := NewStore()
	now := time.Now()
	raw, err := s.Issue(mk("dev-1"), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if raw == "" {
		t.Fatal("empty ticket")
	}
	got, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if got.UserID != "op@acme" || got.TenantID != "acme" {
		t.Fatalf("scope not preserved: %+v", got)
	}
	if s.Len() != 0 {
		t.Fatalf("redeemed ticket still present: len=%d", s.Len())
	}
}

// WS-4: a redeemed ticket cannot be redeemed again.
func TestReplayDenied(t *testing.T) {
	s := NewStore()
	now := time.Now()
	raw, _ := s.Issue(mk("dev-1"), now)
	if _, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, now); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, now); err != ErrInvalid {
		t.Fatalf("replay must be ErrInvalid, got %v", err)
	}
}

// WS-5: exactly one of N concurrent redemptions of one ticket wins.
func TestConcurrentRedemptionExactlyOneWinner(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		s := NewStore()
		now := time.Now()
		raw, _ := s.Issue(mk("dev-1"), now)
		const goroutines = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, now); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			t.Fatalf("trial %d: %d winners, want exactly 1", trial, wins)
		}
	}
}

// WS-6: a ticket past its TTL is a miss (and does not linger).
func TestExpiry(t *testing.T) {
	s := NewStore()
	now := time.Now()
	raw, _ := s.Issue(mk("dev-1"), now)
	later := now.Add(TTL + time.Second)
	if _, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, later); err != ErrInvalid {
		t.Fatalf("expired ticket must be ErrInvalid, got %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("expired ticket not evicted on read: len=%d", s.Len())
	}
}

// WS-7: a ticket bound to device-A is refused at device-B — and is still burned.
func TestWrongDeviceDenied(t *testing.T) {
	s := NewStore()
	now := time.Now()
	raw, _ := s.Issue(mk("dev-A"), now)
	if _, err := s.Redeem(raw, "dev-B", PurposeDeviceSSH, now); err != ErrScope {
		t.Fatalf("cross-device redeem must be ErrScope, got %v", err)
	}
	// A scope mismatch consumes the ticket: a second guess at the right device
	// must not succeed.
	if _, err := s.Redeem(raw, "dev-A", PurposeDeviceSSH, now); err != ErrInvalid {
		t.Fatalf("scope-rejected ticket must still be burned, got %v", err)
	}
}

// WS-9: a ticket minted for another purpose is refused for device SSH.
func TestWrongPurposeDenied(t *testing.T) {
	s := NewStore()
	now := time.Now()
	tk := mk("dev-1")
	tk.Purpose = "some_other_ws"
	raw, _ := s.Issue(tk, now)
	if _, err := s.Redeem(raw, "dev-1", PurposeDeviceSSH, now); err != ErrScope {
		t.Fatalf("wrong-purpose redeem must be ErrScope, got %v", err)
	}
}

// Ticket material is 256-bit, base64url, and unique across issues.
func TestTicketEntropyAndUniqueness(t *testing.T) {
	s := NewStore()
	now := time.Now()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		raw, err := s.Issue(mk("d"), now)
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		// 32 bytes → 43 base64url chars (unpadded).
		if len(raw) != 43 {
			t.Fatalf("ticket length = %d, want 43 (256 bits base64url)", len(raw))
		}
		if seen[raw] {
			t.Fatalf("duplicate ticket at %d", i)
		}
		seen[raw] = true
		// Immediately consume so the cap is never the reason for a miss here.
		if _, err := s.Redeem(raw, "d", PurposeDeviceSSH, now); err != nil {
			t.Fatalf("redeem %d: %v", i, err)
		}
	}
}

// Fingerprint is stable, non-reversible, and short; the raw ticket is not a
// substring of it.
func TestFingerprintIsSafeForLogs(t *testing.T) {
	raw := "abcdefABCDEF0123456789-_aaaaaaaaaaaaaaaaaaaa"
	fp := Fingerprint(raw)
	if len(fp) != 12 {
		t.Fatalf("fingerprint length = %d, want 12", len(fp))
	}
	if fp == raw || len(fp) >= len(raw) {
		t.Fatal("fingerprint must be shorter than and unequal to the raw ticket")
	}
	if Fingerprint(raw) != fp {
		t.Fatal("fingerprint not stable")
	}
}

// The cap is enforced (bounded store) and refuses rather than growing.
func TestCapRefuses(t *testing.T) {
	s := NewStore()
	now := time.Now()
	for i := 0; i < Cap; i++ {
		if _, err := s.Issue(mk("d"), now); err != nil {
			t.Fatalf("issue %d under cap: %v", i, err)
		}
	}
	if _, err := s.Issue(mk("d"), now); err != ErrFull {
		t.Fatalf("over-cap issue must be ErrFull, got %v", err)
	}
	// Once the live entries expire, issuance recovers (eviction path).
	if _, err := s.Issue(mk("d"), now.Add(TTL+time.Second)); err != nil {
		t.Fatalf("issue after expiry should evict and succeed: %v", err)
	}
}
