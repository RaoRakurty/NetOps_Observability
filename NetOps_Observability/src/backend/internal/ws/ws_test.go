package ws

import "testing"

// TestWSAcceptKey pins the RFC 6455 example so the handshake stays correct.
func TestWSAcceptKey(t *testing.T) {
	// From RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" → accept
	// "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("AcceptKey = %q, want the RFC 6455 example value", got)
	}
}
