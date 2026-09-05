package juniper

// s3put_test.go — the hand-rolled SigV4 signer. This is the highest-risk code
// in the package: a wrong signature means an upload that fails against real S3
// and cannot be caught by a fake. The tests pin the parts of the algorithm that
// a fake CANNOT catch — the credential scope, the signed-header set and its
// sort order, the single RFC 3986 path escaping, the fact that the secret and
// the session token actually enter the computation, and determinism (the same
// inputs must always sign identically).

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignV4ProducesAStableSignatureForAKnownRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	// PutObject always sets a Content-Type before signing, so the fixture does too.
	req.Header.Set("Content-Type", "application/zip")
	tok := UploadToken{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Bucket:          "examplebucket",
		ObjectKey:       "test.txt",
	}
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256("")

	if err := signV4(req, tok, payloadHash, when); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request") {
		t.Fatalf("credential scope is wrong: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("signed headers are wrong or unsorted: %q", auth)
	}
	if req.Header.Get("X-Amz-Date") != "20130524T000000Z" {
		t.Errorf("X-Amz-Date = %q", req.Header.Get("X-Amz-Date"))
	}
	if req.Header.Get("X-Amz-Content-Sha256") != payloadHash {
		t.Errorf("payload hash header = %q", req.Header.Get("X-Amz-Content-Sha256"))
	}
	// Deterministic: the same inputs must sign identically. A drifting signature
	// would be a silent upload failure against real S3.
	req2, _ := http.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req2.Header.Set("Content-Type", "application/zip")
	if err := signV4(req2, tok, payloadHash, when); err != nil {
		t.Fatal(err)
	}
	if req2.Header.Get("Authorization") != auth {
		t.Fatal("the signature is not deterministic")
	}
	// A different secret must produce a different signature (the key derivation
	// actually consumes it).
	other := tok
	other.SecretAccessKey = "another-secret"
	req3, _ := http.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req3.Header.Set("Content-Type", "application/zip")
	if err := signV4(req3, other, payloadHash, when); err != nil {
		t.Fatal(err)
	}
	if req3.Header.Get("Authorization") == auth {
		t.Fatal("the signature did not change with the secret")
	}
}

func TestSignV4IncludesTheSessionTokenWhenPresent(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "https://b.s3.us-west-2.amazonaws.com/k", nil)
	tok := UploadToken{AccessKeyID: "ASIA", SecretAccessKey: "s", SessionToken: "sts-session",
		Region: "us-west-2", Bucket: "b", ObjectKey: "k"}
	if err := signV4(req, tok, "abc", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "sts-session" {
		t.Fatal("the STS session token must be sent")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatal("the session token must be SIGNED, not just sent")
	}
}

func TestS3PathEscapingIsSingleAndRFC3986(t *testing.T) {
	for in, want := range map[string]string{
		"simple.zip":            "simple.zip",
		"a/b/c.zip":             "a/b/c.zip",
		"with space.zip":        "with%20space.zip",
		"plus+and&amp.zip":      "plus%2Band%26amp.zip",
		"tilde~dash-dot._ok":    "tilde~dash-dot._ok",
		"already%20encoded.zip": "already%2520encoded.zip", // single-encode: % becomes %25
	} {
		if got := s3EscapePath(in); got != want {
			t.Errorf("s3EscapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHashPayloadRefusesASizeMismatch(t *testing.T) {
	// A bundle that does not match its declared size would be signed for one
	// length and sent with another; failing loudly beats truncating evidence.
	_, err := hashPayload(func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }, 10)
	if err == nil || !strings.Contains(err.Error(), "declared") {
		t.Fatalf("err = %v, want a size-mismatch refusal", err)
	}
	got, err := hashPayload(func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }, 3)
	if err != nil {
		t.Fatal(err)
	}
	// sha256("abc")
	if got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("digest = %q", got)
	}
}
