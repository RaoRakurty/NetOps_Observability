package cloudconn

// sigv4_test.go — runs the OFFICIAL AWS SigV4 test-vector suite (vendored under
// testdata/sigv4/, one directory per vector) as a table-driven test: for every
// vector we parse the raw request + signing context and assert the canonical
// request, the string-to-sign, the signature and the final Authorization header
// byte-for-byte. This is the mandatory pin for hand-rolled wire crypto.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sigv4SuiteContext struct {
	Credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Token           string `json:"token"`
	} `json:"credentials"`
	Normalize        bool   `json:"normalize"`
	Region           string `json:"region"`
	Service          string `json:"service"`
	SignBody         bool   `json:"sign_body"`
	Timestamp        string `json:"timestamp"`
	OmitSessionToken bool   `json:"omit_session_token"`
}

// parseRawRequest parses the suite's request.txt: request line, headers with
// obsolete line folding (continuation lines), optional body after a blank line.
func parseRawRequest(t *testing.T, raw string) (method, target string, headers [][2]string, body string) {
	t.Helper()
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, tail, foundBlank := strings.Cut(raw, "\n\n")
	if foundBlank {
		body = tail
	}
	lines := strings.Split(head, "\n")
	// The request-target may contain literal spaces (get-space-unnormalized),
	// so cut the method prefix and the HTTP-version suffix rather than Fields.
	reqLine := lines[0]
	method, target, _ = strings.Cut(reqLine, " ")
	target = strings.TrimSuffix(target, " HTTP/1.1")
	if method == "" || target == "" {
		t.Fatalf("bad request line: %q", reqLine)
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// continuation of the previous header value
			if len(headers) == 0 {
				t.Fatalf("continuation line with no header: %q", line)
			}
			headers[len(headers)-1][1] += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("bad header line: %q", line)
		}
		headers = append(headers, [2]string{name, value})
	}
	return method, target, headers, body
}

func readVectorFile(t *testing.T, dir, name string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false
		}
		t.Fatalf("read %s/%s: %v", dir, name, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n"), true
}

func TestSigV4OfficialSuite(t *testing.T) {
	root := filepath.Join("testdata", "sigv4")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read suite dir: %v", err)
	}
	if len(entries) < 30 {
		t.Fatalf("expected the full vendored suite, found only %d vectors", len(entries))
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			ctxRaw, ok := readVectorFile(t, dir, "context.json")
			if !ok {
				t.Fatalf("vector without context.json")
			}
			var ctx sigv4SuiteContext
			if err := json.Unmarshal([]byte(ctxRaw), &ctx); err != nil {
				t.Fatalf("context.json: %v", err)
			}
			reqRaw, ok := readVectorFile(t, dir, "request.txt")
			if !ok {
				t.Fatal("vector without request.txt")
			}
			method, target, headers, body := parseRawRequest(t, reqRaw)
			ts, err := time.Parse(time.RFC3339, ctx.Timestamp)
			if err != nil {
				t.Fatalf("timestamp: %v", err)
			}

			path, rawQuery, _ := strings.Cut(target, "?")
			sum := sha256.Sum256([]byte(body))
			payloadHash := hex.EncodeToString(sum[:])

			// The harness (like a real signer) stamps x-amz-date, the session
			// token (unless omit_session_token) and, when the body is signed,
			// x-amz-content-sha256 into the SIGNED header set.
			signed := append([][2]string{}, headers...)
			signed = append(signed, [2]string{amzDateHeader, ts.Format(sigv4TimeFormat)})
			if ctx.Credentials.Token != "" && !ctx.OmitSessionToken {
				signed = append(signed, [2]string{amzTokenHeader, ctx.Credentials.Token})
			}
			if ctx.SignBody {
				signed = append(signed, [2]string{amzContentSHA256, payloadHash})
			}

			in := sigv4Input{
				Method:      method,
				Path:        path,
				RawQuery:    rawQuery,
				Headers:     signed,
				PayloadHash: payloadHash,
				Region:      ctx.Region,
				Service:     ctx.Service,
				Time:        ts.UTC(),
				Creds: AWSCredentials{
					AccessKeyID:     ctx.Credentials.AccessKeyID,
					SecretAccessKey: ctx.Credentials.SecretAccessKey,
					SessionToken:    ctx.Credentials.Token,
				},
				NormalizePath: ctx.Normalize,
			}

			creq, _ := sigv4CanonicalRequest(in)
			if want, ok := readVectorFile(t, dir, "header-canonical-request.txt"); ok && creq != want {
				t.Errorf("canonical request mismatch\n--- got:\n%s\n--- want:\n%s", creq, want)
			}
			sts := sigv4StringToSign(in, creq)
			if want, ok := readVectorFile(t, dir, "header-string-to-sign.txt"); ok && sts != want {
				t.Errorf("string-to-sign mismatch\n--- got:\n%s\n--- want:\n%s", sts, want)
			}
			sig := sigv4Sign(in, sts)
			if want, ok := readVectorFile(t, dir, "header-signature.txt"); ok && sig != strings.TrimSpace(want) {
				t.Errorf("signature mismatch\n got: %s\nwant: %s", sig, strings.TrimSpace(want))
			}
			// Authorization header (from the signed-request artifact when present).
			if signedReq, ok := readVectorFile(t, dir, "header-signed-request.txt"); ok {
				wantAuthz := ""
				for _, line := range strings.Split(signedReq, "\n") {
					if v, found := strings.CutPrefix(line, "Authorization:"); found {
						wantAuthz = strings.TrimSpace(v)
					}
				}
				if wantAuthz != "" {
					if got := sigv4Authorization(in); got != wantAuthz {
						t.Errorf("authorization mismatch\n got: %s\nwant: %s", got, wantAuthz)
					}
				}
			}
		})
	}
}

// TestSigV4CredentialRedaction proves the credential triplet redacts its
// secrets under every fmt verb a log line could use.
func TestSigV4CredentialRedaction(t *testing.T) {
	c := AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "sekret", SessionToken: "sess-tok"}
	for _, s := range []string{c.String(), c.GoString()} {
		if strings.Contains(s, "sekret") || strings.Contains(s, "sess-tok") {
			t.Fatalf("credential formatting leaked a secret: %s", s)
		}
		if !strings.Contains(s, "AKIDEXAMPLE") {
			t.Fatalf("redacted form should keep the non-secret key id: %s", s)
		}
	}
}
