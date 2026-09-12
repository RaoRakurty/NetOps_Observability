// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package juniper

// s3endpoint_test.go — the upload target is built from strings the VENDOR sent,
// so it is built the way Cisco's cxdBase builds its upload host: against a
// published character set, with the domain pinned.
//
// The bundle being PUT is the customer's redacted evidence, signed with STS
// credentials. Sending it anywhere but S3 is the thing this refuses.

import (
	"errors"
	"strings"
	"testing"
)

// TestS3EndpointCannotBeReparentedByTheVendorsBucketOrRegion is the regression.
// Every one of these used to produce a URL whose HOST was not S3.
func TestS3EndpointCannotBeReparentedByTheVendorsBucketOrRegion(t *testing.T) {
	c := &Client{}
	hostile := []struct{ name, bucket, region string }{
		{"a slash makes the rest of the host a path", "attacker.example.com/x", "us-east-1"},
		{"a hash truncates the host", "evil.example.com#", "us-east-1"},
		{"a question mark truncates the host", "evil.example.com?", "us-east-1"},
		{"an at sign moves the host into userinfo", "evil.example.com@x", "us-east-1"},
		{"a colon reparents the port", "evil.example.com:8080", "us-east-1"},
		{"a backslash", "evil.example.com\\x", "us-east-1"},
		{"the region carries the slash instead", "bundles", "us-east-1/x.attacker.example.com"},
		{"the region carries the hash", "bundles", "us-east-1#"},
		{"an empty bucket", "", "us-east-1"},
		{"an empty region", "bundles", ""},
		{"whitespace is not a bucket", "  bundles  ", "us-east-1"},
		{"uppercase is not a bucket name", "Bundles", "us-east-1"},
		{"a bucket may not end in a dot", "bundles.", "us-east-1"},
		{"a bucket may not start with a dot", ".bundles", "us-east-1"},
		{"no double dots", "bun..dles", "us-east-1"},
		{"too short", "ab", "us-east-1"},
		{"too long", strings.Repeat("a", 64), "us-east-1"},
	}
	for _, h := range hostile {
		got, err := c.s3Endpoint(UploadToken{Bucket: h.bucket, Region: h.region, ObjectKey: "k/bundle.zip"})
		if err == nil {
			t.Errorf("%s: s3Endpoint accepted it and produced %q", h.name, got)
			continue
		}
		if !errors.Is(err, ErrRequestInvalid) {
			t.Errorf("%s: err = %v, want ErrRequestInvalid", h.name, err)
		}
		if got != "" {
			t.Errorf("%s: a refused endpoint still returned %q", h.name, got)
		}
	}
}

// TestS3EndpointBuildsTheRealThing keeps the happy path exact: the same URL the
// AWS virtual-hosted style produces, on the pinned domain, with the key escaped.
func TestS3EndpointBuildsTheRealThing(t *testing.T) {
	c := &Client{}
	got, err := c.s3Endpoint(UploadToken{
		Bucket: "juniper-sr-uploads", Region: "us-west-2", ObjectKey: "sr/2026/bundle name.zip",
	})
	if err != nil {
		t.Fatalf("a legitimate token was refused: %v", err)
	}
	want := "https://juniper-sr-uploads.s3.us-west-2.amazonaws.com/sr/2026/bundle%20name.zip"
	if got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "https://") || !strings.Contains(got, ".amazonaws.com/") {
		t.Fatalf("the endpoint left the pinned domain: %q", got)
	}
	// A bucket with dots is legal AWS naming and must still work.
	if _, err := c.s3Endpoint(UploadToken{Bucket: "a.b.c", Region: "eu-central-1", ObjectKey: "k"}); err != nil {
		t.Fatalf("a dotted bucket name was refused: %v", err)
	}
}

// TestS3EndpointOverrideStillPointsAtTheTestServer — the fake-server seam is
// untouched by the pinning, so the flow tests keep working.
func TestS3EndpointOverrideStillPointsAtTheTestServer(t *testing.T) {
	c := &Client{baseOverride: "http://127.0.0.1:9/fake/"}
	got, err := c.s3Endpoint(UploadToken{Bucket: "anything at all", Region: "", ObjectKey: "k/b.zip"})
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if got != "http://127.0.0.1:9/fake/k/b.zip" {
		t.Fatalf("override endpoint = %q", got)
	}
}
