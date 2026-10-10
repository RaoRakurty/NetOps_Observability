#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# ci-backend-guard.sh — local mirror of the blocking backend-ci gate. Run before
# every push that touches Go: go build + vet + the EXACT golangci-lint version CI
# uses (via docker, since it isn't installed locally). Exit non-zero on any
# failure so a pre-push hook can block. -race is CI-only (needs gcc, absent here).
set -uo pipefail
cd "$(dirname "$0")/../src/backend" || exit 1
GOLANGCI_VERSION="v2.14.0"   # keep in sync with .github/workflows/backend-ci.yml
echo "▶ go build ./..."; go build ./... || { echo "✗ build failed"; exit 1; }
echo "▶ go vet ./...";  go vet ./...  || { echo "✗ vet failed";   exit 1; }
echo "▶ golangci-lint $GOLANGCI_VERSION run ./... (docker, matches CI)"
# The image's own Go is older than go.mod's `toolchain` line, so inside
# the container `go` would try to DOWNLOAD the toolchain from proxy.golang.org
# — impossible offline and broken behind TLS-intercepting egress (2026-09-03:
# "x509: certificate signed by unknown authority" blocked every push). The
# host already holds that toolchain in its module cache, so mount it read-write
# (go verifies + may write sumdb/cache entries) and keep a persistent
# golangci/go build cache so a cold run fits the timeout.
# The cached toolchain is still VERIFIED against sum.golang.org from inside the
# container (2026-10-10, go1.26.9: "initializing sumdb.Client ... x509:
# certificate signed by unknown authority"). Keep verification ON and hand the
# container the host's CA bundle, which is what the host's own `go` already
# trusts; never GOSUMDB=off / GONOSUMDB to get past it.
gomodcache="$(go env GOMODCACHE)"
lintcache="${XDG_CACHE_HOME:-$HOME/.cache}/golangci-lint-docker"
mkdir -p "$lintcache/golangci-lint" "$lintcache/go-build"
ca_args=()
host_ca="/etc/ssl/certs/ca-certificates.crt"
if [ -r "$host_ca" ]; then
  ca_args=(-v "$host_ca:/etc/ssl/certs/ca-certificates.crt:ro" -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt)
else
  echo "⚠ $host_ca not readable — the container uses its own CA store; behind TLS interception the toolchain sumdb check will fail" >&2
fi
docker run --rm -v "$PWD:/app" -w /app -e GOFLAGS=-mod=vendor \
  "${ca_args[@]}" \
  -v "$gomodcache:/go/pkg/mod" -e GOMODCACHE=/go/pkg/mod \
  -v "$lintcache:/root/.cache" -e GOCACHE=/root/.cache/go-build \
  -e GOLANGCI_LINT_CACHE=/root/.cache/golangci-lint -e GOTOOLCHAIN=auto \
  "golangci/golangci-lint:$GOLANGCI_VERSION" golangci-lint run ./... --timeout 10m \
  || { echo "✗ golangci-lint failed — fix before pushing (this is the CI blocker)"; exit 1; }
echo "✓ backend CI gate passed locally"
