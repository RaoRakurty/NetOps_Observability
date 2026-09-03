#!/usr/bin/env bash
# ci-backend-guard.sh — local mirror of the blocking backend-ci gate. Run before
# every push that touches Go: go build + vet + the EXACT golangci-lint version CI
# uses (via docker, since it isn't installed locally). Exit non-zero on any
# failure so a pre-push hook can block. -race is CI-only (needs gcc, absent here).
set -uo pipefail
cd "$(dirname "$0")/../src/backend" || exit 1
GOLANGCI_VERSION="v2.12.2"   # keep in sync with .github/workflows/backend-ci.yml
echo "▶ go build ./..."; go build ./... || { echo "✗ build failed"; exit 1; }
echo "▶ go vet ./...";  go vet ./...  || { echo "✗ vet failed";   exit 1; }
echo "▶ golangci-lint $GOLANGCI_VERSION run ./... (docker, matches CI)"
# The image's own Go is older than go.mod's `toolchain go1.26.8`, so inside
# the container `go` would try to DOWNLOAD the toolchain from proxy.golang.org
# — impossible offline and broken behind TLS-intercepting egress (2026-09-03:
# "x509: certificate signed by unknown authority" blocked every push). The
# host already holds that toolchain in its module cache, so mount it read-write
# (go verifies + may write sumdb/cache entries) and keep a persistent
# golangci/go build cache so a cold run fits the timeout.
gomodcache="$(go env GOMODCACHE)"
lintcache="${XDG_CACHE_HOME:-$HOME/.cache}/golangci-lint-docker"
mkdir -p "$lintcache/golangci-lint" "$lintcache/go-build"
docker run --rm -v "$PWD:/app" -w /app -e GOFLAGS=-mod=vendor \
  -v "$gomodcache:/go/pkg/mod" -e GOMODCACHE=/go/pkg/mod \
  -v "$lintcache:/root/.cache" -e GOCACHE=/root/.cache/go-build \
  -e GOLANGCI_LINT_CACHE=/root/.cache/golangci-lint -e GOTOOLCHAIN=auto \
  "golangci/golangci-lint:$GOLANGCI_VERSION" golangci-lint run ./... --timeout 10m \
  || { echo "✗ golangci-lint failed — fix before pushing (this is the CI blocker)"; exit 1; }
echo "✓ backend CI gate passed locally"
