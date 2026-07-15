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
docker run --rm -v "$PWD:/app" -w /app -e GOFLAGS=-mod=vendor \
  "golangci/golangci-lint:$GOLANGCI_VERSION" golangci-lint run ./... --timeout 6m \
  || { echo "✗ golangci-lint failed — fix before pushing (this is the CI blocker)"; exit 1; }
echo "✓ backend CI gate passed locally"
