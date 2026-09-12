// Standalone test fixture — its own module so it never enters the backend's
// dependency graph. stdlib-only, no requires (CLAUDE.md §6).
//
// Toolchain tracks src/backend/go.mod EXACTLY (guarded by
// tests/test_toolchain_pin.py): its Dockerfile already builds on
// golang:1.26.8-alpine, and a module declaring an older Go silently compiles
// under different language semantics than everything else in the repo.
module netops/mock-nms

go 1.26.0

toolchain go1.26.8
