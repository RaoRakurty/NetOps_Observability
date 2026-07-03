// Standalone test fixture — its own module so it never enters the backend's
// dependency graph. stdlib-only, no requires (CLAUDE.md §6).
module netops/mock-nms

go 1.25
