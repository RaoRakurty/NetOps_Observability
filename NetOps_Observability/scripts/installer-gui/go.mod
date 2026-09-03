// Graphical installer (correlix-setup): stdlib-only, no requires (CLAUDE.md
// §6). Toolchain tracks src/backend/go.mod EXACTLY — this module is compiled
// into the customer bundle by make-installer.sh, so a stale pin here ships a
// binary built with an unpatched Go. The 2026-09-02 raise (1.25.13 -> 1.26.8,
// x/crypto GO-2026-6354/6355) reached src/backend and CI but missed this file
// until 2026-09-03. tests/test_toolchain_pin.py now fails if they diverge.
module correlix.io/installer-gui

go 1.26.0

toolchain go1.26.8
