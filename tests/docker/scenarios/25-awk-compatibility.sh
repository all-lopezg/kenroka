#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/lib.sh"
out="$(on_server 'bash /tests/awk-regressions.sh' 2>&1)"; rc=$?
printf '%s\n' "$out" | sed 's/^/    /'
expect_eq 'helper compatible con ambas implementaciones awk' 0 "$rc"
expect_match 'reproduce exactamente el fallo anterior de GNU awk' 'fallo-anterior-reproducido: OK' "$out"
expect_match 'instala el include correctamente con GNU awk' 'gawk-compatible: OK' "$out"
expect_match 'conserva compatibilidad con mawk' 'mawk-compatible: OK' "$out"
scenario_summary
