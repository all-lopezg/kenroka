#!/usr/bin/env bash
# Runner de pruebas de kenroka.
#
#   tests/run.sh unit      lógica pura con stubs (rápido, sin Docker)
#   tests/run.sh docker    escenarios end-to-end en contenedores Ubuntu 24.04
#   tests/run.sh all       ambos (default)
#   tests/run.sh unit -k   para en el primer fallo
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-all}"
[[ $# -gt 1 && "$2" == "-k" ]] && KEEP_ON_FAIL=1 || KEEP_ON_FAIL=0

RC=0
run_suite() {
    local name="$1"; shift
    local f
    printf '\n\033[1m▶ %s\033[0m\n' "$name"
    for f in "$@"; do
        if [[ ! -x "$f" ]]; then chmod +x "$f" 2>/dev/null || true; fi
        if ! bash "$f"; then
            RC=1
            printf '\033[31m  suite %s falló en %s\033[0m\n' "$name" "$(basename "$f")"
            [[ $KEEP_ON_FAIL -eq 1 ]] && return 1
        fi
    done
    return 0
}

case "$MODE" in
    unit)
        run_suite "unit" "$HERE"/unit/[0-9]*.sh || true
        ;;
    docker)
        run_suite "docker" "$HERE/docker/run.sh" || true
        ;;
    all)
        run_suite "unit" "$HERE"/unit/[0-9]*.sh || true
        run_suite "docker" "$HERE/docker/run.sh" || true
        ;;
    *)
        echo "Modo desconocido: $MODE (usa unit | docker | all)" >&2
        exit 2
        ;;
esac

echo
if [[ $RC -eq 0 ]]; then
    printf '\033[32mPRUEBAS OK\033[0m\n'
else
    printf '\033[31mHAY PRUEBAS FALLANDO\033[0m\n'
fi
exit $RC
