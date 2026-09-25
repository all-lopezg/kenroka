#!/usr/bin/env bash
# Arnés de pruebas unitarias: extrae funciones de top-level de secure-vps.sh y
# las corre con stubs, sin tocar un sistema real.
#
# Por qué extraer en vez de sourcear el script: secure-vps.sh termina con
# main "$@", así que cargarlo entero ejecutaría el endurecimiento.
#

set -uo pipefail

# Los asserts de texto esperan mensajes en español.
UI_LANG=es

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/secure-vps.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kenroka-unit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [[ ! -f "$SRC" ]]; then
    echo "no encuentro $SRC" >&2
    exit 2
fi

# extract_fns <funciones...>  ->  escribe el archivo extraído y lo carga
extract_fns() {
    local fn
    : > "$WORK/extracted.sh"
    for fn in "$@"; do
        awk -v fn="$fn" '
            !inside && $0 ~ "^"fn"\\(\\)" { inside=1; print; if ($0 ~ /\}[[:space:]]*$/) inside=0; next }
            inside { print; if (/^}/) inside=0 }
        ' "$SRC" >> "$WORK/extracted.sh"
        printf '\n' >> "$WORK/extracted.sh"
    done
    if ! grep -q . "$WORK/extracted.sh"; then
        echo "  no pude extraer ninguna función: $*" >&2
        exit 2
    fi
    # shellcheck disable=SC1091
    source "$WORK/extracted.sh"
}

# --- asserts ---
PASS=0
FAIL=0
ok()      { PASS=$((PASS+1)); printf '  ok    %s\n' "$*"; }
bad()     { FAIL=$((FAIL+1)); printf '  FALLA %s\n' "$*"; }
check()   { if [[ "$3" == "$2" ]]; then ok "$1"; else bad "$1 | esperado='$2' real='$3'"; fi; }
has()     { case "$3" in *"$2"*) ok "$1";; *) bad "$1 | falta '$2' en: $3";; esac; }
hasnt()   { case "$3" in *"$2"*) bad "$1 | sobra '$2'";; *) ok "$1";; esac; }

summary() {
    printf '\n%s: %d ok, %d fallas\n' "$(basename "$0")" "$PASS" "$FAIL"
    [[ $FAIL -eq 0 ]]
}

# silence() <fn>  -> corre la función descartando su salida (se usa para
# funciones que imprimen por contrato y al test solo le importa el exit code)
silence() { "$@" > "$WORK/silence.out" 2>&1; }
