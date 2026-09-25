#!/usr/bin/env bash
# 11 · Detección automática de idioma: es* del sistema → español, resto → inglés;
# --lang fuerza el idioma sin importar el entorno.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

help_out() { # help_out <env-assignments> <flags...> -> stdout de --help
    local env="$1"; shift
    on_server "env $env bash $SCRIPT $* 2>&1"
}

echo "  ayuda según idioma"
expect_match "--lang es muestra Uso:" "^Uso:" "$(help_out '' --lang es --help)"
expect_match "--lang en muestra Usage:" "^Usage:" "$(help_out '' --lang en --help)"
expect_match "LANG=es_ES detecta español" "^Uso:" "$(help_out 'LANG=es_ES.UTF-8' --help)"
expect_match "LANG=es_MX también detecta español" "^Uso:" "$(help_out 'LANG=es_MX.UTF-8' --help)"
expect_match "LANG=C cae en inglés" "^Usage:" "$(help_out 'LANG=C' --help)"
expect_match "sin locale cae en inglés" "^Usage:" "$(help_out 'LANG= LC_ALL= LC_MESSAGES=' --help)"
expect_match "LC_MESSAGES manda sobre LANG" "^Uso:" "$(help_out 'LANG=C LC_MESSAGES=es_AR.UTF-8' --help)"
expect_match "--lang gana a la detección" "^Uso:" "$(help_out 'LANG=C' --lang es --help)"

echo "  validación del flag"
out="$(help_out '' --lang fr --help)"
expect_eq "--lang fr se rechaza" 1 "$?"
expect_match "explica los valores válidos" "es|en" "$out"

echo "  el token de confirmación no se traduce"
for lang in es en; do
    n="$(on_server "grep -c '\"acceso-ok\"' $SCRIPT")"
    if [[ "${n:-0}" -ge 1 ]]; then
        ok "--lang $lang conserva el token acceso-ok en el código"
    else
        bad "--lang $lang perdió el token acceso-ok del código"
    fi
done

echo "  corrida completa en inglés (cabeceras y resumen, no solo --help)"
start_admin_session
out="$(run_vps --lang en --non-interactive --skip-lockdown --yes \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
expect_eq "termina sin errores" 0 "$rc"
expect_match "la fase 1 se anuncia en inglés" "PHASE 1: Create a usable sudo user" "$out"
expect_match "el resumen final está en inglés" "STATE SUMMARY" "$out"
expect_match "explica en inglés quién manda el puerto" "drives the port" "$out"
expect_nomatch "no se escapa español en las cabeceras" "FASE 1:" "$out"

scenario_summary
