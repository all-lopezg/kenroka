#!/usr/bin/env bash
# Contratos de experiencia guiada: las pantallas de riesgo deben indicar qué
# ocurrirá, qué hacer fuera de esta terminal y qué respuesta conserva/restaura.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

extract_fns ui guided_active phase_guide ssh_test_command show_access_test_steps \
            ask_access_result confirm_key_preflight confirm_access

info()    { printf 'I: %s\n' "$*"; }
warn()    { printf 'W: %s\n' "$*"; }
success() { printf 'S: %s\n' "$*"; }
error()   { printf 'E: %s\n' "$*" >&2; }

UI_LANG=es
GUIDED=1
BOLD='' CYAN='' NC=''
USERNAME=admin
PUBLIC_IP=203.0.113.9
CURRENT_PORT=2222
ROLLBACK_ARMED=1
ROLLBACK_MINUTES=10
ACCESS_TEST_CONFIRMED=0
KEY_TESTED=0

echo '== estructura uniforme de las fases'
out="$(phase_guide '3/7' 'Proteger SSH' 'Protect SSH' \
    'Cerraré root y contraseña tras probar la clave.' 'I will close root and password after testing the key.' \
    'Abre otra terminal.' 'Open another terminal.' \
    'Puedes restaurar los cambios.' 'You can restore changes.')"
has 'muestra el número de fase' '[3/7]' "$out"
has 'explica qué se hará' 'Qué se hará:' "$out"
has 'pide una acción concreta' 'Qué debes hacer ahora:' "$out"
has 'explica la protección' 'Protección:' "$out"
GUIDED=0
out="$(phase_guide '3/7' x x x x x x x x)"
check 'modo experto no imprime guía larga' '' "$out"
GUIDED=1

echo '== comando y pasos de prueba SSH'
cmd="$(ssh_test_command 2222)"
has 'fuerza autenticación por clave' 'PreferredAuthentications=publickey' "$cmd"
has 'desactiva contraseña en la prueba' 'PasswordAuthentication=no' "$cmd"
has 'incluye el puerto concreto' '-p 2222 admin@203.0.113.9' "$cmd"
out="$(show_access_test_steps 2222 'Prueba posterior al firewall.')"
has 'indica otra terminal de la computadora' 'otra terminal de TU computadora' "$out"
has 'mantiene la sesión original abierta' 'ESTA terminal abierta' "$out"
has 'pide comprobar identidad y sudo' 'whoami && sudo -v && sudo -l' "$out"
has 'aclara que la consola no valida SSH' 'NO valida esta prueba SSH externa' "$out"

echo '== decisión humana sin rollback por error de formato'
out="$(printf '\ns\n' | ask_access_result 'conservar' 'keep' 'restaurar' 'restore')"; rc=$?
check 'Enter seguido de s conserva' 0 "$rc"
has 'Enter explica que aún no decide' 'Aún no se tomó ninguna decisión' "$out"
out="$(printf 'texto-equivocado\nn\n' | ask_access_result 'conservar' 'keep' 'restaurar' 'restore')"; rc=$?
check 'n restaura de forma explícita' 1 "$rc"
has 'texto desconocido se explica' "No entendí 'texto-equivocado'" "$out"

echo '== checkpoint posterior al cambio'
ACCESS_TEST_CONFIRMED=0
printf '\ns\n' > "$WORK/confirm-input"
confirm_access 2222 'Prueba posterior al firewall.' < "$WORK/confirm-input" > "$WORK/confirm-output"; rc=$?
out="$(cat "$WORK/confirm-output")"
check 's conserva después de reintentar' 0 "$rc"
check 'marca la confirmación humana' 1 "$ACCESS_TEST_CONFIRMED"
has 'distingue la prueba posterior' 'Prueba posterior al firewall.' "$out"
has 'aclara alcance real del rollback' 'SSH, UFW y Fail2ban' "$out"
has 'no exige un token oculto' '[s] $keep_es' "$(declare -f ask_access_result)"
has 'Enter sigue siendo seguro' 'Aún no se tomó ninguna decisión' "$out"

echo '== preprueba antes de cerrar SSH'
KEY_TESTED=0
printf 'n\n' > "$WORK/preflight-input"
confirm_key_preflight 2222 < "$WORK/preflight-input" > "$WORK/preflight-output"; rc=$?
out="$(cat "$WORK/preflight-output")"
check 'n antes del cierre mantiene el acceso abierto' 1 "$rc"
check 'no marca una clave no probada' 0 "$KEY_TESTED"
has 'declara que el cierre aún no ocurre' 'todavía no cerraré root ni el acceso con contraseña' "$out"
has 'da el siguiente resultado comprensible' 'No cerraré root ni la contraseña' "$out"

summary
