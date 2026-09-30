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
has 'permite claves del agente en la prueba' 'IdentitiesOnly=no' "$cmd"
has 'desactiva teclado interactivo' 'KbdInteractiveAuthentication=no' "$cmd"
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
has 'explica el fallo de autenticación' 'Permission denied' "$out"
has 'indica cómo volver a probar' '1.4 repite la prueba' "$out"
has 'detiene recorrido antes de UFW' 'antes de cambiar SSH o activar UFW' "$out"
has 'da el siguiente resultado comprensible' 'No cerraré root ni la contraseña' "$out"

echo '== sugerencia de puerto disponible'
extract_fns suggest_ssh_port
CURRENT_PORT=22
ss() { printf '%s\n' 'LISTEN 0 128 0.0.0.0:22'; }
check 'sugiere un puerto diferente de 2222' 24022 "$(suggest_ssh_port)"
ss() { printf '%s\n' 'LISTEN 0 128 0.0.0.0:24022' 'UNCONN 0 0 [::]:24023'; }
check 'evita TCP y UDP ocupados' 24024 "$(suggest_ssh_port)"
CURRENT_PORT=24024
check 'evita también el puerto actual' 24025 "$(suggest_ssh_port)"
ss() { return 1; }
suggest_ssh_port > /dev/null; rc=$?
check 'no sugiere si no puede leer escuchas' 1 "$rc"
CURRENT_PORT=22
ss() { local p; for ((p=24022; p<24122; p++)); do printf 'LISTEN 0 128 0.0.0.0:%s\n' "$p"; done; }
suggest_ssh_port > /dev/null; rc=$?
check 'rango agotado no propone un puerto ocupado' 1 "$rc"

echo '== corrección de entradas en la fase de puerto'
extract_fns fase_7_change_port port_in_use_by_other is_port
header() { :; }
detect_ssh_activation() { :; }
ssh_activation_summary() { :; }
current_ssh_port() { printf '22'; }
confirm() { return 0; }
snapshot_state() { printf 'SNAPSHOT_REQUESTED\n'; return 1; }
ss() { printf '%s\n' 'LISTEN 0 128 0.0.0.0:24022'; }
NON_INTERACTIVE=0 ASSUME_YES=0 ON_CONSOLE=0 ALLOW_LOCKDOWN=0 NEW_PORT=''
out="$(printf 'texto\n24022\n24024\n' | fase_7_change_port)"; rc=$?
has 'permite corregir un número inválido' 'Escribe un número entre 1 y 65535' "$out"
has 'permite corregir un puerto ocupado' 'El puerto 24022 está ocupado' "$out"
has 'recuerda el cortafuegos del proveedor' 'cortafuegos externo' "$out"
has 'solo llega a preparar cambios tras una entrada válida' 'SNAPSHOT_REQUESTED' "$out"
# El stub de snapshot falla intencionadamente: nunca se cambia SSH aquí.
check 'la prueba se detiene antes de modificar SSH' 1 "$rc"
NEW_PORT=''
out="$(fase_7_change_port < /dev/null)"; rc=$?
check 'EOF conserva el puerto sin error' 0 "$rc"
hasnt 'EOF no prepara cambios' 'SNAPSHOT_REQUESTED' "$out"

echo '== limpieza de pantalla'
NON_INTERACTIVE=0
check 'sin terminal no escribe escapes' '' "$(clear_screen)"
# PTY real para comprobar lo que ve el usuario, sin modificar el servidor.
declare -f ui_visual clear_screen > "$WORK/clear-screen.sh"
python3 - "$WORK/clear-screen.sh" <<'PTY' > "$WORK/clear-output"
import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execvp('bash', ['bash', '-c', 'source "$1"; TERM=xterm; NON_INTERACTIVE=0; clear_screen; NON_INTERACTIVE=1; clear_screen', '_', sys.argv[1]])
out = b''
while True:
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
PTY
check 'limpia y mueve cursor solo en modo interactivo' $'\033[2J\033[H' "$(cat "$WORK/clear-output")"

echo '== una preprueba fallida detiene cambios y recorrido'
extract_fns fase_3_harden_ssh run_all_fases phase_label
existing_key_present() { return 0; }
log() { :; }
snapshot_state() { printf 'UNEXPECTED_SNAPSHOT\n'; return 1; }
NON_INTERACTIVE=0 ON_CONSOLE=0 OPT_SKIP_LOCKDOWN=0 ALLOW_LOCKDOWN=0
for ready in 0 1; do
    KEY_READY=$ready KEY_TESTED=0
    fase_3_harden_ssh < "$WORK/preflight-input" > "$WORK/phase-preflight-output"; rc=$?
    out="$(cat "$WORK/phase-preflight-output")"
    check "clave preparada=$ready: fase detenida" 1 "$rc"
    check "clave preparada=$ready: sigue sin probar" 0 "$KEY_TESTED"
    hasnt "clave preparada=$ready: no prepara cambios" 'UNEXPECTED_SNAPSHOT' "$out"
    check "clave preparada=$ready: resultado pendiente" 'Pendiente; la prueba SSH no fue confirmada' "$UI_PHASE_RESULT"
done
fase_1_user() { :; }
fase_2_ssh_key() { KEY_READY=1; KEY_TESTED=0; }
fase_2b_updates() { :; }
fase_4_ufw() { printf 'UNEXPECTED_UFW\n'; }
out="$(run_all_fases < "$WORK/preflight-input")"; rc=$?
check 'la guía completa también se detiene' 1 "$rc"
hasnt 'la guía no alcanza UFW tras prueba fallida' 'UNEXPECTED_UFW' "$out"
hasnt 'la guía no prepara cambios SSH tras prueba fallida' 'UNEXPECTED_SNAPSHOT' "$out"

summary
