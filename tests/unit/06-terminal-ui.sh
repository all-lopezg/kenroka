#!/usr/bin/env bash
# Pruebas de comportamiento de la interfaz en PTY, sin tocar SSH ni el VPS.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
extract_fns ui info warn success error header pause confirm confirm_labels phase_label \
    phase_guide guided_active ssh_test_command show_access_test_steps ask_access_result main_menu banner
{
    printf 'set -euo pipefail\n'
    declare -f ui_visual ui_width ui_rule ui_text ui_panel ui_menu_text ui_read ui_screen ui_command \
        ui_message ui_help ui_phase_finish run_phase clear_screen ui info warn success error header pause \
        confirm confirm_labels phase_label phase_guide guided_active ssh_test_command show_access_test_steps \
        ask_access_result main_menu banner
    cat <<'FIXTURE'
UI_INPUT_TTY=1
NON_INTERACTIVE=0 AUDIT_MODE=0 VERIFY_MODE=0 UI_PLAIN=0 GUIDED=1 ASSUME_YES=0
UI_LANG=es
SCRIPT_VERSION=dev PUBLIC_IP=203.0.113.9 USERNAME=admin ORIGINAL_USER=admin CURRENT_PORT=24022
ROLLBACK_ARMED=0 ROLLBACK_MINUTES=10 RECOVERY_OCCURRED=0 SOCKET_ACTIVATED=0
RED='' GREEN='' BLUE='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
LOG_FILE=/var/log/secure-vps.log
SNAPSHOTS_DIR=/nonexistent
list_pending_rollbacks() { :; }
log() { :; }
fase_1_user() {
    header 'CUENTA ADMINISTRADORA'
    phase_guide 1/7 'Cuenta de administración' 'Administration account' \
        'Revisaré tu cuenta administradora.' 'I will review your administrator account.' \
        'Confirma si quieres continuar.' 'Confirm whether you want to continue.' \
        'No se cierra ningún acceso.' 'No access is closed.'
    warn 'AVISO IMPORTANTE: el acceso por contraseña sigue disponible.'
    if [[ $1 == decision ]]; then confirm '¿Continuar con esta cuenta?' || return 1; fi
    success 'Cuenta revisada. Prueba SSH todavía pendiente.'
    pause
}
case "$1" in
    access|restore)
        ROLLBACK_ARMED=1
        show_access_test_steps 24022 'Primero prueba SSH y sudo desde tu computadora.'
        ask_access_result 'conservar cambios' 'keep changes' 'restaurar cambios' 'restore changes' && rc=0 || rc=$?
        printf 'ACCESS_RESULT=%s\n' "$rc"
        ;;
    result)
        fase_1_user() { success 'Clave instalada; acceso aún pendiente.'; UI_PHASE_RESULT='Pendiente; falta probar SSH'; pause; }
        run_phase fase_1_user
        ;;
    decision)
        # Función de fase sin operaciones del sistema: confirma y muestra resultado.
        eval "$(declare -f fase_1_user | sed 's/\[\[ \$1 == decision \]\]/[[ decision == decision ]]/')"
        run_phase fase_1_user
        ;;
    failed)
        fase_3_harden_ssh() { error 'DIAGNOSTICO QUE DEBE SEGUIR VISIBLE'; RECOVERY_OCCURRED=1; return 1; }
        run_phase fase_3_harden_ssh && rc=0 || rc=$?
        printf 'PHASE_RESULT=%s\n' "$rc"
        ;;
    plain)
        NON_INTERACTIVE=1
        ui_screen 'PLAIN' 'Sin cambios'
        phase_guide 1/7 x x y y z z
        printf 'PLAIN_DONE\n'
        ;;
    dumb)
        TERM=dumb
        clear_screen
        ui_panel 'SIMPLE'
        ;;
    menu) main_menu ;;
    resize)
        ui_panel 'WIDE'
        stty cols 42
        ui_panel 'NARROW'
        ui_text 'Esta explicación larga debe adaptarse al ancho nuevo sin dividir palabras ni perder información.'
        ui_phase_finish 0
        ;;
esac
FIXTURE
} > "$WORK/ui-fixture.sh"

run_ui() {
    python3 "$HERE/helpers/ui-pty.py" "$WORK/ui-fixture.sh" "$1" "$2" "$WORK/$1-$2"
    local rc=$?
    check "PTY $1/$2 termina" 0 "$rc"
    OUT="$(cat "$WORK/$1-$2")"
}

echo '== decisiones de acceso con ayuda y Enter seguro'
run_ui access 80
has 'estado de prueba pendiente' 'Estado: Esperando prueba' "$OUT"
has 'ayuda opcional' 'AYUDA' "$OUT"
has 'Enter no confirma' 'Aún no se tomó ninguna decisión' "$OUT"
has 'opción 1 conserva' 'ACCESS_RESULT=0' "$OUT"
has 'explica protección temporal' 'Protección temporal activa' "$OUT"
has 'comando SSH mantiene la autenticación por clave' 'PreferredAuthentications=publickey' "$OUT"
run_ui restore 80
has 'opción 2 restaura' 'ACCESS_RESULT=1' "$OUT"

echo '== resultados y fallos'
run_ui result 80
has 'no confunde clave instalada con acceso probado' 'Pendiente; falta probar SSH' "$OUT"
has 'espera antes de la siguiente fase' 'Pulsa Enter para continuar' "$OUT"
run_ui failed 80
has 'conserva diagnóstico visible' 'DIAGNOSTICO QUE DEBE SEGUIR VISIBLE' "$OUT"
has 'restauración no se anuncia como éxito' 'Restaurado; fase pendiente' "$OUT"
has 'conserva el fallo original' 'PHASE_RESULT=1' "$OUT"
hasnt 'un fallo no limpia el diagnóstico' '[SCREEN]' "$OUT"
run_ui decision 80
has 'la decisión conserva los avisos de la fase' 'AVISO IMPORTANTE' "$OUT"
has 'termina con un resultado explícito' 'Confirmado para esta fase' "$OUT"

echo '== ancho, comandos copiables y salida sencilla'
run_ui access 42
hasnt 'terminal estrecha no usa marcos anchos' '+---' "$OUT"
has 'comando partido mantiene continuación de shell' $'\\\n' "$OUT"
python3 - "$WORK/access-42" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
long = [line for line in lines if len(line) > 42]
if long:
    print('líneas demasiado largas:', repr(long))
    sys.exit(1)
PY
check 'prueba SSH cabe en 42 columnas' 0 "$?"
run_ui resize 80
has 'recalcula el ancho al redimensionar' 'NARROW' "$OUT"
run_ui plain 80
hasnt 'automatización no limpia la pantalla' '[SCREEN]' "$OUT"
hasnt 'automatización no añade marcos' '+---' "$OUT"
run_ui dumb 80
hasnt 'TERM=dumb no usa escapes de pantalla' '[SCREEN]' "$OUT"
run_ui menu 80
has 'menú ofrece tareas comprensibles' 'Revisar el estado sin cambiar nada' "$OUT"
has 'acciones por fase están disponibles' 'ACCIONES AVANZADAS' "$OUT"
# Facilita inspección manual de una ejecución real sin incluir artefactos en Git.
if [[ -n ${KENROKA_UI_PREVIEW_DIR:-} ]]; then
    mkdir -p "$KENROKA_UI_PREVIEW_DIR"
    cp "$WORK"/access-80 "$WORK"/access-42 "$WORK"/result-80 "$WORK"/decision-80 "$WORK"/menu-80 "$KENROKA_UI_PREVIEW_DIR/"
fi
summary
