#!/usr/bin/env bash
#
# secure-vps.sh - Endurecimiento de VPS Ubuntu 22.04 / 24.04
# Menú interactivo, idempotente, con red de seguridad: valida la clave antes
# de cerrar el acceso, y si nada se confirma revierte solo (cuenta atrás).
# Interfaz en español o inglés según el locale del sistema (--lang fuerza uno).
#
# Uso interactivo:   sudo bash secure-vps.sh
# Uso no interactivo: sudo bash secure-vps.sh --non-interactive \
#                       --user TUUSUARIO --pubkey-file /root/clave.pub \
#                       --sudo nopasswd --port 24022 --allow-lockdown --no-rollback --yes
#                     (--allow-lockdown asume el riesgo: cierra sin prueba humana)
#
# Autor: Allan López
# Versión: 1.4.6
#

set -euo pipefail

# ============================================================
# CONFIGURACIÓN GLOBAL
# ============================================================
readonly SCRIPT_VERSION="1.4.6"
readonly HARDENING_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
# No es readonly a propósito: check_backup_exists puede reutilizar el backup de
# una corrida anterior en vez de dejar otro .bak en /etc/ssh cada vez.
BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%Y%m%d-%H%M%S)"
readonly CLOUD_INIT_FILE="/etc/ssh/sshd_config.d/50-cloud-init.conf"
readonly LOG_FILE="/var/log/secure-vps.log"

# Estado persistente y rollback temporizado
readonly STATE_DIR="/var/lib/secure-vps"
readonly SNAPSHOTS_DIR="$STATE_DIR/snapshots"
readonly SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
readonly SOCKET_DROPIN="$SOCKET_DROPIN_DIR/99-secure-vps.conf"
readonly ROLLBACK_BIN="/usr/local/bin/secure-vps-rollback"
readonly REBOOT_FLAG="/var/run/reboot-required"

# Estado global (se rellena en runtime)
PUBLIC_IP=""
ORIGINAL_USER=""
NEW_PORT=""
USERNAME=""
SSH_PUBKEY=""
PUBKEY_FILE=""
NON_INTERACTIVE=0
ASSUME_YES=0
RUN_ALL=0
CURRENT_PORT=22
SNAP_DIR=""
ROLLBACK_JOB=""
ROLLBACK_SNAP_DIR=""     # snapshot fijo de la cuenta atrás, independiente de SNAP_DIR
ROLLBACK_ARMED=0
ROLLBACK_MINUTES=10
SUDO_MODE=""            # prompt | nopasswd | keep
ALLOW_LOCKDOWN=0        # required para cerrar el acceso en modo no interactivo
OPT_NO_ROLLBACK=0
OPT_SKIP_LOCKDOWN=0
SOCKET_ACTIVATED=-1     # -1 = sin detectar, 0 = ssh.service, 1 = ssh.socket
FAIL2BAN_BACKEND=""     # systemd | auto
FAIL2BAN_LOGPATH=""
JAIL_LOCAL="/etc/fail2ban/jail.d/99-secure-vps.local"
KEY_READY=0
KEY_TESTED=0              # una conexión con clave fue probada antes del cierre
USER_CREATED_THIS_RUN=0   # evita sugerir ssh-copy-id a una cuenta sin contraseña SSH
ACCESS_TEST_CONFIRMED=0   # confirmación humana de esta ejecución, no un estado persistente
RECOVERY_OCCURRED=0       # el último cambio de acceso de esta ejecución fue restaurado
RECOVERY_REASON=""
# ask = preguntar en interactivo; yes con --upgrade; no con --no-upgrade.
# En modo desatendido solo se aplica con --upgrade explícito: un apt upgrade de
# varios minutos no lo decide un pipeline en silencio.
UPGRADE_MODE=ask
PENDING_COUNT=0
PENDING_SECURITY=0
# 'auto' guía a quien llega sin clave o desde la consola del proveedor;
# --novato y --experto lo fuerzan. ON_CONSOLE = esta sesión no es SSH.
GUIDED_MODE=auto
GUIDED=0                    # GUIDED_MODE resuelto contra el estado de runtime
ON_CONSOLE=0
CLIENT_OS=linux               # macos | windows | linux, para los textos de guía
CANDIDATE_KEYS_FILE=""        # tsv: número, clave, archivo de origen, huella
VALID_FINGERPRINT=""
ADMIN_IPS=""
LOCKDOWN=1
AUDIT_MODE=0            # --audit: reporte de solo lectura, no toca nada
VERIFY_MODE=0           # --verify: solo comprobar y guardar reporte
VERIFY_REPORT=""
VERIFY_FAILURES=0
VERIFY_PENDING=0
VERIFY_EXTERNAL=unconfirmed
VERIFY_STATUS=""
UI_INPUT_TTY=0
[[ -t 0 ]] && UI_INPUT_TTY=1

# Colores (se desactivan si no hay TTY). Van con comillas ANSI-C ($'...') a
# propósito: con '\033[1m' el valor guarda el texto literal "\033[1m", que solo
# interpreta `echo -e`. printf '%s' y los heredoc lo imprimían tal cual, y por
# eso el banner salía cubierto de basura en pantalla.
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    NC=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
fi

# Idioma de la interfaz: detección automática (es* → español, resto → inglés),
# overridable con --lang. ui() devuelve el texto en el idioma activo y SIEMPRE
# devuelve algo: si falta la traducción, cae al texto en español.
UI_LANG="en"
UI_LANG_EXPLICIT=0
ui_lang_detect() {
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        es*) UI_LANG="es" ;;
        *)   UI_LANG="en" ;;
    esac
}
ui() {
    if [[ $UI_LANG == es ]]; then
        printf '%s' "$1"
    elif [[ -n "${2:-}" ]]; then
        printf '%s' "$2"
    else
        printf '%s' "$1"
    fi
}
ui_lang_detect

# ============================================================
# UTILIDADES DE LOG Y SALIDA
# ============================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" >/dev/null
}
# Presentación interactiva. Los reportes y la automatización conservan texto
# normal; no se necesitan dialog, ncurses ni un runtime adicional.
ui_visual() {
    [[ ${NON_INTERACTIVE:-0} -eq 0 && ${AUDIT_MODE:-0} -eq 0 && ${VERIFY_MODE:-0} -eq 0 &&
       ${UI_PLAIN:-0} -eq 0 && ${TERM:-dumb} != dumb && ( -t 0 || ${UI_INPUT_TTY:-0} -eq 1 ) && -t 1 ]]
}

ui_width() {
    local size="" width="${COLUMNS:-}"
    if [[ ${UI_RENDER_WIDTH:-} =~ ^[0-9]+$ ]]; then
        printf '%s' "$UI_RENDER_WIDTH"
        return 0
    fi
    size=$(stty size 2>/dev/null) || size=$(stty size 2>/dev/null </dev/tty) || true
    [[ ${size##* } =~ ^[0-9]+$ && ${size##* } -gt 0 ]] && width=${size##* }
    [[ $width =~ ^[0-9]+$ ]] || width=80
    (( width > 96 )) && width=96
    (( width < 20 )) && width=20
    printf '%s' "$width"
}

ui_rule() {
    local width i
    width=$(ui_width)
    printf '%s+' "${CYAN:-}"
    for ((i=2; i<width; i++)); do printf '%s' '-'; done
    printf '+%s\n' "${NC:-}"
}

ui_text() {
    local width line
    if ! ui_visual; then printf '%s\n' "$*"; return 0; fi
    width=$(ui_width)
    # Cada línea es un párrafo: no se fusionan avisos ni etiquetas de la guía.
    while IFS= read -r line; do
        printf '%s\n' "$line" | fmt -w "$((width-4))" | sed 's/^/  /'
    done <<< "$*"
}

ui_panel() {
    local width
    width=$(ui_width)
    if ui_visual && ((width >= 60)); then ui_rule; fi
    ui_text "$*"
    if ui_visual && ((width >= 60)); then ui_rule; fi
}

ui_read() {
    local prompt="$1" variable="$2"
    if ui_visual; then
        ui_text "$prompt"
        read -rp '> ' "$variable"
    else
        read -rp "$prompt" "$variable"
    fi
}

ui_menu_text() {
    local line
    while IFS= read -r line; do ui_text "$line"; done
}

ui_screen() {
    local title="$1" state="${2:-}"
    clear_screen
    ui_panel "KENROKA · $title"
    ui_text "$(ui 'Servidor' 'Server'): ${PUBLIC_IP:-?}"
    ui_text "$(ui 'Administrador' 'Administrator'): ${USERNAME:-${ORIGINAL_USER:-?}} · SSH: ${CURRENT_PORT:-22}"
    [[ -n "$state" ]] && ui_text "$(ui 'Estado' 'State'): $state"
    if [[ ${ROLLBACK_ARMED:-0} -eq 1 ]]; then
        ui_text "$(ui 'Protección temporal activa. El plazo real lo controla systemd; vuelve a probar el acceso antes de confirmar.' 'Temporary protection is active. systemd controls the actual deadline; test access again before confirming.')"
    fi
    echo
}

ui_command() {
    local command="$1" destination="${2:-}" width
    if ! ui_visual; then printf '     %s\n' "$command"; return 0; fi
    width=$(ui_width)
    echo
    ui_text "$(ui 'COPIAR Y EJECUTAR' 'COPY AND RUN')${destination:+ · $destination}"
    if ((width >= 60)); then ui_rule; else ui_text '---'; fi
    printf '%s' "${BOLD:-}${GREEN:-}"
    # Una sola línea lógica, sin saltos ni barras añadidos por el asistente.
    # La terminal puede envolverla visualmente según el ancho de la ventana.
    printf '  %s\n' "$command"
    printf '%s' "${NC:-}"
    if ((width >= 60)); then ui_rule; else ui_text '---'; fi
    echo
}

ui_message() {
    local kind="$1" text="$2" prefix color
    case "$kind" in
        info) prefix='i'; color="${BLUE:-}" ;;
        success) prefix='OK'; color="${GREEN:-}" ;;
        warn) prefix='!'; color="${YELLOW:-}" ;;
        error) prefix='ERROR'; color="${RED:-}" ;;
    esac
    if [[ ${UI_MANAGED_PHASE:-0} -eq 1 ]]; then
        UI_PHASE_MESSAGES="${UI_PHASE_MESSAGES:-}[$prefix] $text"$'\n'
    fi
    if ui_visual; then
        printf '%s' "$color"
        ui_text "[$prefix] $text"
        printf '%s' "${NC:-}"
    else
        [[ ${UI_PLAIN:-0} -eq 1 || ${AUDIT_MODE:-0} -eq 1 || ${VERIFY_MODE:-0} -eq 1 || ${NON_INTERACTIVE:-0} -eq 1 ]] && color=''
        case "$kind" in info) prefix='ℹ';; success) prefix='✔';; warn) prefix='⚠';; error) prefix='✘';; esac
        printf '%s%s%s  %s\n' "$color" "$prefix" "${NC:-}" "$text"
    fi
}

ui_help() {
    ui_panel "$(ui 'AYUDA' 'HELP')"
    if [[ -n ${UI_GUIDE:-} ]]; then ui_text "$UI_GUIDE"; fi
    ui_text "$(ui 'Lee la pregunta y elige una respuesta explícita. Enter no confirma una prueba SSH. Mantén esta sesión abierta y usa otra terminal de tu computadora para las pruebas.' 'Read the question and choose an explicit answer. Enter does not confirm an SSH test. Keep this session open and use another terminal on your computer for tests.')"
    ui_text "$(ui 'Los resultados de una fase no certifican todo el VPS. La verificación final comprueba los componentes y pide tu prueba de acceso.' 'A phase result does not certify the entire VPS. Final verification checks components and asks for your access test.')"
    if [[ -n ${UI_ACCESS_PORT:-} ]]; then
        ui_text "$(ui 'Permission denied: revisa usuario, clave privada y la opción -i. No pegues la clave privada en el VPS.' 'Permission denied: check the user, private key and -i option. Never paste the private key into the VPS.')"
        ui_text "$(ui 'Connection timed out: revisa dirección, puerto y el cortafuegos del proveedor. Connection refused: el servicio puede no estar escuchando en ese puerto.' 'Connection timed out: check address, port and provider firewall. Connection refused: the service may not be listening on that port.')"
        ui_text "$(ui 'Si no consigues entrar, elige la opción 2 de esta prueba. Antes del cierre conserva el acceso; después de un cambio solicita restaurarlo.' 'If you cannot log in, choose option 2 in this test. Before lockdown it keeps access open; after a change it requests restoration.')"
    fi
    ui_text "$(ui 'Registro de operaciones' 'Operation log'): ${LOG_FILE:-/var/log/secure-vps.log}"
}

ui_phase_finish() {
    local rc="$1" state="${UI_PHASE_RESULT:-}"
    ui_visual || return 0
    if [[ $rc -ne 0 ]]; then
        if [[ ${UI_ACCESS_PRECHECK_FAILED:-0} -eq 1 ]]; then
            state="${UI_PHASE_RESULT:-}"
        elif [[ ${RECOVERY_OCCURRED:-0} -eq 1 && ${UI_PHASE_ACCESS:-0} -eq 1 ]]; then
            state="$(ui 'Restaurado; fase pendiente' 'Restored; phase pending')"
        else
            state="$(ui 'Detenido; revisa el error' 'Stopped; review the error')"
        fi
    elif [[ ${ROLLBACK_ARMED:-0} -eq 1 ]]; then
        state="$(ui 'Pendiente de confirmación de acceso' 'Awaiting access confirmation')"
    fi
    # Al fallar se deja el diagnóstico en pantalla; nunca se tapa un error.
    if [[ $rc -eq 0 ]]; then
        ui_screen "$(ui 'RESULTADO' 'RESULT'): ${UI_PHASE_TITLE:-}" "$state"
        ui_text "${UI_PHASE_MESSAGES:-$(ui 'Sin mensajes adicionales.' 'No additional messages.')}"
    else
        ui_panel "$(ui 'RESULTADO DE LA FASE' 'PHASE RESULT'): $state"
    fi
    ui_text "$(ui 'Pulsa Enter para continuar o h para ver ayuda.' 'Press Enter to continue or h for help.')"
    local answer=""
    while read -rp '> ' answer; do
        case "$answer" in
            '') break ;;
            h|H|'?') ui_help ;;
            *) ui_text "$(ui 'Enter continúa; h muestra ayuda.' 'Enter continues; h shows help.')" ;;
        esac
    done
    return 0
}

run_phase() {
    local step="$1" rc=0
    local UI_MANAGED_PHASE=1 UI_PHASE_MESSAGES='' UI_GUIDE='' UI_PHASE_ACCESS=0
    local UI_ACCESS_PORT='' UI_ACCESS_CONTEXT='' UI_ACCESS_PRECHECK_FAILED=0
    local UI_PHASE_TITLE
    UI_PHASE_TITLE=$(phase_label "$step")
    case "$step" in
        fase_1_user) UI_PHASE_TITLE="$(ui 'Paso 1 de 8 · Administrador' 'Step 1 of 8 · Administrator')" ;;
        fase_2_ssh_key) UI_PHASE_TITLE="$(ui 'Paso 2 de 8 · Clave SSH' 'Step 2 of 8 · SSH key')" ;;
        fase_2b_updates) UI_PHASE_TITLE="$(ui 'Paso 3 de 8 · Actualizaciones' 'Step 3 of 8 · Updates')" ;;
        fase_3_harden_ssh) UI_PHASE_TITLE="$(ui 'Paso 4 de 8 · Protección SSH' 'Step 4 of 8 · SSH protection')" ;;
        fase_4_ufw) UI_PHASE_TITLE="$(ui 'Paso 5 de 8 · Cortafuegos' 'Step 5 of 8 · Firewall')" ;;
        fase_5_fail2ban) UI_PHASE_TITLE="$(ui 'Paso 6 de 8 · Fail2ban' 'Step 6 of 8 · Fail2ban')" ;;
        fase_6_auto_updates) UI_PHASE_TITLE="$(ui 'Paso 7 de 8 · Actualizaciones automáticas' 'Step 7 of 8 · Automatic updates')" ;;
        fase_7_change_port) UI_PHASE_TITLE="$(ui 'Paso 8 de 8 · Puerto opcional' 'Step 8 of 8 · Optional port')" ;;
    esac
    local UI_PHASE_RESULT
    UI_PHASE_RESULT="$(ui 'Confirmado para esta fase' 'Confirmed for this phase')"
    case "$step" in fase_3_harden_ssh|fase_4_ufw|fase_7_change_port) UI_PHASE_ACCESS=1 ;; esac
    "$step" || rc=$?
    ui_phase_finish "$rc"
    if [[ $rc -ne 0 ]] && ! ui_visual; then pause; fi
    return "$rc"
}

info()    { ui_message info "$*"; }
success() { ui_message success "$*"; }
warn()    { ui_message warn "$*"; }
error()   { ui_message error "$*" >&2; }
header() {
    local title="$*"
    if ui_visual; then
        # La numeración interna 2.5 no compite con los ocho pasos de la guía.
        case "$title" in FASE*:*|PHASE*:*) title="${title#*: }" ;; esac
        ui_screen "$title" "$(ui 'En curso' 'In progress')"
    else echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; fi
}

# confirm_labels <idioma-ui>  ->  "[s/n]: " o "[y/n]: "
confirm_labels() {
    if [[ $UI_LANG == es ]]; then
        printf '%s' "[s/n]: "
    else
        printf '%s' "[y/n]: "
    fi
}

confirm() {
    local prompt="$1"
    if [[ $ASSUME_YES -eq 1 ]]; then
        info "$prompt $(ui "→ asumido 's' (modo --yes)" "→ assumed 'y' (--yes mode)")"
        return 0
    fi
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        error "$(ui "Confirmación requerida en modo no interactivo sin --yes: $prompt" "Confirmation required in non-interactive mode without --yes: $prompt")"
        exit 1
    fi
    local response
    if ui_visual && [[ ${UI_MANAGED_PHASE:-0} -eq 1 ]]; then
        ui_screen "$(ui 'DECISIÓN' 'DECISION')" "$(ui 'Esperando tu decisión' 'Awaiting your decision')"
        ui_text "${UI_GUIDE:-}"
        [[ -n ${UI_PHASE_MESSAGES:-} ]] && ui_text "$UI_PHASE_MESSAGES"
        ui_panel "$prompt"
        ui_text "$(ui '1) Sí   2) No   h) Ayuda' '1) Yes   2) No   h) Help')"
    fi
    while true; do
        # EOF en stdin = respuesta "n": sin esto el bucle no termina nunca
        # cuando se corre con la entrada redirigida o cerrada.
        # La etiqueta del corchete es lo único que cambia: 'y' ya se aceptaba
        # desde siempre; escribir "[s/n]" en una pantalla en inglés hacía dudar.
        if ui_visual; then
            if [[ ${UI_MANAGED_PHASE:-0} -ne 1 ]]; then
                ui_panel "$prompt"
                ui_text "$(ui '1) Sí   2) No   h) Ayuda' '1) Yes   2) No   h) Help')"
            fi
            read -rp '> ' response || return 1
        else
            read -rp "$(echo -e "${YELLOW}?${NC}  $prompt $(confirm_labels)")" response || return 1
        fi
        case "$response" in
            1|[sSyY]) return 0 ;;
            2|[nN])   return 1 ;;
            h|H|\?) ui_help ;;
            *)      ui_text "$(ui "Responde 1/s para sí, 2/n para no o h para ayuda." "Answer 1/y for yes, 2/n for no or h for help.")" ;;
        esac
    done
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "$(ui "Este script debe ejecutarse como root (usa: sudo bash $0)" "This script must run as root (use: sudo bash $0)")"
        exit 1
    fi
}

# Limpia la vista y coloca el cursor arriba; conserva el historial de la
# terminal para revisar mensajes anteriores. Nunca emite escapes en reportes.
clear_screen() {
    ui_visual || return 0
    printf '\033[2J\033[H'
}

pause() {
    if ui_visual && [[ ${UI_MANAGED_PHASE:-0} -eq 1 ]]; then return 0; fi
    # Sin terminal no tiene sentido esperar un Enter: tragarlo rompería además
    # las respuestas que el operador está escribiendo para las fases siguientes.
    if [[ $NON_INTERACTIVE -eq 1 ]] || [[ ! -t 0 ]]; then
        return 0
    fi
    read -rp "$(echo -e "${CYAN}$(ui "Presiona Enter para continuar..." "Press Enter to continue...")${NC}")" || true
}

# Las fases guiadas siguen siempre el mismo orden. Así una persona sabe qué
# cambiará el script antes de que aparezca una pregunta y qué acción concreta
# se espera de ella. En modo experto se conservan las salidas cortas.
phase_guide() {
    local number="$1" title_es="$2" title_en="$3" change_es="$4" change_en="$5"
    local action_es="$6" action_en="$7" protection_es="${8:-}" protection_en="${9:-}"
    UI_GUIDE="$(ui 'Qué se hará:' 'What will happen:') $(ui "$change_es" "$change_en")
$(ui 'Qué debes hacer ahora:' 'What you must do now:') $(ui "$action_es" "$action_en")
$(ui 'Protección:' 'Protection:') $(ui "$protection_es" "$protection_en")"
    if ui_visual; then
        local step="$number"
        case "$number" in 1/7) step=1;; 2/7) step=2;; 2.5/7) step=3;; 3/7) step=4;; 4/7) step=5;; 5/7) step=6;; 6/7) step=7;; 7/7) step=8;; esac
        ui_panel "$(ui 'Paso' 'Step') $step $(ui 'de 8' 'of 8') · $(ui "$title_es" "$title_en")"
        if ! guided_active; then ui_text "$(ui "$change_es" "$change_en")"; return 0; fi
        ui_text "$UI_GUIDE"
        echo
        return 0
    fi
    guided_active || return 0
    echo
    echo "  ${BOLD}[$number] $(ui "$title_es" "$title_en")${NC}"
    echo "  ${CYAN}$(ui "Qué se hará:" "What will happen:")${NC} $(ui "$change_es" "$change_en")"
    echo "  ${CYAN}$(ui "Qué debes hacer ahora:" "What you must do now:")${NC} $(ui "$action_es" "$action_en")"
    if [[ -n "$protection_es$protection_en" ]]; then
        echo "  ${CYAN}$(ui "Protección:" "Protection:")${NC} $(ui "$protection_es" "$protection_en")"
    fi
    echo
}

# La elección inicial no puede depender solo del locale del VPS: ese locale
# describe al servidor, no necesariamente a quien lo administra. Solo se
# muestra en un TTY y en modo guiado; automatización y pruebas con stdin no
# consumen una respuesta adicional.
choose_ui_language() {
    local answer=""
    [[ $GUIDED -eq 1 && $UI_LANG_EXPLICIT -eq 0 && $NON_INTERACTIVE -eq 0 && -t 0 ]] || return 0
    clear_screen
    ui_panel 'KENROKA · Idioma / Language'
    echo
    echo "  Selecciona el idioma / Choose your language"
    echo "    1) Español"
    echo "    2) English"
    while true; do
        if ! read -rp "  [1/2] ($( [[ $UI_LANG == es ]] && printf '1' || printf '2' )): " answer; then
            return 0
        fi
        case "${answer:-}" in
            "") return 0 ;;
            1|es|ES|Español|español) UI_LANG=es; return 0 ;;
            2|en|EN|English|english)    UI_LANG=en; return 0 ;;
            *) echo "  Escribe 1 o 2 / Type 1 or 2." ;;
        esac
    done
}

# ============================================================
# DETECCIÓN DE IP PÚBLICA
# ============================================================
detect_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
        "https://ident.me"
    )
    for svc in "${services[@]}"; do
        ip=$(curl -fsS --max-time 5 "$svc" 2>/dev/null || true)
        # Validar formato IPv4
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            PUBLIC_IP="$ip"
            return 0
        fi
    done
    # Fallback: IP local de la interfaz principal
    PUBLIC_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)
    if [[ -z "$PUBLIC_IP" ]]; then
        warn "$(ui "No se pudo detectar la IP pública." "Could not detect the public IP.")"
        PUBLIC_IP="<IP_DEL_VPS>"
        return 1
    fi
    return 0
}

# ============================================================
# ============================================================
# VERIFICACIÓN DE USUARIO ORIGINAL
# ============================================================
# Usuarios con las que una persona podría entrar: uid >= 1000 y shell real.
# Acepta un archivo para poder probarla sin tocar /etc/passwd.
other_human_users() {
    local file="${1:-/etc/passwd}"
    [[ -r "$file" ]] || return 0
    awk -F: '$3 >= 1000 && $7 !~ /(nologin|\/false)$/ {printf "%s ", $1}' "$file" | sed 's/[[:space:]]*$//'
}

check_original_user() {
    ORIGINAL_USER="${SUDO_USER:-}"
    if [[ -z "$ORIGINAL_USER" ]]; then
        # Si no hay SUDO_USER, intentar con logname
        ORIGINAL_USER=$(logname 2>/dev/null || echo "")
    fi
    if [[ "$ORIGINAL_USER" == "root" || -z "$ORIGINAL_USER" ]]; then
        local others
        others=$(other_human_users)
        warn "$(ui "Estás ejecutando el script directamente como root." "You are running this script directly as root.")"
        if [[ $NON_INTERACTIVE -eq 1 ]]; then
            # La razón de pedir 'sudo' es asegurar que queda otro usuario con el
            # que entrar si el cierre sale mal. Con --skip-lockdown no se cierra
            # nada, así que root directo es aceptable.
            if [[ $OPT_SKIP_LOCKDOWN -eq 1 ]]; then
                warn "$(ui "Root directo en modo no interactivo: aceptado porque --skip-lockdown no cierra el acceso." "Direct root in non-interactive mode: accepted because --skip-lockdown does not lock down.")"
                return 0
            fi
            error "$(ui "Root directo en modo no interactivo: no hay garantía de un usuario alternativo." "Direct root in non-interactive mode: no guarantee of an alternative user.")"
            error "$(ui "Corre el script una vez en una terminal, para que cree el usuario" "Run the script once in a terminal, so it creates the user")"
            error "$(ui "administrador, o añade --skip-lockdown." "admin user, or add --skip-lockdown.")"
            exit 1
        fi
        if [[ -n "$others" ]]; then
            warn "$(ui "En este equipo ya hay otros usuarios con acceso interactivo: $others" "This machine already has other interactive users: $others")"
            warn "$(ui "Aun así, antes de cerrar nada vas a probar que puedes entrar con uno de ellos." "Still, before anything is closed you will test that you can log in with one of them.")"
            if ! confirm "$(ui "¿Continuar de todas formas?" "Continue anyway?")"; then
                exit 0
            fi
            return 0
        fi
        # El caso del VPS recién creado: solo existe root. Hay que decirlo con
        # las letras, no insinuar que "se recomienda sudo" cuando no hay a quién.
        warn "$(ui "En este equipo solo existe root: no hay otro usuario con el que entrar." "This machine has only root: there is no other user to log in with.")"
        info "$(ui "Lo que hace este script en ese caso:" "What this script does in that case:")"
        info "$(ui "  · La fase 1 crea un usuario administrador con sudo." "  · Phase 1 creates an admin user with sudo.")"
        info "$(ui "  · La fase 2 instala TU clave pública y comprueba que sshd la acepta." "  · Phase 2 installs YOUR public key and checks sshd accepts it.")"
        info "$(ui "  · No se cierra root ni la contraseña hasta que entres con ese usuario" "  · Root and password are not closed until you log in as that user")"
        info "$(ui "    desde OTRA terminal y marques que funcionó con 's'. Si no puedes, eliges restaurar." "    from ANOTHER terminal and mark that it worked with 'y'. If it does not, choose restore.")"
        local q_usuario q_en
        if [[ -n "$USERNAME" ]]; then
            q_usuario="¿Creo ahora el usuario '$USERNAME' y sigo con el endurecido?"
            q_en="Shall I create the user '$USERNAME' now and continue with the hardening?"
        else
            q_usuario="¿Creo ahora un usuario administrador y sigo con el endurecido?"
            q_en="Shall I create an admin user now and continue with the hardening?"
        fi
        if ! confirm "$(ui "$q_usuario" "$q_en")"; then
            echo "$(ui "Sin usuario no hay forma segura de cerrar el acceso: no toco nada." "Without a user there is no safe way to lock down: I will not touch anything.")"
            exit 0
        fi
    else
        success "$(ui "Script lanzado por el usuario: $ORIGINAL_USER (no root directo)." "Script launched by user: $ORIGINAL_USER (not direct root).")"
    fi
}

# ============================================================
# VERIFICACIONES PREVIAS
# ============================================================
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "$(ui "No se pudo detectar el sistema operativo." "Could not detect the operating system.")"
        return 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != ubuntu ]]; then
        error "$(ui "Solo se admite Ubuntu; detectado: ${PRETTY_NAME:-desconocido}." "Only Ubuntu is supported; detected: ${PRETTY_NAME:-unknown}.")"
        return 1
    fi
    # 24.04 y 22.04 tienen escenarios e2e propios; cualquier otra versión
    # continuaría con advertencia explícita en vez de negarse a ayudar.
    case "${VERSION_ID:-}" in
        24.04|22.04) success "$(ui "Ubuntu $VERSION_ID probado con escenarios e2e." "Ubuntu $VERSION_ID is covered by e2e scenarios.")" ;;
        *)
            warn "$(ui "Ubuntu $VERSION_ID no está en la matriz de pruebas (22.04 y 24.04 sí lo están). Revisa los cambios tú mismo." "Ubuntu $VERSION_ID is not in the test matrix (22.04 and 24.04 are). Review the changes yourself.")"
            if [[ $NON_INTERACTIVE -eq 0 ]] && ! confirm "$(ui "¿Continuar con una versión sin probar?" "Continue with an untested version?")"; then
                return 1
            fi
            ;;
    esac
    systemctl show --property=Version --value >/dev/null || { error "$(ui "Se requiere systemd operativo." "A working systemd is required.")"; return 1; }
    success "$(ui "Sistema operativo: $PRETTY_NAME" "Operating system: $PRETTY_NAME")"
}

check_dependencies() {
    local missing=()
    local cmd
    # Los nuevos (getent, stat, ssh-keygen, visudo, systemd-run, who) los usan
    # las verificaciones de la fase 2, 3 y 5: sin ellos no se puede garantizar
    # que el cierre de acceso sea seguro.
    for cmd in ip ss sshd ssh-keygen systemctl getent stat visudo \
               systemd-run who mktemp find awk sed flock runuser sudo; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "$(ui "Faltan comandos necesarios: ${missing[*]}. Instálalos antes de continuar." "Missing required commands: ${missing[*]}. Install them before continuing.")"
        return 1
    else
        success "$(ui "Todas las dependencias básicas están presentes." "All required dependencies are present.")"
    fi
    return 0
}

check_backup_exists() {
    local existing
    # $BACKUP_FILE lleva el timestamp de ESTA ejecución, así que comprobar ese
    # nombre concreto nunca acierta: se reutiliza el backup más antiguo, que es
    # el sshd_config previo a cualquier endurecimiento.
    existing=$(ls -1 /etc/ssh/sshd_config.bak.* 2>/dev/null | sort | sed -n '1p' || true)
    if [[ -n "$existing" ]]; then
        BACKUP_FILE="$existing"
        success "$(ui "Backup ya existe: $BACKUP_FILE" "Backup already exists: $BACKUP_FILE")"
    else
        cp /etc/ssh/sshd_config "$BACKUP_FILE" || return 1
        success "$(ui "Backup creado: $BACKUP_FILE" "Backup created: $BACKUP_FILE")"
    fi
}

# ============================================================
# PARSEO DE ARGUMENTOS
# ============================================================
usage() {
if [[ $UI_LANG == es ]]; then
cat <<EOF
Uso: sudo bash $0 [OPCIONES]

Versiones con pruebas end-to-end: Ubuntu 22.04 y 24.04.

Opciones:
  --non-interactive    Modo no interactivo (para Ansible/CI).
  --run-all            Ejecutar todas las fases de corrido, sin abrir el menú,
                       pero manteniendo las preguntas de confirmación.
  --user NOMBRE        Usuario administrador no-root, existente o nuevo; sin default.
  --pubkey CLAVE       Clave pública SSH a instalar.
  --pubkey-file RUTA   Leer la clave pública desde un archivo (evita la clave
                       visible en 'ps'; recomendado).
  --port PUERTO        Nuevo puerto SSH (opcional, ej: 24022).
  --sudo MODO          prompt (default, pide contraseña local) | nopasswd | keep
                       En modo no interactivo solo vale nopasswd o keep.
  --rollback-minutes N Minutos antes de revertir solo si no confirmas (default 10)
  --no-rollback        No armar el rollback temporizado (NO recomendado).
  --skip-lockdown      No añade restricciones de login. SÍ modifica el sistema;
                       no es una simulación ni garantiza ausencia de interrupciones.
  --allow-lockdown     Omitir prueba humana; exige --no-rollback explícito.
                       Puedes perder todo acceso SSH. Solo para automatización controlada.
  --yes                Asumir 's' en todas las confirmaciones.
  --upgrade            Aplicar las actualizaciones pendientes antes de cerrar el
                       acceso (obligatorio para hacerlo en modo no interactivo).
  --no-upgrade         Solo reportar las pendientes; no aplicar nada.
  --novato             Guía paso a paso para quien nunca usó SSH. Se activa
                       solo si llegas sin clave o desde la consola del proveedor.
  --experto            Sin textos de guía: el flujo directo de siempre.
  --audit              Reporte de solo lectura: qué está endurecido, qué falta
                       y qué riesgos hay. No escribe nada. Impide preguntas.
  --verify             Verificar hardening sin aplicar cambios; requiere --user.
                       Guarda reporte. Salida: 0 exitoso, 2 pendientes, 1 fallos.
                       --yes o sin terminal no confirman el acceso externo.
  --help               Mostrar esta ayuda.

Ejemplo de auditoría (antes de cambiar nada; guarda el texto para revisarlo):
  sudo bash secure-vps.sh --audit > auditoria.txt

Ejemplo interactivo (el recomendado: la fase 3 te pide confirmar desde otra terminal):
  sudo bash secure-vps.sh --user administrador --port 24022

Ejemplo sin cerrar el acceso (prepara todo; el cierre lo haces tú después):
  sudo bash secure-vps.sh --skip-lockdown --user administrador \\
       --pubkey-file /home/ubuntu/clave_publica.pub --sudo nopasswd

Ejemplo no interactivo completo (Ansible/CI; --pubkey-file evita la clave en 'ps'):
  sudo bash secure-vps.sh --non-interactive --user administrador \\
       --pubkey-file /root/clave_publica.pub --sudo nopasswd --allow-lockdown --no-rollback --yes
EOF
else
cat <<EOF
Usage: sudo bash $0 [OPTIONS]

Versions covered by end-to-end tests: Ubuntu 22.04 and 24.04.

Options:
  --non-interactive    Non-interactive mode (for Ansible/CI).
  --run-all            Run all phases back to back without opening the menu,
                       while keeping the confirmation prompts.
  --user NOMBRE        Non-root admin user, existing or new; no default.
  --pubkey CLAVE       SSH public key to install.
  --pubkey-file RUTA   Read the public key from a file (keeps the key
                       out of 'ps'; recommended).
  --port PUERTO        New SSH port (optional, e.g.: 24022).
  --sudo MODO          prompt (default, asks for a local password) | nopasswd | keep
                       In non-interactive mode only nopasswd or keep are valid.
  --rollback-minutes N Minutes before auto-revert if you do not confirm (default 10)
  --no-rollback        Do not arm the timed rollback (NOT recommended).
  --skip-lockdown      Adds no login restrictions. It DOES modify the system;
                       it is not a dry-run and does not guarantee zero disruption.
  --allow-lockdown     Skip the human test; requires explicit --no-rollback.
                       You can lose all SSH access. For controlled automation only.
  --yes                Assume 'yes' for all confirmations.
  --upgrade            Apply pending package updates before locking down
                       (required to do it in non-interactive mode).
  --no-upgrade         Only report what is pending; apply nothing.
  --novato             Step-by-step guidance for someone who never used SSH.
                       Turns itself on if you arrive without a key or from the
                       provider's web console.
  --experto            No guidance text: the direct flow as always.
  --audit              Read-only report: what is hardened, what is missing and
                       what is risky. Writes nothing; implies no prompts.
  --verify             Verify hardening without applying changes; requires --user.
                       Saves a report. Exit: 0 successful, 2 pending, 1 failures.
                       --yes or no terminal cannot confirm external access.
  --help               Show this help.

Audit example (before changing anything; keep the text to review it):
  sudo bash secure-vps.sh --audit > audit.txt

Interactive example (recommended: phase 3 asks you to confirm from another terminal):
  sudo bash secure-vps.sh --user administrador --port 24022

Example without locking down (prepares everything; you lock down later):
  sudo bash secure-vps.sh --skip-lockdown --user administrador \\
       --pubkey-file /home/ubuntu/clave_publica.pub --sudo nopasswd

Full non-interactive example (Ansible/CI; --pubkey-file keeps the key out of 'ps'):
  sudo bash secure-vps.sh --non-interactive --user administrador \\
       --pubkey-file /root/clave_publica.pub --sudo nopasswd --allow-lockdown --no-rollback --yes
EOF
fi
}

# Falla con mensaje claro cuando falta el valor de una opción, en vez de
# dejar un "unbound variable" de set -u.
require_val() {
    if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
        error "$(ui "La opción $1 necesita un valor." "Option $1 needs a value.")"
        usage
        exit 1
    fi
}

is_port() { [[ "${1:-}" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }

valid_username() {
    [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,30}$ && "$1" != root ]]
}

# Acepta IPv4/IPv6, con sufijo /cidr opcional. Se usa sobre lo que el operador
# escribe, que luego se interpola en un archivo de configuración: la forma
# hexadecimal+dos puntos es lo que mantiene la inyección fuera.
valid_ip_or_cidr() {
    local v="${1:-}" ip="" cidr="" has_cidr=0
    if [[ "$v" == */* ]]; then
        ip="${v%%/*}"
        cidr="${v#*/}"
        has_cidr=1
        [[ "$cidr" =~ ^[0-9]{1,3}$ ]] || return 1
    else
        ip="$v"
    fi
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        if [[ $has_cidr -eq 1 ]] && (( 10#$cidr > 32 )); then
            return 1
        fi
        return 0
    fi
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$ip" =~ [0-9a-fA-F] ]] || return 1
    [[ "$ip" != *:::* ]] || return 1
    # '::' solo aparece una vez.
    if [[ "$ip" == *::* && "${ip#*::}" == *::* ]]; then
        return 1
    fi
    if [[ $has_cidr -eq 1 ]] && (( 10#$cidr > 128 )); then
        return 1
    fi
    return 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --non-interactive) NON_INTERACTIVE=1; shift ;;
            --run-all)         RUN_ALL=1; shift ;;
            --user)            require_val "$@"; USERNAME="$2"; shift 2 ;;
            --pubkey)          require_val "$@"; SSH_PUBKEY="$2"; shift 2 ;;
            --pubkey-file)     require_val "$@"; PUBKEY_FILE="$2"; shift 2 ;;
            --port)            require_val "$@"; NEW_PORT="$2"; shift 2 ;;
            --sudo)            require_val "$@"; SUDO_MODE="$2"; shift 2 ;;
            --rollback-minutes) require_val "$@"; ROLLBACK_MINUTES="$2"; shift 2 ;;
            --no-rollback)     OPT_NO_ROLLBACK=1; shift ;;
            --skip-lockdown)   OPT_SKIP_LOCKDOWN=1; shift ;;
            --allow-lockdown)  ALLOW_LOCKDOWN=1; shift ;;
            --yes)             ASSUME_YES=1; shift ;;
            --novato|--guided) GUIDED_MODE=on; shift ;;
            --experto|--plain) GUIDED_MODE=off; shift ;;
            --upgrade)         UPGRADE_MODE=yes; shift ;;
            --no-upgrade)      UPGRADE_MODE=no; shift ;;
            # --audit nunca debe quedarse esperando una 's': al responderle que
            # no es interactivo, las preguntas de las verificaciones previas se
            # saltan y el reporte siempre sale.
            --audit)           AUDIT_MODE=1; NON_INTERACTIVE=1; shift ;;
            --verify)          VERIFY_MODE=1; shift ;;
            --lang)            require_val "$@"
                               case "$2" in es|en) UI_LANG="$2"; UI_LANG_EXPLICIT=1;; *) error "$(ui "Idioma no soportado: usa --lang es o --lang en" "Unsupported language: use --lang es or --lang en")"; exit 1;; esac
                               shift 2 ;;
            --help|-h)         usage; exit 0 ;;
            *)                 error "$(ui "Opción desconocida: $1" "Unknown option: $1")"; usage; exit 1 ;;
        esac
    done

    if [[ $AUDIT_MODE -eq 1 && $VERIFY_MODE -eq 1 ]]; then
        error "$(ui "Usa --audit o --verify por separado." "Use --audit or --verify separately.")"; exit 1
    fi
    if [[ $VERIFY_MODE -eq 1 && -z "$USERNAME" ]]; then
        error "$(ui "--verify requiere --user NOMBRE para comprobar el administrador." "--verify requires --user NAME to check the administrator.")"; exit 1
    fi
    case "$SUDO_MODE" in
        "" | prompt | nopasswd | keep) ;;
        *) error "$(ui "--sudo debe ser prompt, nopasswd o keep (venía: $SUDO_MODE)" "--sudo must be prompt, nopasswd or keep (got: $SUDO_MODE)")"; exit 1 ;;
    esac
    if [[ -n "$NEW_PORT" ]] && ! is_port "$NEW_PORT"; then
        error "$(ui "--port no es un puerto válido: $NEW_PORT" "--port is not a valid port: $NEW_PORT")"; exit 1
    fi
    if ! [[ "$ROLLBACK_MINUTES" =~ ^[1-9][0-9]{0,2}$ ]] || (( 10#$ROLLBACK_MINUTES > 240 )); then
        error "$(ui "--rollback-minutes debe estar entre 1 y 240" "--rollback-minutes must be between 1 and 240")"; exit 1
    fi
    if [[ -n "$USERNAME" ]] && ! valid_username "$USERNAME"; then
        error "$(ui "--user debe ser un nombre Linux válido distinto de root." "--user must be a valid Linux username other than root.")"; exit 1
    fi
    if [[ $ALLOW_LOCKDOWN -eq 1 && $OPT_NO_ROLLBACK -eq 0 ]]; then
        error "$(ui "--allow-lockdown requiere --no-rollback explícito: renuncias a la prueba de acceso y a la reversión automática." "--allow-lockdown requires explicit --no-rollback: you give up the access test and the automatic rollback.")"; exit 1
    fi
    if [[ "${BASH_SOURCE[0]:-}" == /dev/stdin || "${BASH_SOURCE[0]:-}" == /dev/fd/* || -z "${BASH_SOURCE[0]:-}" ]]; then
        error "$(ui "Descarga secure-vps.sh a un archivo, revísalo y ejecútalo; no se admite curl | bash." "Download secure-vps.sh to a file, review it, and run it; curl | bash is not supported.")"; exit 1
    fi

    case "$UI_LANG" in
        es|en) ;;
        *) error "$(ui "Idioma no soportado: usa --lang es o --lang en" "Unsupported language: use --lang es or --lang en")"; exit 1 ;;
    esac

    # Hay que resolver --pubkey-file antes de validar: si no, un comando
    # perfectamente correcto se rechaza por no traer --pubkey.
    resolve_pubkey

    # Las obligaciones del modo desatendido son del endurecido (usuario, clave,
    # sudo, riesgo de encierro). Una auditoría no necesita ninguna.
    if [[ $NON_INTERACTIVE -eq 1 && $AUDIT_MODE -eq 0 && $VERIFY_MODE -eq 0 ]]; then
        if [[ -z "$USERNAME" ]]; then
            error "$(ui "En modo no interactivo, --user es obligatorio." "In non-interactive mode, --user is required.")"
            exit 1
        fi
        if [[ -z "$SSH_PUBKEY" ]]; then
            error "$(ui "En modo no interactivo, --pubkey es obligatorio." "In non-interactive mode, --pubkey is required.")"
            exit 1
        fi
        if [[ -z "$SUDO_MODE" ]]; then
            error "$(ui "En modo no interactivo, --sudo es obligatorio (nopasswd o keep)." "In non-interactive mode, --sudo is required (nopasswd or keep).")"
            exit 1
        fi
        if [[ "$SUDO_MODE" == "prompt" ]]; then
            error "$(ui "--sudo prompt necesita una terminal donde escribir la contraseña." "--sudo prompt needs a terminal to type the password into.")"
            error "$(ui "Usa --sudo nopasswd, o --sudo keep si la contraseña ya está puesta." "Use --sudo nopasswd, or --sudo keep if the password is already set.")"
            exit 1
        fi
        if [[ $OPT_SKIP_LOCKDOWN -eq 0 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            error "$(ui "No se puede cerrar el acceso SSH sin prueba humana.
Repite con --skip-lockdown (prepara todo y cierras tú tras probar la clave)
o con --allow-lockdown si asumes el riesgo de quedarte fuera." "Cannot lock down SSH access without a human verification step.
Retry with --skip-lockdown (prepare everything; you lock down after testing the key)
or --allow-lockdown if you accept the risk of being locked out.")"
            exit 1
        fi
    fi
}

# ============================================================
# AYUDANTES DE SEGURIDAD
# ============================================================

# Deja solo la última línea con contenido, sin espacios ni \r (un .pub copied
# desde Windows trae CRLF y ssh-keygen lo rechaza).
_pubkey_normalize() {
    printf '%s\n' "$1" | tr -d '\r' | awk '{sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); if ($0 != "" && $0 !~ /^#/) print}'
}

resolve_pubkey() {
    if [[ -n "${PUBKEY_FILE:-}" ]]; then
        local raw=""
        if [[ "$PUBKEY_FILE" == "-" ]]; then
            raw=$(cat)
            PUBKEY_FILE=""      # stdin es de un solo uso
        elif [[ -f "$PUBKEY_FILE" ]]; then
            raw=$(cat "$PUBKEY_FILE")
        else
            error "$(ui "No existe el archivo de clave: $PUBKEY_FILE" "Key file does not exist: $PUBKEY_FILE")"
            exit 1
        fi
        SSH_PUBKEY="$raw"
    fi
    [[ -z "${SSH_PUBKEY:-}" ]] && return 0
    SSH_PUBKEY=$(_pubkey_normalize "$SSH_PUBKEY")
    return 0
}

# ssh-keygen rechaza líneas corruptas; si esto falla, la clave no va a servir
# y es mejor abortar antes de deshabitar root/contraseña.
validate_pubkey() {
    local key="$1"
    local tmp rc=0 fp=""
    [[ -n "$key" && "$key" != *$'\n'* ]] || return 1
    tmp=$(mktemp) || return 1
    printf '%s\n' "$key" > "$tmp"
    fp=$(ssh-keygen -l -f "$tmp" 2>/dev/null) || rc=1
    rm -f "$tmp"
    if [[ $rc -ne 0 ]]; then
        return 1
    fi
    VALID_FINGERPRINT="$fp"
    return 0
}

# --- Cómo escucha SSH hoy: servicio clásico o socket-activado (24.04) ---
# Ubuntu 24.04 añade un generador de systemd (sshd-socket-generator) que traduce
# las líneas `Port` de sshd_config a ListenStream del socket y las escribe en
# /run/systemd/generator/ssh.socket.d/addresses.conf. Con ese generador presente,
# EL UNICO mando válido del puerto es `Port` en sshd_config.d: un drop-in manual
# de ListenStream queda aplastado por el del generador.
readonly SOCKET_GENERATOR_DIR="/run/systemd/generator/ssh.socket.d"

has_socket_generator() {
    [[ -d "$SOCKET_GENERATOR_DIR" ]] || \
        ls /lib/systemd/system-generators/*ssh* >/dev/null 2>&1
}

detect_ssh_activation() {
    # Capturar primero y grep sobre la variable: con `grep -q` en un pipe,
    # grep sale al hallar la coincidencia, el productor recibe SIGPIPE y con
    # pipefail el estado del pipeline es 141 => falso negativo intermitente.
    local unit_files state
    unit_files=$(systemctl list-unit-files 2>/dev/null) || true
    state=$(systemctl is-enabled ssh.socket 2>/dev/null) || true
    if grep -qE '^ssh\.socket' <<< "$unit_files" && [[ "$state" == "enabled" ]]; then
        SOCKET_ACTIVATED=1
    else
        SOCKET_ACTIVATED=0
    fi
}

# Puerto real en el que entra tráfico. Con socket-activación el valor de
# sshd_config y el del socket pueden no coincidir: reportamos ambos.
current_ssh_port() {
    local sock_port="" conf_port=""
    conf_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
    if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
        sock_port=$(systemctl show -p Listen --value ssh.socket 2>/dev/null \
                    | grep -oE ':[0-9]+' | tr -d ':' | sort -u | head -1 || true)
        printf '%s' "${sock_port:-${conf_port:-22}}"
    else
        printf '%s' "${conf_port:-22}"
    fi
}

ssh_activation_summary() {
    if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
        if has_socket_generator; then
            echo "    $(ui "ssh.socket + generador de Ubuntu 24.04: el puerto se manda con 'Port'." "ssh.socket + Ubuntu 24.04 generator: the port is driven by 'Port'.")"
        else
            echo "    $(ui "ssh.socket sin generador: el puerto se manda con un drop-in de ListenStream." "ssh.socket without generator: the port is driven by a ListenStream drop-in.")"
        fi
    else
        echo "    $(ui "ssh.service clásico: el puerto manda sshd_config." "Classic ssh.service: sshd_config drives the port.")"
    fi
}

# --- Snapshot / rollback temporizado ---
snapshot_state() {
    local path status pending
    # La cuenta atrás de OTRA ejecución es un motivo para no encimar cambios;
    # la que armó este mismo proceso no lo es: en la consola del proveedor nada
    # se puede verificar, y si no, las fases siguientes no correrían nunca.
    pending="$(list_pending_rollbacks)"
    if [[ -n "$pending" && "$pending" != "${ROLLBACK_JOB}.timer" ]]; then
        error "$(ui "Hay un rollback pendiente de otra ejecución; no iniciaré otro cambio." "A rollback from another run is pending; I will not start another change.")"
        return 1
    fi
    if [[ $ROLLBACK_ARMED -eq 1 ]] && ! rollback_snapshot_open "$ROLLBACK_SNAP_DIR"; then
        error "$(ui "La cuenta atrás ya revirtió o está revirtiendo; no iniciaré otra fase." "The countdown has rolled back or is rolling back; I will not start another phase.")"
        return 1
    fi
    ensure_sshd_runtime && sshd -t || return 1
    mkdir -p "$SNAPSHOTS_DIR" || return 1
    chmod 700 "$STATE_DIR" "$SNAPSHOTS_DIR" || return 1
    SNAP_DIR=$(mktemp -d "$SNAPSHOTS_DIR/$(date +%Y%m%d-%H%M%S).XXXXXX") || return 1
    printf '%s\n' /etc/ssh/sshd_config "$HARDENING_FILE" "$CLOUD_INIT_FILE" \
        "$SOCKET_DROPIN" "$JAIL_LOCAL" /etc/ufw/user.rules /etc/ufw/user6.rules \
        /etc/ufw/ufw.conf /etc/default/ufw > "$SNAP_DIR/paths" || return 1
    while IFS= read -r path; do
        if [[ -e "$path" || -L "$path" ]]; then
            mkdir -p "$SNAP_DIR/files$(dirname "$path")" || return 1
            cp -a -- "$path" "$SNAP_DIR/files$path" || return 1
        fi
    done < "$SNAP_DIR/paths"
    if command -v ufw >/dev/null; then
        status=$(ufw status) || return 1
        if [[ "$status" == *"Status: active"* ]]; then
            touch "$SNAP_DIR/UFW_ACTIVE" || return 1
        fi
    fi
    if systemctl is-active --quiet fail2ban; then
        touch "$SNAP_DIR/FAIL2BAN_ACTIVE" || return 1
    fi
    if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
        touch "$SNAP_DIR/SSH_SOCKET" || return 1
    fi
    printf 'created=%s\nusername=%s\ncurrent_port=%s\n' "$(date -Is)" "$USERNAME" "$CURRENT_PORT" > "$SNAP_DIR/meta" || return 1
    printf '%s\n' "$CURRENT_PORT" > "$SNAP_DIR/port" || return 1
    touch "$SNAP_DIR/READY" || return 1
    success "$(ui "Snapshot guardado en $SNAP_DIR" "Snapshot saved at $SNAP_DIR")"
    log "snapshot: $SNAP_DIR"
}

install_rollback_bin() {
    cat > "$ROLLBACK_BIN" <<'ROLLBACK_EOF' || return 1
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
SNAP="${1:?Falta snapshot}"
LOG="/var/log/secure-vps-rollback.log"
[[ $EUID -eq 0 && -f "$SNAP/READY" ]] || exit 1
exec 8>"$SNAP/lock"
flock -x 8
[[ ! -f "$SNAP/CONFIRMED" && ! -f "$SNAP/REVERTED" ]] || exit 0
touch "$SNAP/ROLLING_BACK"
trap 'touch "$SNAP/ROLLBACK_FAILED"; rm -f "$SNAP/ROLLING_BACK"' ERR
exec >>"$LOG" 2>&1
printf 'Rollback iniciado: %s\n' "$SNAP"
while IFS= read -r path; do
    if [[ -e "$SNAP/files$path" || -L "$SNAP/files$path" ]]; then
        mkdir -p "$(dirname "$path")"
        cp -a --remove-destination -- "$SNAP/files$path" "$path"
    else
        rm -f -- "$path"
    fi
done < "$SNAP/paths"

if command -v ufw >/dev/null; then
    if [[ -f "$SNAP/UFW_ACTIVE" ]]; then
        # 'ufw enable' sobre un firewall YA activo NO recarga las reglas: el
        # filtro se quedaba con lo que hubiera vivo en ese momento (p. ej.
        # dpt:2222 tras un cambio de puerto) y el 22 restaurado seguía
        # bloqueado. reload carga el estado de los archivos recién restaurados.
        ufw reload || { ufw --force disable && ufw --force enable; }
    else
        ufw --force disable
    fi
fi
if command -v fail2ban-client >/dev/null; then
    if [[ -f "$SNAP/FAIL2BAN_ACTIVE" ]]; then
        systemctl restart fail2ban
    else
        systemctl stop fail2ban
    fi
fi
if [[ -f "$SNAP/SSH_SOCKET" ]]; then
    systemctl stop ssh.service ssh.socket
else
    systemctl stop ssh.service
fi
mkdir -p /run/sshd
chmod 0755 /run/sshd
sshd -t
systemctl daemon-reload
systemctl reset-failed ssh.service
if [[ -f "$SNAP/SSH_SOCKET" ]]; then
    systemctl reset-failed ssh.socket
    systemctl start ssh.socket
fi
systemctl start ssh.service
systemctl is-active --quiet ssh.service
pgrep -x sshd >/dev/null
port=$(<"$SNAP/port")
ss -Htln | awk -v port="$port" '$4 ~ (":" port "$") {found=1} END {exit !found}'
touch "$SNAP/REVERTED"
rm -f "$SNAP/ROLLING_BACK" "$SNAP/ROLLBACK_FAILED"
printf 'Rollback completado: %s\n' "$SNAP"
ROLLBACK_EOF
    chmod 0755 "$ROLLBACK_BIN" || return 1
}

# 'systemctl cancel' NO cancela timers transitorios: responde OK y deja el
# timer programado igual. Lo que elimina la unidad de systemd-run es stop.
kill_rollback_timer() {
    local job="$1"
    [[ -n "$job" ]] || return 0
    systemctl stop "$job.timer" >> "$LOG_FILE" 2>&1 || return 1
    return 0
}

arm_rollback() {
    if [[ $OPT_NO_ROLLBACK -eq 1 ]]; then
        warn "$(ui "--no-rollback: el script NO se revertirá solo si te quedas fuera." "--no-rollback: the script will NOT revert on its own if you get locked out.")"
        return 0
    fi
    if ! command -v systemd-run >/dev/null; then
        error "$(ui "systemd-run no está disponible: no puedo armar el rollback temporizado." "systemd-run is not available: cannot arm the timed rollback.")"
        return 1
    fi
    [[ -f "$SNAP_DIR/READY" ]] || { error "$(ui "Snapshot incompleto; no aplicaré cambios." "Incomplete snapshot; I will not apply changes.")"; return 1; }
    [[ -z "$(list_pending_rollbacks)" ]] || { error "$(ui "Ya hay un rollback pendiente." "There is already a pending rollback.")"; return 1; }
    install_rollback_bin || return 1
    ROLLBACK_JOB="secure-vps-rollback-$(basename "$SNAP_DIR")"
    if systemd-run --unit="$ROLLBACK_JOB" --on-active="${ROLLBACK_MINUTES}m" --timer-property=AccuracySec=1s \
            "$ROLLBACK_BIN" "$SNAP_DIR" >> "$LOG_FILE" 2>&1; then
        ROLLBACK_SNAP_DIR="$SNAP_DIR"
        ROLLBACK_ARMED=1
        warn "$(ui "Protección temporal activa: tienes ${ROLLBACK_MINUTES} min para comprobar el acceso desde otra terminal." "Temporary protection active: you have ${ROLLBACK_MINUTES} min to check access from another terminal.")"
        info "$(ui "Si la prueba no funciona o no estás seguro, elige restaurar. Si no respondes, se restaurarán solos SSH, UFW y Fail2ban." "If the test does not work or you are unsure, choose restore. If you do not respond, SSH, UFW and Fail2ban restore themselves.")"
        info "$(ui "Al confirmar que funciona, esta protección se cancela automáticamente. No tienes que ejecutar ningún comando ahora." "When you confirm it works, this protection is cancelled automatically. You do not need to run any command now.")"
        log "rollback armado en $ROLLBACK_JOB (${ROLLBACK_MINUTES}m) -> $SNAP_DIR"
    else
        error "$(ui "No pude armar el rollback temporizado." "Could not arm the timed rollback.")"
        return 1
    fi
}

# Leer estas marcas bajo el lock para confirmar o modificar un estado pendiente.
rollback_snapshot_open() {
    local snap="$1"
    [[ -n "$snap" && -f "$snap/READY" && ! -f "$snap/CONFIRMED" &&
       ! -f "$snap/ROLLING_BACK" && ! -f "$snap/REVERTED" &&
       ! -f "$snap/ROLLBACK_FAILED" ]]
}

# Un callback opcional finaliza el puerto dentro del mismo lock que el rollback.
# CONFIRMED solo se escribe si terminó bien; si falla, el timer sigue protegiendo.
disarm_rollback() {
    [[ $ROLLBACK_ARMED -eq 1 ]] || return 0
    if ! (
        exec 8>"$ROLLBACK_SNAP_DIR/lock" || exit 1
        flock -x 8 || exit 1
        rollback_snapshot_open "$ROLLBACK_SNAP_DIR" || exit 1
        if [[ $# -gt 0 ]]; then
            "$@" || exit 1
        fi
        touch "$ROLLBACK_SNAP_DIR/CONFIRMED" || exit 1
    ); then
        error "$(ui "No pude finalizar la confirmación: el rollback ya comenzó, terminó o la operación falló. No continuaré." "Could not finish confirmation: rollback already started, completed, or the operation failed. I will not continue.")"
        return 1
    fi
    if kill_rollback_timer "$ROLLBACK_JOB"; then
        ROLLBACK_ARMED=0
        success "$(ui "Cuenta atrás cancelada. Los cambios son permanentes." "Countdown cancelled. The changes are permanent.")"
        log "rollback cancelado: $ROLLBACK_JOB"
    else
        error "$(ui "Los cambios están confirmados, pero no pude detener $ROLLBACK_JOB.timer; su rollback omitirá el snapshot confirmado." "Changes are confirmed, but could not stop $ROLLBACK_JOB.timer; its rollback will skip the confirmed snapshot.")"
        return 1
    fi
}

# En 24.04 sshd arranca por socket: cambiar solo sshd_config no mueve el
# puerto, y reiniciar el servicio sin el socket deja el listen viejo.
# ssh.service lleva RuntimeDirectory=sshd: systemd crea /run/sshd al arrancar
# el servicio y LO BORRA al pararlo. Sin ese directorio, `sshd -t` y `sshd -T`
# fallan sin decir por qué, y son justo las herramientas con las que este script
# comprueba la sintaxis y la config efectiva antes de cerrar el acceso.
ensure_sshd_runtime() {
    mkdir -p /run/sshd && chmod 0755 /run/sshd
}

# sshd vivo y sirviendo: un restart que agota el StartLimit deja la unidad en
# 'failed' sin nadie atendiendo el puerto, que es el encierro total.
# Ojo con pgrep -f: casaba con cualquier línea de mando que contuviera la ruta
# (incluidos los propios comandos de diagnóstico), dando un falso "sí está vivo".
sshd_serving() {
    # is-active + el proceso real: ss puede no mostrar el fd todavía (socket
    # activation lo pasa en el exec) y pgrep -f casaba líneas ajenas.
    local i
    for i in 1 2 3 4 5; do
        if systemctl is-active --quiet ssh.service && pgrep -x sshd >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

listening_ports() {
    local out
    out=$(ss -Htlnp 2>/dev/null | awk '/"sshd"/ {n=split($4,p,":"); print p[n]}' || true)
    if [[ -z "$out" && $SOCKET_ACTIVATED -eq 1 ]]; then
        # Con socket-activation systemd sostiene el fd hasta el exec de sshd:
        # la fuente sin carrera es el Listen declarado del socket.
        out=$(systemctl show -p Listen --value ssh.socket 2>/dev/null \
              | grep -oE ':[0-9]+' | tr -d ':' | sort -un | tr '\n' ' ' || true)
    else
        # IPv4 e IPv6 del mismo puerto cuentan una vez, y el resultado lleva
        # espacio final: la fase 7 compara contra "$NEW_PORT " tal cual.
        out=$(printf '%s\n' "$out" | sort -un | tr '\n' ' ')
    fi
    printf '%s\n' "$out"
}

restart_ssh() {
    # systemd falla de forma intermitente ("Job failed") si se re-arranca poco
    # después de otro reinicio: 3 intentos con verificación de listener real.
    local attempt
    for attempt in 1 2 3; do
        detect_ssh_activation
        if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
            systemctl stop ssh.service ssh.socket >> "$LOG_FILE" 2>&1 || true
        else
            systemctl stop ssh.service >> "$LOG_FILE" 2>&1 || true
        fi
        ensure_sshd_runtime && sshd -t >> "$LOG_FILE" 2>&1 || return 1
        systemctl daemon-reload >> "$LOG_FILE" 2>&1 || return 1
        if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
            systemctl start ssh.socket >> "$LOG_FILE" 2>&1 || true
        fi
        if systemctl start ssh.service >> "$LOG_FILE" 2>&1 && sshd_serving; then
            return 0
        fi
        sleep 2
    done
    error "$(ui "SSH no quedó sirviendo tras 3 intentos de reinicio." "SSH did not come back up after 3 restart attempts.")"
    return 1
}

socket_dropin_write() {
    # Acepta varios puertos: durante la transición se dejan los dos abiertos,
    # y el antiguo se quita solo después de confirmar el acceso.
    local port
    mkdir -p "$SOCKET_DROPIN_DIR"
    {
        echo "# Generado por secure-vps v$SCRIPT_VERSION"
        echo "[Socket]"
        echo "ListenStream="
        for port in "$@"; do
            echo "ListenStream=$port"
        done
    } > "$SOCKET_DROPIN"
    success "$(ui "Drop-in de socket escrito en $SOCKET_DROPIN (escucha: $*)" "Socket drop-in written at $SOCKET_DROPIN (listening: $*)")"
}

socket_dropin_remove() {
    rm -f "$SOCKET_DROPIN"
    rmdir "$SOCKET_DROPIN_DIR" 2>/dev/null || true
    info "$(ui "Drop-in de socket eliminado (vuelve al puerto del paquete)." "Socket drop-in removed (back to the packaged port).")"
}

# --- UFW: borrar reglas por puerto o servicio, sin depender del alias ---
# 'ufw allow ssh' crea una regla que 'ufw delete allow 22/tcp' NO empareja,
# así que se busca por número en 'ufw status numbered'.
ufw_purge_port() {
    local port="$1" service="${2:-}"
    local pattern nums n
    if [[ -n "$service" ]]; then
        pattern="^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+(${port}(/tcp|/udp)?|${service})([[:space:]]|\(|$)"
    else
        pattern="^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+${port}(/tcp|/udp)?([[:space:]]|\(|$)"
    fi
    # De mayor a menor número: al borrar, las reglas de abajo se renumeran.
    nums=$(ufw status numbered 2>/dev/null | grep -E "$pattern" \
           | sed -E 's/.*\[[[:space:]]*([0-9]+)\].*/\1/' | sort -rn || true)
    for n in $nums; do
        if ufw --force delete "$n" >> "$LOG_FILE" 2>&1; then
            info "$(ui "Regla UFW #$n eliminada." "UFW rule #$n removed.")"
        else
            warn "$(ui "No pude borrar la regla UFW #$n." "Could not remove UFW rule #$n.")"
        fi
    done
}

# ============================================================
# FASE 0: BIENVENIDA
# ============================================================
# El nombre en ASCII: adorno, pero es lo que hace que la pantalla parezca un
# programa y no un script. Solo en la bienvenida y en el menú.
banner() {
    if ui_visual && (( $(ui_width) < 60 )); then
        printf '%s' "${BOLD}${CYAN}"
        printf '%s\n' ' .-----------------.' ' | K E N R O K A   |' " '-----------------'"
        printf '%s\n\n' "${NC}   secure-vps v$SCRIPT_VERSION"
        return 0
    fi
    printf '%s' "${BOLD}${CYAN}"
    cat <<'BANNER'
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗ 
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
    printf '%s\n' "${NC}   secure-vps v$SCRIPT_VERSION"
    echo
}

fase_0_welcome() {
    clear_screen
    banner
    if ui_visual; then
        ui_text "${PRETTY_NAME:-Ubuntu} · ${PUBLIC_IP:-?} · SSH ${CURRENT_PORT:-22}"
        ui_panel "$(ui 'PREPARAR Y PROTEGER EL VPS' 'PREPARE AND PROTECT THE VPS')"
        ui_text "$(ui 'Recorrerás 8 pasos: administrador, clave pública, actualizaciones, SSH, UFW, Fail2ban, actualizaciones automáticas y puerto opcional.' 'You will follow 8 steps: administrator, public key, updates, SSH, UFW, Fail2ban, automatic updates and optional port.')"
        ui_text "$(ui 'Mantén esta sesión abierta y ten disponible la consola de recuperación del proveedor. Las pruebas SSH se hacen desde otra terminal de tu computadora.' 'Keep this session open and have the provider recovery console available. SSH tests happen in another terminal on your computer.')"
        ui_text "$(ui 'Los cambios de acceso tienen una protección temporal: si no confirmas a tiempo, se restauran SSH, UFW y Fail2ban. No se deshacen usuarios, claves, sudo ni paquetes.' 'Access changes have temporary protection: if you do not confirm in time, SSH, UFW and Fail2ban are restored. Users, keys, sudo and packages are not undone.')"
        if ! confirm "$(ui '¿Tienes la consola de recuperación disponible y quieres comenzar?' 'Is the recovery console available and do you want to begin?')"; then
            return 1
        fi
        log 'Fase 0 completada: advertencia aceptada.'
        return 0
    fi
if [[ $UI_LANG == es ]]; then
cat <<EOF
  ${CYAN}▸${NC} ${BOLD}$PRETTY_NAME${NC} · ${PUBLIC_IP} · como ${ORIGINAL_USER:-root} · puerto ${CURRENT_PORT}
  ${DIM}Idioma: --lang es o --lang en permite fijarlo en futuras ejecuciones.${NC}

  ${BOLD}LO QUE VAMOS A HACER${NC}
   ${CYAN}1${NC}  Usuario administrador con sudo que funciona de verdad
   ${CYAN}2${NC}  Tu clave pública, verificada antes de cerrar nada
   ${CYAN}3${NC}  Límites de sshd, y cierre del root y de la contraseña
   ${CYAN}4${NC}  UFW, avisando de lo que va a bloquear
   ${CYAN}5${NC}  Fail2ban con tu IP excluida de los baneos
   ${CYAN}6${NC}  Actualizaciones automáticas de seguridad
   ${CYAN}7${NC}  Puerto SSH distinto de 22 (opcional; decides tú)

  ${BOLD}LA RED DE SEGURIDAD${NC}
   ${GREEN}·${NC} Cada cambio deja un snapshot y revertir es una opción del menú.
   ${GREEN}·${NC} El rollback devuelve SSH, UFW y fail2ban. No deshace usuarios, sudo,
     claves ni paquetes.
   ${GREEN}·${NC} Al cerrar el acceso arranca una cuenta atrás de ${BOLD}${ROLLBACK_MINUTES} min${NC}: prueba desde
     ${BOLD}otra${NC} terminal y elige conservar/restaurar; sin respuesta, se revierte.

  ${YELLOW}⚠${NC}  ${BOLD}No cierres esta sesión${NC} y mantén abierta la consola VNC del proveedor.
  ${DIM}Idempotente: detecta lo ya configurado y lo omite, puedes repetir.${NC}
EOF
else
cat <<EOF
  ${CYAN}▸${NC} ${BOLD}$PRETTY_NAME${NC} · ${PUBLIC_IP} · as ${ORIGINAL_USER:-root} · port ${CURRENT_PORT}
  ${DIM}Language: use --lang es or --lang en to fix it in future runs.${NC}

  ${BOLD}WHAT WE ARE ABOUT TO DO${NC}
   ${CYAN}1${NC}  An admin user whose sudo actually works
   ${CYAN}2${NC}  Your public key, verified before anything gets closed
   ${CYAN}3${NC}  sshd limits, and closing root and password login
   ${CYAN}4${NC}  UFW, warning you about what it will block
   ${CYAN}5${NC}  Fail2ban with your IP excluded from bans
   ${CYAN}6${NC}  Automatic security updates
   ${CYAN}7${NC}  SSH off port 22 (optional; you decide)

  ${BOLD}THE SAFETY NET${NC}
   ${GREEN}·${NC} Every change leaves a snapshot, and reverting is a menu option.
   ${GREEN}·${NC} Rollback restores SSH, UFW and fail2ban. It does not undo users, sudo,
     keys or packages.
   ${GREEN}·${NC} Closing access starts a ${BOLD}${ROLLBACK_MINUTES} min${NC} countdown: test from
     ${BOLD}another${NC} terminal; choose keep/restore or it reverts automatically.

  ${YELLOW}⚠${NC}  ${BOLD}Do NOT close this session${NC}, and keep the provider VNC console open.
  ${DIM}Idempotent: it detects what is already set and skips it, so you can repeat.${NC}
EOF
fi
    if guided_active; then
        echo
        info "$(ui "Si es tu primer VPS: no hay prisa. Cada fase dice qué hará, qué debes hacer y cómo se protege. En una prueba de acceso, Enter no revierte: vuelve a mostrar la decisión." "If this is your first VPS: no rush. Each phase says what it will do, what you must do, and how it is protected. At an access test, Enter does not revert: it shows the decision again.")"
    fi
    if ! confirm "$(ui "¿Entiendes las advertencias y quieres continuar?" "Do you understand the warnings and want to continue?")"; then
        echo "$(ui "Cancelado por el usuario." "Cancelled by the user.")"
        return 1
    fi
    log "Fase 0 completada: advertencia aceptada."
}

# ============================================================
# FASE 1: USUARIO
# ============================================================
# passwd -S campo 2: P=contraseña activa, L=bloqueada, NP=sin contraseña, E=vacía
# (el `|| true` es por pipefail: sin el usuario, el pipeline mataría al script)
password_state() { passwd -S "$1" 2>/dev/null | awk '{print $2}' || true; }

install_sudoers_policy() {
    local user="$1" tag="$2" file="/etc/sudoers.d/90-$1"
    case "$tag" in PASSWD|NOPASSWD) ;; *) return 1 ;; esac
    printf '%s ALL=(ALL) %s:ALL\n' "$user" "$tag" > "$file.tmp" || return 1
    if visudo -cf "$file.tmp" >/dev/null 2>&1; then
        chmod 0440 "$file.tmp" || return 1
        mv "$file.tmp" "$file" || return 1
        success "$(ui "Drop-in instalado en $file" "Drop-in installed at $file")"
    else
        rm -f "$file.tmp"
        error "$(ui "El drop-in de sudoers no pasó visudo; no lo instalé." "The sudoers drop-in failed visudo; not installed.")"
        return 1
    fi
}

install_sudoers_nopasswd() {
    install_sudoers_policy "$1" NOPASSWD
}

install_sudoers_prompt() {
    local user="$1"
    install_sudoers_policy "$user" PASSWD || return 1
    if ! visudo -c >/dev/null 2>&1 || ! sudo -l -U "$user" -- true >/dev/null 2>&1; then
        error "$(ui "La política sudo efectiva no permite administrar como '$user'. Revisa sudoers antes de continuar." "The effective sudo policy does not allow administration as '$user'. Check sudoers before continuing.")"
        return 1
    fi
    # -k ignora cualquier credencial sudo cacheada para esta comprobación.
    if runuser -u "$user" -- sudo -k -n true 2>/dev/null; then
        error "$(ui "Otra regla sudoers permite sudo sin contraseña para '$user'. Revisa sudo -l -U $user; no daré por aplicada la política con contraseña." "Another sudoers rule allows passwordless sudo for '$user'. Check sudo -l -U $user; I will not report the password policy as applied.")"
        return 1
    fi
    success "$(ui "Comprobado: sudo de '$user' exige contraseña." "Verified: sudo for '$user' requires a password.")"
}

ask_sudo_mode() {
    [[ -n "$SUDO_MODE" ]] && return 0
    if [[ $ASSUME_YES -eq 1 ]]; then
        SUDO_MODE=prompt
        return 0
    fi
    local answer=""
    if ui_visual; then ui_screen "$(ui 'ELEGIR CÓMO USAR SUDO' 'CHOOSE HOW TO USE SUDO')" "$(ui 'Esperando tu decisión' 'Awaiting your decision')"; fi
    echo
    ui_text "  $(ui "'$USERNAME' necesita una forma real de escalar a root:" "'$USERNAME' needs a real way to escalate to root:")"
    ui_text "    $(ui "1) contraseña   (recomendado; sudo la pide en la terminal, no afecta a SSH)" "1) password   (recommended; sudo asks for it in the terminal, unrelated to SSH)")"
    ui_text "    $(ui "2) NOPASSWD     (cómodo, más superficie de ataque si te roban la sesión)" "2) NOPASSWD     (convenient, larger attack surface if your session is stolen)")"
    ui_text "    $(ui "3) conservar la configuración actual (solo si este usuario ya tiene sudo utilizable)" "3) keep the current setup (only if this user already has usable sudo)")"
    ui_read "$(ui "Elige 1/2/3 [1]: " "Choose 1/2/3 [1]: ")" answer || return 1
    case "${answer:-1}" in
        2) SUDO_MODE=nopasswd ;;
        3) SUDO_MODE=keep ;;
        *) SUDO_MODE=prompt ;;
    esac
}

# adduser --disabled-password deja la cuenta con '!' : entra en el grupo sudo
# pero sudo le pide una contraseña que no existe, y no puede escalar.
ensure_usable_sudo() {
    local user="$1" state
    ask_sudo_mode || return 1
    state=$(password_state "$user")

    case "$SUDO_MODE" in
        nopasswd)
            install_sudoers_nopasswd "$user" || return 1
            ;;
        prompt)
            if [[ "$state" == "P" ]]; then
                info "$(ui "$user ya tiene contraseña utilizable." "$user already has a usable password.")"
            elif [[ $NON_INTERACTIVE -eq 1 || ! -t 0 ]]; then
                error "$(ui "'$user' está sin contraseña usable (estado '$state') y no puedo pedirla aquí." "'$user' has no usable password (state '$state') and I cannot prompt for it here.")"
                error "$(ui "Repite con --sudo nopasswd, o ponla a mano: sudo passwd $user" "Retry with --sudo nopasswd, or set it manually: sudo passwd $user")"
                return 1
            else
                warn "$(ui "Escribe ahora la contraseña de '$user'. Se pide en esta terminal;" "Now type the password for '$user'. It is asked in this terminal;")"
                warn "$(ui "deshabilitar el login por contraseña en SSH no afecta a sudo." "disabling SSH password login does not affect sudo.")"
                passwd "$user" || return 1
                [[ "$(password_state "$user")" == "P" ]] || { error "$(ui "La contraseña no quedó activa." "The password did not become active.")"; return 1; }
                success "$(ui "Contraseña de '$user' activa." "Password for '$user' is now active.")"
            fi
            install_sudoers_prompt "$user" || return 1
            ;;
        keep)
            if ! runuser -u "$user" -- sudo -n true 2>/dev/null && [[ "$state" != P ]]; then
                error "$(ui "--sudo keep no es seguro: '$user' no tiene contraseña utilizable ni sudo sin contraseña comprobado." "--sudo keep is not safe: '$user' has no usable password and no verified passwordless sudo.")"
                return 1
            fi
            info "$(ui "Se conserva sudo; compruébalo en la nueva sesión antes de confirmar el acceso." "sudo kept as-is; verify it in the new session before confirming access.")"
            ;;
    esac

    if [[ "$SUDO_MODE" == "nopasswd" ]]; then
        if su - "$user" -c 'sudo -n true' 2>/dev/null; then
            success "$(ui "Comprobado: '$user' ejecuta sudo sin contraseña." "Verified: '$user' can run sudo without a password.")"
        else
            error "$(ui "'$user' NO logra sudo con NOPASSWD. Revisa /etc/sudoers.d/$user" "'$user' CANNOT run sudo with NOPASSWD. Check /etc/sudoers.d/$user")"
            return 1
        fi
    fi
}

prompt_admin_username() {
    ui_text "$(ui 'Escribe el nombre del usuario que usarás para administrar el VPS y pulsa Enter. Por ejemplo: miadmin.' 'Type the username you will use to administer the VPS and press Enter. For example: myadmin.')"
    ui_text "$(ui 'Si ya tienes una cuenta administradora, escribe su nombre. Si el usuario no existe, lo crearé. Aquí se pide un nombre, no una contraseña.' 'If you already have an administrator account, type its username. If the user does not exist, I will create it. This asks for a username, not a password.')"
    while true; do
        ui_read "$(ui 'Escribe el nombre de usuario (ejemplo: miadmin): ' 'Type the username (example: myadmin): ')" USERNAME || return 1
        if valid_username "$USERNAME"; then return 0; fi
        warn "$(ui 'El nombre es obligatorio: usa minúsculas, empieza con una letra y escribe hasta 31 caracteres. No uses root. Escribe el nombre y pulsa Enter.' 'A username is required: use lowercase, start with a letter and enter up to 31 characters. Do not use root. Type the username and press Enter.')"
    done
}

fase_1_user() {
    clear_screen
    header "$(ui "FASE 1: Crear usuario con sudo utilizable" "PHASE 1: Create a usable sudo user")"
    phase_guide "1/7" \
        "Cuenta de administración" "Administration account" \
        "Crearé o revisaré un usuario no-root y comprobaré que puede usar sudo." "I will create or review a non-root user and check that it can use sudo." \
        "Escribe el nombre de la cuenta que usarás cada día y pulsa Enter (ejemplo: miadmin). Si ya tienes un administrador, escribe su nombre." "Type the username you will use every day and press Enter (example: myadmin). If you already have an administrator, type its username." \
        "Esta fase no cambia todavía las reglas de acceso SSH." "This phase does not change SSH access rules yet."

    if [[ -z "$USERNAME" ]]; then
        prompt_admin_username || return 1
    fi
    if ! valid_username "$USERNAME"; then
        error "$(ui "Nombre de usuario inválido para Linux: '$USERNAME'" "Invalid Linux username: '$USERNAME'")"
        error "$(ui "Usa minúsculas, empezando con letra, hasta 31 caracteres." "Use lowercase, starting with a letter, up to 31 characters.")"
        return 1
    fi

    if id "$USERNAME" &>/dev/null; then
        success "$(ui "El usuario '$USERNAME' ya existe. Omitiendo creación." "User '$USERNAME' already exists. Skipping creation.")"
    else
        info "$(ui "Creando usuario '$USERNAME'..." "Creating user '$USERNAME'...")"
        adduser --gecos "" --disabled-password "$USERNAME" || return 1
        USER_CREATED_THIS_RUN=1
        success "$(ui "Usuario creado." "User created.")"
    fi

    if groups "$USERNAME" | grep -qw sudo; then
        success "$(ui "El usuario '$USERNAME' ya tiene sudo." "User '$USERNAME' already has sudo.")"
    else
        usermod -aG sudo "$USERNAME" || return 1
        success "$(ui "Privilegios sudo otorgados a '$USERNAME'." "Sudo privileges granted to '$USERNAME'.")"
    fi

    ensure_usable_sudo "$USERNAME" || return 1

    success "$(ui "Cuenta lista: entra por SSH como '$USERNAME' y usa sudo para administrar." "Account ready: log in over SSH as '$USERNAME' and use sudo to administer.")"

    log "Fase 1 completada: usuario=$USERNAME sudo=$SUDO_MODE"
    pause
}

# ============================================================
# FASE 2: CLAVE SSH
# ============================================================
user_home() { getent passwd "$1" 2>/dev/null | cut -d: -f6 || true; }

install_authorized_key() {
    local user="$1" key="$2"
    local home ssh_dir auth_file
    home=$(user_home "$user")
    if [[ -z "$home" ]]; then
        error "$(ui "No encuentro el home de '$user'." "Cannot find the home directory of '$user'.")"
        return 1
    fi
    ssh_dir="$home/.ssh"
    auth_file="$ssh_dir/authorized_keys"
    mkdir -p "$ssh_dir"
    touch "$auth_file"
    if grep -qF "$key" "$auth_file"; then
        success "$(ui "La clave ya estaba en $auth_file" "The key was already in $auth_file")"
    else
        printf '%s\n' "$key" >> "$auth_file"
        success "$(ui "Clave añadida a $auth_file" "Key added to $auth_file")"
    fi
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_file"
    # No cambiar el dueño de otros archivos en ~/.ssh: podría haber claves
    # privadas u otros datos que el usuario no debía poder leer.
    chown "$user:$user" "$ssh_dir" "$auth_file"
}

_file_mode()  { stat -c '%a' "$1" 2>/dev/null || true; }
_file_owner() { stat -c '%U' "$1" 2>/dev/null || true; }

# True si el modo (octal) concede escritura a grupo o a otros.
world_or_group_writable() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]+$ ]] && (( 8#$mode & 022 ))
}

# StrictModes (activo por defecto) hace que sshd ignore authorized_keys si el
# home o .ssh son escribibles por grupo/otros. Es la causa nº1 de "la clave
# está puesta y aun así pide contraseña".
verify_strictmodes() {
    local user="$1" home home_mode ssh_mode keys_mode keys_owner m
    home=$(user_home "$user")
    if [[ -z "$home" || ! -d "$home/.ssh" ]]; then
        error "$(ui "No encuentro $home/.ssh para '$user'." "Cannot find $home/.ssh for '$user'.")"
        return 1
    fi
    home_mode=$(_file_mode "$home")
    ssh_mode=$(_file_mode "$home/.ssh")
    keys_mode=$(_file_mode "$home/.ssh/authorized_keys")
    keys_owner=$(_file_owner "$home/.ssh/authorized_keys")

    for m in "$home_mode:$home" "$ssh_mode:$home/.ssh" "$keys_mode:$home/.ssh/authorized_keys"; do
        local mode="${m%%:*}" path="${m#*:}"
        if world_or_group_writable "$mode"; then
            warn "$(ui "$path tenía permisos relajados ($mode); endureciendo." "$path had loose permissions ($mode); tightening.")"
            case "$path" in
                *authorized_keys) chmod 600 "$path" ;;
                *)                chmod g-w,o-w "$path" ;;
            esac
        fi
    done
    if [[ -n "$keys_owner" && "$keys_owner" != "$user" && "$keys_owner" != "root" ]]; then
        warn "$(ui "authorized_keys era de '$keys_owner'; lo paso a '$user'." "authorized_keys belonged to '$keys_owner'; reassigning to '$user'.")"
        chown "$user:$user" "$home/.ssh/authorized_keys"
    fi

    home_mode=$(_file_mode "$home")
    ssh_mode=$(_file_mode "$home/.ssh")
    if world_or_group_writable "$home_mode" || world_or_group_writable "$ssh_mode"; then
        error "$(ui "Permisos siguen inválidos para StrictModes (home=$home_mode .ssh=$ssh_mode)." "Permissions still invalid for StrictModes (home=$home_mode .ssh=$ssh_mode).")"
        return 1
    fi
    success "$(ui "Permisos OK para StrictModes (home=$home_mode .ssh=$ssh_mode)." "Permissions OK for StrictModes (home=$home_mode .ssh=$ssh_mode).")"
}

# Claves que ESTE equipo ya acepta hoy (casi siempre la que se subió al crear el
# VPS). Reutilizar una evita que el operador genere y subida nada: se le listan
# con su huella y su archivo de origen para que reconozca la suya.
collect_key_candidates() {
    local f line n=0
    CANDIDATE_KEYS_FILE="$STATE_DIR/candidate_keys.tsv"
    : > "$CANDIDATE_KEYS_FILE" || return 1
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ -f "$f" && -r "$f" ]] || continue
        while IFS= read -r line; do
            case "$line" in ssh-*|ecdsa-*|sk-*) ;; *) continue ;; esac
            if [[ -n "$line" ]] && grep -qF "	$line	" "$CANDIDATE_KEYS_FILE"; then
                continue
            fi
            if validate_pubkey "$line"; then
                n=$((n+1))
                printf '%s\t%s\t%s\t%s\n' "$n" "$line" "$f" "$VALID_FINGERPRINT" \
                    >> "$CANDIDATE_KEYS_FILE"
            fi
        done < "$f"
    done
    [[ $n -gt 0 ]]
}

print_key_candidates() {
    awk -F'\t' '{printf "    %s) %s  [%s]\n", $1, $4, $3}' "$CANDIDATE_KEYS_FILE"
}

pick_key_candidate() {
    awk -F'\t' -v n="$1" '$1 == n { print $2; exit }' "$CANDIDATE_KEYS_FILE"
}

ask_client_os() {
    local answer=""
    if ui_visual; then ui_screen "$(ui 'TU COMPUTADORA' 'YOUR COMPUTER')" "$(ui 'Sin cambios de acceso' 'No access changes')"; fi
    if [[ -t 0 && $NON_INTERACTIVE -eq 0 && $ASSUME_YES -eq 0 ]]; then
        echo
        echo "  $(ui "1) macOS" "1) macOS")"
        echo "  $(ui "2) Windows 10/11 (PowerShell)" "2) Windows 10/11 (PowerShell)")"
        echo "  $(ui "3) Linux u otro" "3) Linux or other")"
        ui_read "$(ui "  ¿Desde qué computadora trabajas? [1/2/3]: " "  Which computer are you working from? [1/2/3]: ")" answer
        case "$answer" in
            1) CLIENT_OS=macos ;;
            2) CLIENT_OS=windows ;;
            *) CLIENT_OS=linux ;;
        esac
    fi
    return 0
}

# Cómo se crea una clave en la máquina del operador. El par NUNCA se genera en
# el VPS: la privada no debe existir ni pasar por el servidor que se endurece.
key_howto_text() {
    if ui_visual; then
        ui_screen "$(ui 'PREPARAR LA CLAVE PÚBLICA' 'PREPARE THE PUBLIC KEY')" "$(ui 'Sin cambios de acceso' 'No access changes')"
        ui_text "$(ui 'En otra terminal de tu computadora, crea el par de claves:' 'In another terminal on your computer, create the key pair:')"
        ui_command 'ssh-keygen -t ed25519' "$(ui 'EN TU COMPUTADORA' 'ON YOUR COMPUTER')"
        ui_text "$(ui 'Acepta la ruta con Enter y elige una frase de protección. Después muestra la parte pública:' 'Accept the path with Enter and choose a passphrase. Then display the public part:')"
        if [[ $CLIENT_OS == windows ]]; then ui_command 'Get-Content "$HOME\.ssh\id_ed25519.pub"' "$(ui 'POWERSHELL EN TU COMPUTADORA' 'POWERSHELL ON YOUR COMPUTER')";
        else ui_command 'cat ~/.ssh/id_ed25519.pub' "$(ui 'EN TU COMPUTADORA' 'ON YOUR COMPUTER')"; fi
        ui_text "$(ui 'Copia la línea que empieza por ssh-ed25519 y pégala aquí. El archivo privado, sin .pub, permanece en tu computadora.' 'Copy the line starting with ssh-ed25519 and paste it here. The private file, without .pub, stays on your computer.')"
        return 0
    fi
    local win=0
    if [[ "$CLIENT_OS" == windows ]]; then
        win=1
    fi
    if [[ $UI_LANG == es ]]; then
        cat <<EOF
  1. Abre la Terminal$([[ $win -eq 1 ]] && echo " (busca 'PowerShell' en el menú de Inicio)") y ejecuta:
       ssh-keygen -t ed25519
     Acepta la ruta con Enter y escribe una contraseña si quieres protegerla.
  2. Muestra SOLO la parte pública:
       $( [[ $win -eq 1 ]] && echo 'Get-Content "$HOME\.ssh\id_ed25519.pub"' || echo 'cat ~/.ssh/id_ed25519.pub' )
  3. Copia esa línea (empieza por 'ssh-ed25519') y pégala cuando este script la pida.

  La clave privada (id_ed25519, sin .pub) NO se copia a ningún lado: se queda en
  tu computadora. Quien la tenga, tiene tu acceso.
EOF
    else
        cat <<EOF
  1. Open a terminal$([[ $win -eq 1 ]] && echo " (search for 'PowerShell' in the Start menu)") and run:
       ssh-keygen -t ed25519
     Accept the default path with Enter, and set a passphrase if you want one.
  2. Print ONLY the public part:
       $( [[ $win -eq 1 ]] && echo 'Get-Content "$HOME\.ssh\id_ed25519.pub"' || echo 'cat ~/.ssh/id_ed25519.pub' )
  3. Copy that line (it starts with 'ssh-ed25519') and paste it when this script asks.

  The private key (id_ed25519, without .pub) is NOT copied anywhere: it stays on
  your computer. Whoever holds it holds your access.
EOF
    fi
}

fase_2_ssh_key() {
    clear_screen
    header "$(ui "FASE 2: Configurar clave SSH" "PHASE 2: Set up the SSH key")"
    phase_guide "2/7" \
        "Clave SSH" "SSH key" \
        "Guardaré solo tu clave pública en la cuenta '$USERNAME'. La clave privada no llega al VPS." "I will save only your public key in account '$USERNAME'. The private key never reaches the VPS." \
        "Desde tu computadora crea o busca la clave pública y pégala aquí. No pegues el archivo privado." "From your computer create or find the public key and paste it here. Do not paste the private-key file." \
        "Todavía no cerraré root ni la contraseña. Primero tendrás que probar la clave desde otra terminal." "I will not close root or password access yet. First you will test the key from another terminal."

    resolve_pubkey
    if [[ -z "$SSH_PUBKEY" ]]; then
        info "$(ui "Necesitas añadir una clave pública SSH a '$USERNAME'. Esta acción ocurre en dos lugares: la clave se crea en TU computadora y aquí solo se pega la parte pública." "You need to add an SSH public key to '$USERNAME'. This happens in two places: the key is created on YOUR computer and only its public part is pasted here.")"
        echo
        if guided_active && collect_key_candidates; then
            if ui_visual; then ui_screen "$(ui 'ELEGIR UNA CLAVE EXISTENTE' 'CHOOSE AN EXISTING KEY')" "$(ui 'Sin cambios de acceso' 'No access changes')"; fi
            ui_text "$(ui "Ya hay claves autorizadas en este VPS. Elige una SOLO si reconoces su huella y sabes que tu computadora conserva la clave privada correspondiente:" "This VPS already has authorized keys. Choose one ONLY if you recognize its fingerprint and know your computer still has the matching private key:")"
            print_key_candidates
            echo
            ui_read "$(ui "  Número de TU clave (o Enter para pegar una distinta): " "  Number of YOUR key (or Enter to paste a different one): ")" choice || return 1
            if [[ -n "$choice" ]]; then
                SSH_PUBKEY=$(pick_key_candidate "$choice")
                if [[ -n "$SSH_PUBKEY" ]]; then
                    success "$(ui "Reutilizando la clave número $choice." "Reusing key number $choice.")"
                else
                    warn "$(ui "Ese número no estaba en la lista; puedes pegar la clave abajo." "That number was not in the list; you can paste the key below.")"
                fi
            fi
        fi
        if [[ -z "$SSH_PUBKEY" ]]; then
            if guided_active; then
                ui_text "$(ui "Para entrar por SSH sin contraseña hace falta un par de claves. Se crea en TU computadora, no aquí:" "To log in over SSH without a password you need a key pair. It is created on YOUR computer, not here:")"
                ask_client_os
                key_howto_text
                echo
                if [[ $USER_CREATED_THIS_RUN -eq 1 ]]; then
                    warn "$(ui "'$USERNAME' se creó sin contraseña SSH. No uses ssh-copy-id: normalmente no podrá entrar. Pega la línea .pub abajo." "'$USERNAME' was created without an SSH password. Do not use ssh-copy-id: it normally cannot log in. Paste the .pub line below.")"
                elif [[ "$CLIENT_OS" != windows ]]; then
                    info "$(ui "Alternativa solo para un usuario existente cuya contraseña SSH conoces: ssh-copy-id -p $CURRENT_PORT $USERNAME@$PUBLIC_IP. Si no estás seguro, pega la pública abajo." "Alternative only for an existing user whose SSH password you know: ssh-copy-id -p $CURRENT_PORT $USERNAME@$PUBLIC_IP. If unsure, paste the public key below.")"
                fi
            else
                ui_text "$(ui "Pega una sola línea de clave pública. No pegues la clave privada." "Paste one public-key line only. Do not paste the private key.")"
                echo
            fi
            while [[ -z "$SSH_PUBKEY" ]]; do
                ui_text "$(ui "Pega aquí la clave pública (la línea que empieza por ssh-ed25519, ssh-rsa o ecdsa-...):" "Paste the public key here (the line beginning ssh-ed25519, ssh-rsa or ecdsa-...):")"
                if ! ui_read "$(ui "Clave pública SSH (Enter muestra opciones seguras): " "SSH public key (Enter shows safe options): ")" SSH_PUBKEY; then
                    return 1
                fi
                resolve_pubkey
                [[ -n "$SSH_PUBKEY" ]] && break

                if ui_visual; then ui_screen "$(ui 'FALTA LA CLAVE PÚBLICA' 'PUBLIC KEY MISSING')" "$(ui 'Pendiente' 'Pending')"; fi
                warn "$(ui "No se recibió una clave. Sin una clave probada no es seguro cerrar root ni el acceso con contraseña." "No key was received. Without a tested key it is not safe to close root or password access.")"
                ui_text "  1) $(ui "Volver a ver las instrucciones y pegar la clave" "Review the instructions and paste the key")"
                ui_text "  2) $(ui "Aplicar solo límites no restrictivos; root y la contraseña SEGUIRÁN activos" "Apply only non-restrictive limits; root and password will STAY enabled")"
                ui_text "  3) $(ui "Salir sin continuar con el hardening de SSH" "Exit without continuing SSH hardening")"
                local no_key_choice=""
                if ! ui_read "$(ui "Elige 1/2/3: " "Choose 1/2/3: ")" no_key_choice; then
                    return 1
                fi
                case "$no_key_choice" in
                    1)
                        if guided_active; then
                            key_howto_text
                        fi
                        ;;
                    2)
                        UI_PHASE_RESULT="$(ui 'Pendiente; falta una clave SSH' 'Pending; SSH key missing')"
                        KEY_READY=0
                        OPT_SKIP_LOCKDOWN=1
                        warn "$(ui "Continuarás con límites parciales. Root y el acceso por contraseña no se cerrarán." "You will continue with partial limits. Root and password access will not be closed.")"
                        log "Fase 2 omitida por falta de clave; fase 3 sin cierre de acceso."
                        pause
                        return 0
                        ;;
                    3)
                        info "$(ui "No se aplicó hardening de SSH. Cuando tengas la clave pública, vuelve a ejecutar la fase 2." "No SSH hardening was applied. Run phase 2 again when you have the public key.")"
                        return 1
                        ;;
                    *)
                        warn "$(ui "Elige 1, 2 o 3. No haré cambios de acceso hasta que decidas." "Choose 1, 2 or 3. I will make no access changes until you decide.")"
                        ;;
                esac
            done
        fi
    fi

    if [[ -z "$SSH_PUBKEY" ]]; then
        # Solo se alcanza desde entrada no interactiva inválida o si una futura
        # ruta salta el bucle anterior. Nunca se convierte un Enter accidental
        # en --skip-lockdown.
        error "$(ui "No hay clave pública; detengo esta fase sin tocar el acceso SSH." "There is no public key; stopping this phase without changing SSH access.")"
        return 1
    fi

    if ! validate_pubkey "$SSH_PUBKEY"; then
        error "$(ui "Esa clave pública no es válida: ssh-keygen la rechaza." "That public key is not valid: ssh-keygen rejects it.")"
        error "$(ui "Debe empezar con un tipo reconocido (ssh-ed25519, ssh-rsa, ecdsa-sha2-...) y base64 intacto." "It must start with a known type (ssh-ed25519, ssh-rsa, ecdsa-sha2-...) and have intact base64.")"
        return 1
    fi
    success "$(ui "Clave válida: $VALID_FINGERPRINT" "Valid key: $VALID_FINGERPRINT")"

    install_authorized_key "$USERNAME" "$SSH_PUBKEY" || return 1
    verify_strictmodes "$USERNAME" || return 1

    KEY_READY=1
    KEY_TESTED=0
    success "$(ui "Clave instalada. Aún no cerré nada: la fase 3 primero te pedirá probar ESTA clave desde otra terminal." "Key installed. Nothing is closed yet: phase 3 will first ask you to test THIS key from another terminal.")"
    log "Fase 2 completada: $VALID_FINGERPRINT"
    pause
}

# ============================================================
# FASE 2.5: ACTUALIZACIONES PENDIENTES
# ============================================================
# El orden importa: se reportan al arrancar (es gratis y cambia la conversación)
# y se aplican AQUI, con la clave ya verificada y antes de cerrar el acceso. Si
# un upgrade rompe algo, todavía se puede entrar con la contraseña del proveedor.
apt_pending_counts() {
    local sim
    # Formato real: "Inst libfreetype6 [2.11.2-2] (2.11.2-3 Ubuntu:24.04/noble-security [amd64])"
    # No hay número tras 'Inst': contar por nombre, y tratar como de seguridad
    # lo que menciona security en el origen (es heurístico, orienta, no miente).
    sim=$(LANG=C apt-get -s -o quiet=version upgrade 2>/dev/null) || true
    PENDING_COUNT=$(printf '%s\n' "$sim" | awk '/^Inst /{n++} END{print n+0}')
    PENDING_SECURITY=$(printf '%s\n' "$sim" | awk '/^Inst / && /security/{n++} END{print n+0}')
}

report_pending_updates() {
    # Con reintentos y timeout cortos: un DNS roto en el VPS no debe dejar el
    # script colgado antes de empezar. Si falla, se avisa y se sigue.
    if ! apt-get update -qq -o Acquire::Retries=1 -o Acquire::http::Timeout=8 \
            >> "$LOG_FILE" 2>&1; then
        warn "$(ui "No pude refrescar los índices de apt (¿sin red?): no sé cuántos paquetes faltan." "Could not refresh the apt indexes (no network?): I cannot tell how many packages are missing.")"
        return 0
    fi
    apt_pending_counts
    if [[ "${PENDING_COUNT:-0}" -eq 0 ]]; then
        success "$(ui "El sistema está al día según los índices actuales." "The system is up to date according to the current indexes.")"
    else
        warn "$(ui "Hay $PENDING_COUNT paquetes actualizables ($PENDING_SECURITY de seguridad)." "There are $PENDING_COUNT upgradable packages ($PENDING_SECURITY of them security).")"
        info "$(ui "Los aplicaré antes de cerrar el acceso, cuando aún puedes entrar con contraseña." "I will apply them before locking down, while password access still works.")"
    fi
    return 0
}

reboot_hint() {
    local when="${1:-now}"
    if [[ -f "$REBOOT_FLAG" ]]; then
        warn "$(ui "Hace falta reiniciar: el kernel que está corriendo sigue siendo el viejo, así que los parches nuevos aún no hacen efecto." "A reboot is needed: the running kernel is still the old one, so the new patches are not in effect yet.")"
        if [[ "$when" == after_access_test ]]; then
            info "$(ui "No reinicies todavía. Primero termina las pruebas de acceso y confirma los cambios; después ejecuta: sudo reboot. Al volver, usa la opción 2.3 para verificar." "Do not reboot yet. First finish the access tests and confirm the changes; then run: sudo reboot. Once back, use option 2.3 to verify.")"
        else
            echo "    sudo reboot"
        fi
    fi
    return 0
}

fase_2b_updates() {
    clear_screen
    header "$(ui "FASE 2.5: Aplicar actualizaciones pendientes" "PHASE 2.5: Apply the pending updates")"
    phase_guide "2.5/7" \
        "Actualizaciones de hoy" "Today's updates" \
        "Aplicaré los paquetes pendientes antes del cierre de SSH, mientras aún existe una ruta de recuperación." "I will apply pending packages before SSH lockdown, while a recovery path still exists." \
        "Decide si quieres aplicarlas ahora. Si se pide reiniciar, termina primero las pruebas de acceso de este asistente." "Decide whether to apply them now. If a reboot is needed, finish this assistant's access tests first." \
        "Un reinicio posterior activa parches de kernel; no cambia por sí solo las reglas SSH." "A later reboot activates kernel patches; it does not itself change SSH rules."

    if [[ $UPGRADE_MODE == no ]]; then
        info "$(ui "--no-upgrade: dejo las pendientes para unattended-upgrades (fase 6)." "--no-upgrade: leaving the pending ones to unattended-upgrades (phase 6).")"
        UI_PHASE_RESULT="$(ui 'Sin cambios; revisa las actualizaciones pendientes' 'No changes; review pending updates')"
        pause
        return 0
    fi
    apt_pending_counts
    if [[ "${PENDING_COUNT:-0}" -eq 0 ]]; then
        success "$(ui "Nada pendiente que aplicar." "Nothing pending to apply.")"
        reboot_hint after_access_test
        UI_PHASE_RESULT="$(ui 'Sin cambios; no hay paquetes pendientes' 'No changes; no pending packages')"
        pause
        return 0
    fi
    if [[ $NON_INTERACTIVE -eq 1 && $UPGRADE_MODE != yes ]]; then
        warn "$(ui "Modo desatendido: no actualizo por tu cuenta. Repite con --upgrade si quieres que lo haga ahora." "Unattended mode: I will not upgrade on my own. Repeat with --upgrade to have it done now.")"
        UI_PHASE_RESULT="$(ui 'Sin cambios; revisa las actualizaciones pendientes' 'No changes; review pending updates')"
        pause
        return 0
    fi
    if [[ $UPGRADE_MODE != yes ]] && ! confirm "$(ui "Quedan $PENDING_COUNT paquetes ($PENDING_SECURITY de seguridad). ¿Los aplico ahora, antes de cerrar el acceso? Puede tardar varios minutos." "$PENDING_COUNT packages remain ($PENDING_SECURITY of them security). Apply them now, before locking down? It may take several minutes.")"; then
        info "$(ui "Los dejas pendientes; la fase 6 hará que se apliquen solos más adelante." "You leave them pending; phase 6 will have them applied on their own later.")"
        UI_PHASE_RESULT="$(ui 'Sin cambios; revisa las actualizaciones pendientes' 'No changes; review pending updates')"
        pause
        return 0
    fi
    info "$(ui "Aplicando actualizaciones (sin retirar ni instalar paquetes nuevos)..." "Applying updates (removing and installing no new packages)...")"
    if ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
            -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef >> "$LOG_FILE" 2>&1; then
        error "$(ui "El upgrade falló: revisa $LOG_FILE y /var/log/dpkg.log. Me detengo ANTES de tocar el acceso." "The upgrade failed: check $LOG_FILE and /var/log/dpkg.log. I stop BEFORE touching access.")"
        return 1
    fi
    success "$(ui "Actualizaciones aplicadas." "Updates applied.")"
    reboot_hint after_access_test
    log "Fase 2.5 completada: upgrades=$PENDING_COUNT security=$PENDING_SECURITY"
    pause
}

# ============================================================
# FASE 3: ENDURECER SSH
# ============================================================
# Los límites no cierran acceso; las líneas de cierre van solo con clave verificada.
write_hardening_file() {
    # Las líneas Port las escribió la fase 7: este archivo es nuestro, así que
    # hay que preservarlas o volver a correr el script devolvería SSH al 22
    # mientras UFW y fail2ban siguen apuntando al puerto nuevo.
    local puertos_existentes="" acceso_existente=""
    if [[ -f "$HARDENING_FILE" ]]; then
        puertos_existentes=$(awk '$1 == "Port" {print $2}' "$HARDENING_FILE") || return 1
        acceso_existente=$(awk '$1 ~ /^(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|AllowUsers)$/ {print}' "$HARDENING_FILE") || return 1
    fi

    cat > "$HARDENING_FILE" <<EOF || return 1
# Generado por secure-vps; se reescribe al volver a ejecutar.
EOF

    cat >> "$HARDENING_FILE" <<EOF || return 1

# --- Límites de seguridad ---
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 2
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
PubkeyAuthentication yes
EOF
    if [[ $LOCKDOWN -eq 1 ]]; then
        cat >> "$HARDENING_FILE" <<EOF || return 1

# --- Cierre de acceso (fase 3; requiere clave verificada en fase 2) ---
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers $USERNAME
EOF
    else
        printf '\n%s\n' "$acceso_existente" >> "$HARDENING_FILE" || return 1
    fi
    # Port al final, igual que hardening_set_ports: re-ejecutar debe producir
    # bytes idénticos o el rollback por checksum no será exacto.
    local p
    for p in $puertos_existentes; do
        printf 'Port %s\n' "$p" >> "$HARDENING_FILE" || return 1
    done
}

# Pregunta a sshd cómo respondería para ese usuario, con la config nueva en disco.
# Si sshd no nos dice nada, NO se asume bueno: sin evidencia no se cierra el acceso.
verify_effective_access() {
    local out="" client_addr=127.0.0.1 policy
    ensure_sshd_runtime || return 1
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        client_addr="${SSH_CONNECTION%% *}"
        [[ "$client_addr" =~ ^[0-9a-fA-F:.]+$ ]] || return 1
    fi
    out=$(sshd -T -C "user=$USERNAME,host=$client_addr,addr=$client_addr") || return 1
    if [[ -z "$out" ]]; then
        error "$(ui "No pude leer la configuración SSH efectiva; no cerraré el acceso." "Could not read the effective SSH configuration; I will not lock down.")"
        return 1
    fi
    if ! grep -qE '^pubkeyauthentication yes' <<< "$out"; then
        error "$(ui "sshd no permitiría autenticación por clave para '$USERNAME'." "sshd would not allow key authentication for '$USERNAME'.")"
        return 1
    fi
    if grep -qE '^allowusers ' <<< "$out"; then
        if ! awk '/^allowusers /{$1="";print}' <<< "$out" | tr ' ' '\n' \
             | grep -qx "$USERNAME"; then
            error "$(ui "El AllowUsers efectivo no incluye a '$USERNAME': quedarías fuera." "The effective AllowUsers does not include '$USERNAME': you would be locked out.")"
            return 1
        fi
    fi
    if [[ $LOCKDOWN -eq 1 ]]; then
        for policy in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitrootlogin no'; do
            if ! grep -qxF "$policy" <<< "$out"; then
                error "$(ui "No se aplicó la política: $policy. Revisa otros archivos SSH y bloques Match." "Policy not applied: $policy. Check other SSH files and Match blocks.")"
                return 1
            fi
        done
    fi
    success "$(ui "Políticas SSH comprobadas; falta probar una conexión nueva con clave y sudo." "SSH policies verified; still need to test a fresh connection with key and sudo.")"
}

# IPs con sesión SSH abierta ahora: leer de utmp con 'who' no depende del
# entorno de sudo, que suele limpiar SSH_CONNECTION.
current_admin_ips() {
    who 2>/dev/null | sed -nE 's/.*\(([0-9a-fA-F:.]+)\).*/\1/p' | sort -u | tr '\n' ' ' \
        | sed 's/[[:space:]]*$//' || true
}

# Una consola de proveedor (VNC/KVM/serie) no es una sesión SSH: no existe
# SSH_CONNECTION y 'who' no lista ninguna IP. Desde ahí no se puede probar un
# login nuevo, así que ningún paso que cierre el acceso es confirmable.
detect_session_kind() {
    ON_CONSOLE=0
    if [[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ]]; then
        return 0
    fi
    if [[ -n "$(current_admin_ips)" ]]; then
        return 0
    fi
    ON_CONSOLE=1
    return 0
}

# La guía larga solo molesta a quien ya sabe SSH: se activa sola en los dos
# casos reales de novato (llega sin clave, o desde la consola del proveedor).
# Se resuelve UNA vez, con el estado de runtime ya conocido: si no, la fase 2
# rellena SSH_PUBKEY y las fases de después decidirían que no hacía falta guiar.
guided_active() { [[ $GUIDED -eq 1 ]]; }

resolve_guided_mode() {
    GUIDED=0
    case "$GUIDED_MODE" in
        on)  GUIDED=1; return 0 ;;
        off) return 0 ;;
    esac
    if [[ $ON_CONSOLE -eq 1 ]]; then
        GUIDED=1
        return 0
    fi
    if [[ -z "$SSH_PUBKEY" && -z "$PUBKEY_FILE" ]]; then
        GUIDED=1
    fi
    return 0
}

ssh_test_command() {
    local port="${1:-$CURRENT_PORT}"
    printf 'ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o IdentitiesOnly=no -p %s %s@%s' \
        "$port" "$USERNAME" "$PUBLIC_IP"
}

# Imprime la misma prueba antes de cerrar SSH, después de modificar SSH, tras
# activar UFW y durante un cambio de puerto. La consola web del proveedor es
# deliberadamente excluida: permite recuperar el VPS, pero no demuestra que
# una conexión SSH nueva desde Internet funcione.
show_access_test_steps() {
    local port="${1:-$CURRENT_PORT}" context="${2:-}"
    UI_ACCESS_PORT="$port"
    UI_ACCESS_CONTEXT="$context"
    if ui_visual; then
        ui_screen "$(ui 'PRUEBA DE ACCESO' 'ACCESS TEST')" "$(ui 'Esperando prueba' 'Awaiting test')"
    fi
    echo
    ui_text "$(ui "PRUEBA DE ACCESO DESDE OTRA TERMINAL" "ACCESS TEST FROM ANOTHER TERMINAL")"
    [[ -n "$context" ]] && info "$context"
    ui_text "1. $(ui "Deja ESTA terminal abierta como respaldo." "Keep THIS terminal open as your backup.")"
    ui_text "2. $(ui "En otra terminal de TU computadora ejecuta:" "In another terminal on YOUR computer run:")"
    ui_command "$(ssh_test_command "$port")" "$(ui 'OTRA TERMINAL DE TU COMPUTADORA' 'ANOTHER TERMINAL ON YOUR COMPUTER')"
    ui_text "3. $(ui "La nueva sesión debe mostrar el usuario '$USERNAME'. Allí ejecuta:" "The new session must show user '$USERNAME'. There run:")"
    ui_command "whoami && sudo -v && sudo -l" "$(ui 'DENTRO DE LA NUEVA SESIÓN SSH' 'INSIDE THE NEW SSH SESSION')"
    ui_text "4. $(ui "Vuelve a esta terminal solo cuando esos pasos funcionen." "Return to this terminal only after those steps work.")"
    info "$(ui "Si tu clave privada no usa la ruta habitual, añade -i /ruta/a/tu_clave al comando." "If your private key is not in the usual location, add -i /path/to/your_key to the command.")"
    warn "$(ui "La consola web/VNC del proveedor sirve para recuperar el VPS; NO valida esta prueba SSH externa." "The provider web/VNC console is for VPS recovery; it does NOT validate this external SSH test.")"
}

# Las respuestas humanas deben ser fáciles de acertar. Se aceptan los tokens
# antiguos para compatibilidad, pero la pantalla pide s/y o n. Enter o un
# texto desconocido vuelven a explicar la pregunta: nunca provocan rollback
# por un error de formato.
ask_access_result() {
    local keep_es="$1" keep_en="$2" restore_es="$3" restore_en="$4" response=""
    if ui_visual; then
        ui_panel "$(ui '¿La prueba funcionó?' 'Did the test work?')"
        ui_text "1) $(ui "$keep_es" "$keep_en")"
        ui_text "2) $(ui "$restore_es" "$restore_en")"
        ui_text "$(ui 'h) Ayuda · Enter mantiene la decisión pendiente' 'h) Help · Enter leaves the decision pending')"
    fi
    local prompt
    prompt="$(ui "¿La prueba funcionó? [s] $keep_es  [n] $restore_es: " "Did the test work? [y] $keep_en  [n] $restore_en: ")"
    ui_visual && prompt='> '
    while true; do
        if ! read -rp "$prompt" response; then
            return 1
        fi
        case "$response" in
            1|s|S|y|Y|acceso-ok|access-ok) return 0 ;;
            2|n|N|r|R|revertir|revert|restore) return 1 ;;
            h|H|\?)
                ui_help
                ;;
            "")
                info "$(ui "Aún no se tomó ninguna decisión. Termina la prueba en la otra terminal y responde s o n." "No decision has been made yet. Finish the test in the other terminal and answer y or n.")"
                ;;
            *)
                warn "$(ui "No entendí '$response'. Responde s para conservar o n para restaurar; la cuenta atrás sigue protegiéndote." "I did not understand '$response'. Answer y to keep or n to restore; the countdown is still protecting you.")"
                ;;
        esac
    done
}

# Se usa antes de cualquier cierre. No hay cambios que revertir todavía: si la
# prueba falla, simplemente se deja el acceso por contraseña abierto y se
# explica la siguiente acción.
confirm_key_preflight() {
    local port="${1:-$CURRENT_PORT}"
    show_access_test_steps "$port" "$(ui "Esta es la prueba PREVIA: todavía no cerraré root ni el acceso con contraseña." "This is the PRE-CHECK: root and password access are not closed yet.")"
    if ask_access_result \
        "La clave funciona; continuar con el cierre" "The key works; continue with the lockdown" \
        "No funcionó; detener y revisar" "It did not work; stop and review"; then
        KEY_TESTED=1
        success "$(ui "Prueba previa confirmada. Ahora sí es seguro aplicar el cierre de SSH." "Pre-check confirmed. It is now safe to apply the SSH lockdown.")"
        return 0
    fi
    KEY_TESTED=0
    UI_PHASE_RESULT="$(ui 'Pendiente; la prueba SSH no fue confirmada' 'Pending; SSH test was not confirmed')"
    UI_ACCESS_PRECHECK_FAILED=1
    warn "$(ui "La clave no quedó confirmada. No cerraré root ni la contraseña en esta ejecución." "The key was not confirmed. I will not close root or password access in this run.")"
    info "$(ui 'Detengo este recorrido antes de cambiar SSH o activar UFW. Mantén esta sesión abierta.' 'Stopping this flow before changing SSH or enabling UFW. Keep this session open.')"
    info "$(ui 'Permission denied significa que el servidor respondió, pero no aceptó la clave ofrecida. Comprueba que la clave privada de tu computadora corresponde a la pública instalada para este usuario.' 'Permission denied means the server responded but did not accept the offered key. Check that your computer private key matches the public key installed for this user.')"
    info "$(ui 'Si usaste la ruta habitual al crear la clave, prueba este comando en TU computadora:' 'If you used the usual path when creating the key, try this command on YOUR computer:')"
    ui_command "ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -p $port $USERNAME@$PUBLIC_IP" "$(ui 'TU COMPUTADORA · SOLO SI ESA ES TU CLAVE' 'YOUR COMPUTER · ONLY IF THAT IS YOUR KEY')"
    info "$(ui 'Si tu clave tiene otra ruta, reemplaza ~/.ssh/id_ed25519 por la ruta del archivo privado, sin .pub. No lo copies al VPS.' 'If your key has another path, replace ~/.ssh/id_ed25519 with the private file path, without .pub. Do not copy it to the VPS.')"
    info "$(ui 'En el menú, 1.2 permite revisar o cambiar la clave pública; 1.4 repite la prueba. No confirmes éxito hasta que SSH y sudo funcionen.' 'In the menu, 1.2 lets you review or replace the public key; 1.4 repeats the test. Do not confirm success until SSH and sudo work.')"
    return 1
}

confirm_access() {
    local port="${1:-$CURRENT_PORT}" motivo="${2:-}" default_reason=""
    default_reason="$(ui "Esta es la prueba POSTERIOR al cambio; confirma que el cambio ya aplicado sigue siendo accesible." "This is the POST-CHANGE test; confirm that the change already applied remains accessible.")"
    show_access_test_steps "$port" "${motivo:-$default_reason}"
    if [[ $ROLLBACK_ARMED -eq 1 ]]; then
        warn "$(ui "Protección temporal activa durante ~${ROLLBACK_MINUTES} min. Si eliges restaurar o no confirmas, volverán SSH, UFW y Fail2ban al estado anterior a esta fase." "Temporary protection is active for ~${ROLLBACK_MINUTES} min. If you choose restore or do not confirm, SSH, UFW and Fail2ban return to their state before this phase.")"
        info "$(ui "Usuario, clave instalada, sudo y actualizaciones no se eliminan. No necesitas tocar el temporizador: se cancela automáticamente al conservar los cambios." "The user, installed key, sudo and updates are not removed. You do not need to touch the timer: it is cancelled automatically when you keep the changes.")"
    fi
    if ask_access_result \
        "Conservar cambios y continuar" "Keep changes and continue" \
        "restaurar cambios de acceso" "restore access changes"; then
        ACCESS_TEST_CONFIRMED=1
        return 0
    fi
    return 1
}

revert_now() {
    local reason="$1"
    error "$reason"
    local target="$SNAP_DIR"
    if [[ $ROLLBACK_ARMED -eq 1 ]]; then
        target="$ROLLBACK_SNAP_DIR"
    fi
    if [[ -z "$target" || ! -f "$target/READY" ]]; then
        error "$(ui "No hay snapshot válido; no borraré configuración existente. Usa la consola del proveedor." "No valid snapshot; I will not delete existing configuration. Use the provider console.")"
        return 1
    fi
    install_rollback_bin || return 1
    info "$(ui "Revirtiendo desde $target" "Reverting from $target")"
    if "$ROLLBACK_BIN" "$target"; then
        if [[ $ROLLBACK_ARMED -eq 1 ]]; then
            kill_rollback_timer "$ROLLBACK_JOB" || return 1
            ROLLBACK_ARMED=0
        fi
        RECOVERY_OCCURRED=1
        RECOVERY_REASON="$reason"
        success "$(ui "RESTAURACIÓN SEGURA COMPLETADA." "SAFE RESTORATION COMPLETED.")"
        info "$(ui "Volvieron SSH, UFW y Fail2ban al estado anterior a esta fase. Tu usuario, clave instalada, sudo y actualizaciones permanecen." "SSH, UFW and Fail2ban returned to their state before this phase. Your user, installed key, sudo and updates remain.")"
        info "$(ui "Siguiente paso: revisa la prueba indicada, conserva esta sesión abierta y vuelve a ejecutar solo la fase pendiente." "Next step: review the indicated test, keep this session open, and run only the pending phase again.")"
    else
        error "$(ui "El rollback pidió atención manual: usa la consola VNC del proveedor." "The rollback needs manual attention: use the provider VNC console.")"
        return 1
    fi
}

show_effective_ssh() {
    info "$(ui "Configuración efectiva:" "Effective configuration:")"
    sshd -T 2>/dev/null \
        | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|maxsessions|allowusers|clientaliveinterval)" \
        | sed 's/^/    /' || true
}

# ¿Queda ya una clave usable para ese usuario? (la instalamos en otra ejecución)
existing_key_present() {
    local user="$1" home auth
    home=$(user_home "$user")
    auth="$home/.ssh/authorized_keys"
    [[ -s "$auth" ]] || return 1
    # Al menos una línea que sea una clave pública válida.
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if validate_pubkey "$line"; then
            success "$(ui "Veo una clave instalada para '$user': $VALID_FINGERPRINT" "Found an installed key for '$user': $VALID_FINGERPRINT")"
            return 0
        fi
    done < "$auth"
    return 1
}

# AllowUsers vacío significa "nadie puede entrar": bloquear por si acaso.
lockdown_possible() {
    if [[ -z "$USERNAME" ]]; then
        error "$(ui "Fase 1 no ejecutada: sin usuario no puedo escribir AllowUsers." "Phase 1 not run: without a user I cannot write AllowUsers.")"
        return 1
    fi
    if ! valid_username "$USERNAME" || ! id "$USERNAME" >/dev/null 2>&1; then
        error "$(ui "El usuario administrador no es válido o no existe." "The admin user is not valid or does not exist.")"
        return 1
    fi
    if [[ "$(id -u "$USERNAME")" == "0" ]]; then
        error "$(ui "Permitiría el acceso solo a root, que es justo lo que queremos cerrar." "It would allow access only to root, which is exactly what we want to close.")"
        return 1
    fi
    return 0
}

fase_3_harden_ssh() {
    clear_screen
    header "$(ui "FASE 3: Endurecer configuración SSH" "PHASE 3: Harden the SSH configuration")"
    RECOVERY_OCCURRED=0
    RECOVERY_REASON=""
    phase_guide "3/7" \
        "Proteger el acceso SSH" "Protect SSH access" \
        "Aplicaré límites de SSH y, solo con una clave probada, desactivaré root y la autenticación por contraseña para '$USERNAME'." "I will apply SSH limits and, only with a tested key, disable root and password authentication for '$USERNAME'." \
        "Mantén esta sesión abierta. Antes del cierre probarás una conexión nueva desde otra terminal de tu computadora; después la repetirás con el cambio activo." "Keep this session open. Before lockdown you will test a new connection from another terminal on your computer; then repeat it with the change active." \
        "Si la segunda prueba falla, una cuenta atrás restaura SSH, UFW y Fail2ban; tu usuario, clave y sudo permanecen." "If the second test fails, a countdown restores SSH, UFW and Fail2ban; your user, key and sudo remain."
    LOCKDOWN=1

    # Una fase ejecutada desde el menú puede venir después de un cambio de
    # puerto. La prueba previa debe mostrar el listener efectivo de AHORA,
    # nunca un valor que quedó de una fase anterior.
    detect_ssh_activation
    CURRENT_PORT=$(current_ssh_port)
    ssh_activation_summary

    if [[ $KEY_READY -ne 1 ]]; then
        if [[ -n "$USERNAME" ]] && existing_key_present "$USERNAME"; then
            if [[ $NON_INTERACTIVE -eq 0 && $ON_CONSOLE -eq 0 && $OPT_SKIP_LOCKDOWN -eq 0 ]]; then
                if ! confirm_key_preflight "$CURRENT_PORT"; then KEY_READY=0; return 1; fi
                KEY_READY=1
                log "$(ui "Fase 3: clave preexistente confirmada por el operador." "Phase 3: pre-existing key confirmed by the operator.")"
            else
                info "$(ui "Hay una clave, pero no quedó probada desde otra terminal: mantendré el acceso abierto." "There is a key, but it was not tested from another terminal: I will keep access open.")"
            fi
        fi
    fi
    if [[ $KEY_READY -eq 1 && $KEY_TESTED -ne 1 && $NON_INTERACTIVE -eq 0 && $ON_CONSOLE -eq 0 && \
          $OPT_SKIP_LOCKDOWN -eq 0 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        if ! confirm_key_preflight "$CURRENT_PORT"; then
            KEY_READY=0
            return 1
        fi
    fi
    if [[ $KEY_READY -ne 1 ]] || [[ $OPT_SKIP_LOCKDOWN -eq 1 ]] || ! lockdown_possible; then
        LOCKDOWN=0
    fi
    # Desde la consola no hay como verificar la conexión nueva: el cierre queda
    # pendiente hasta que se corra de nuevo por SSH. --allow-lockdown lo fuerza.
    if [[ $ON_CONSOLE -eq 1 && $ALLOW_LOCKDOWN -eq 0 && $NON_INTERACTIVE -eq 0 ]]; then
        LOCKDOWN=0
    fi
    if [[ $LOCKDOWN -eq 0 ]]; then
        UI_PHASE_RESULT="$(ui 'Aplicado parcialmente; acceso pendiente' 'Partially applied; access pending')"
        warn "$(ui "HARDENING PARCIAL: NO cerraré root ni el acceso por contraseña." "PARTIAL HARDENING: I will NOT close root or password access.")"
        info "$(ui "Sí aplicaré límites de SSH que no cierran sesiones (intentos, sesiones, X11 y keepalive)." "I will apply SSH limits that do not close sessions (attempts, sessions, X11 and keepalive).")"
        [[ $KEY_READY -ne 1 ]] && info "$(ui "Motivo: no hay clave verificada en la fase 2." "Reason: no key was verified in phase 2.")"
        [[ $OPT_SKIP_LOCKDOWN -eq 1 ]] && info "$(ui "Motivo: elegiste conservar el acceso abierto hasta tener una clave probada." "Reason: you chose to keep access open until you have a tested key.")"
        if [[ $ON_CONSOLE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            info "$(ui "Motivo: estás en la consola del proveedor; sirve para recuperar el VPS, pero no para probar una conexión SSH externa." "Reason: you are on the provider console; it recovers the VPS but cannot test an external SSH connection.")"
        fi
        info "$(ui "Siguiente paso: desde tu computadora instala o prueba la clave en la fase 2 y vuelve a ejecutar esta fase." "Next step: from your computer install or test the key in phase 2, then run this phase again.")"
    fi
    snapshot_state || return 1
    if [[ $LOCKDOWN -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        arm_rollback || return 1
    fi

    info "$(ui "Escribiendo $HARDENING_FILE" "Writing $HARDENING_FILE")"
    if ! write_hardening_file; then
        revert_now "$(ui "No pude escribir el endurecimiento." "Could not write the hardening.")"
        return 1
    fi

    if [[ -f "$CLOUD_INIT_FILE" ]] && grep -qE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' "$CLOUD_INIT_FILE"; then
        if [[ $LOCKDOWN -eq 1 ]]; then
            sed -i -E 's/^([[:space:]]*PasswordAuthentication[[:space:]]+)yes/\1no/' "$CLOUD_INIT_FILE"
            success "$(ui "Corregido $CLOUD_INIT_FILE (dejaba PasswordAuthentication en yes)." "Fixed $CLOUD_INIT_FILE (it left PasswordAuthentication at yes).")"
        else
            info "$(ui "$CLOUD_INIT_FILE pide PasswordAuthentication yes; no lo toco en modo suave." "$CLOUD_INIT_FILE asks for PasswordAuthentication yes; leaving it untouched in soft mode.")"
        fi
    fi

    if ! sshd -t; then
        error "$(ui "La configuración SSH tiene errores de sintaxis." "The SSH configuration has syntax errors.")"
        revert_now "$(ui "Dejo el servidor como estaba." "Leaving the server as it was.")"
        return 1
    fi
    success "$(ui "Sintaxis SSH correcta." "SSH syntax OK.")"

    if ! verify_effective_access; then
        revert_now "$(ui "Cancelo el cambio para no dejarte fuera." "Cancelling the change so you are not locked out.")"
        return 1
    fi

    if [[ $LOCKDOWN -eq 0 ]]; then
        if ! restart_ssh; then
            revert_now "$(ui "En modo suave sshd no quedó escuchando." "In soft mode sshd is not listening.")"
            return 1
        fi
        success "$(ui "SSH recargado con límites; root y la contraseña siguen activos." "SSH reloaded with limits; root and password stay enabled.")"
        show_effective_ssh
        log "Fase 3 completada en modo suave."
        pause
        return 0
    fi

    if [[ $ALLOW_LOCKDOWN -eq 1 ]]; then
        warn "$(ui "--allow-lockdown: cierro el acceso sin prueba humana y SIN cuenta atrás." "--allow-lockdown: locking down without human verification and WITHOUT a countdown.")"
        warn "$(ui "Si la clave no funciona, la única salida es la consola VNC del proveedor." "If the key does not work, the only way out is the provider VNC console.")"
    fi

    # Un reinicio que no deja sshd escuchando ES el encierro: se revierte al
    # instante en vez de esperar a la cuenta atrás.
    if ! restart_ssh; then
        revert_now "$(ui "El cierre dejó SSH sin escuchar: revierto ahora mismo." "The lockdown left SSH not listening: reverting right now.")"
        return 1
    fi
    success "$(ui "SSH recargado." "SSH reloaded.")"
    show_effective_ssh

    # La prueba de acceso va DESPUÉS del reinicio: antes de esto el servidor
    # aún corría con la config vieja y el token no significaba nada.
    if [[ $ALLOW_LOCKDOWN -eq 0 && $NON_INTERACTIVE -eq 0 ]]; then
        if confirm_access "$CURRENT_PORT" "$(ui "Esta es la prueba POSTERIOR al cierre de root y contraseña. Debe funcionar solo con tu clave." "This is the POST-LOCKDOWN test after closing root and password access. It must work using only your key.")"; then
            disarm_rollback || return 1
        else
            revert_now "$(ui "Elegiste restaurar o no se pudo confirmar el acceso después del cierre SSH." "You chose restore or access could not be confirmed after SSH lockdown.")"
            return 1
        fi
    fi

    log "Fase 3 completada (lockdown=1)."
    pause
}

# ============================================================
# FASE 4: UFW
# ============================================================
# UFW entra con deny incoming: todo lo que escuche y no tenga regla queda fuera.
# Se avisa por TCP y por UDP (WireGuard, DNS, VoIP...), y se ignora lo que
# escucha solo en loopback: UFW deja pasar el tráfico de la interfaz lo.
warn_listening_services() {
    local proto p ports allowed tcp_ports udp_ports risky_tcp="" risky_udp=""
    tcp_ports=$(ss -Htln 2>/dev/null | awk '{print $4}' \
        | grep -vE '^(127\.|\[::1\]|::1)' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' ' || true)
    udp_ports=$(ss -Huln 2>/dev/null | awk '{print $4}' \
        | grep -vE '^(127\.|\[::1\]|::1)' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' ' || true)
    if [[ -z "$tcp_ports$udp_ports" ]]; then
        return 0
    fi
    [[ -n "$tcp_ports" ]] && info "$(ui "Puertos TCP a la escucha ahora:$tcp_ports" "TCP ports currently listening:$tcp_ports")"
    [[ -n "$udp_ports" ]] && info "$(ui "Puertos UDP a la escucha ahora:$udp_ports" "UDP ports currently listening:$udp_ports")"
    allowed=$(ufw status numbered 2>/dev/null || true)
    for proto in tcp udp; do
        [[ $proto == tcp ]] && ports="$tcp_ports" || ports="$udp_ports"
        for p in $ports; do
            [[ "$p" == "$CURRENT_PORT" ]] && continue
            if [[ $proto == tcp ]]; then
                grep -qE "[[:space:]]${p}(/tcp)?([[:space:]]|\(|$)" <<< "$allowed" && continue
                risky_tcp="$risky_tcp $p"
            else
                grep -qE "[[:space:]]${p}/udp([[:space:]]|\(|$)" <<< "$allowed" && continue
                risky_udp="$risky_udp $p"
            fi
        done
    done
    if [[ -n "$risky_tcp$risky_udp" ]]; then
        warn "$(ui "Al activar UFW, estos puertos quedarán BLOQUEADOS salvo que los permitas de forma deliberada:$risky_tcp$risky_udp" "When UFW is enabled, these ports will be BLOCKED unless you deliberately allow them:$risky_tcp$risky_udp")"
        echo "     $(ui "No abras un puerto que no reconozcas. Si uno es un servicio público que necesitas conservar, estos son los comandos:" "Do not open a port you do not recognize. If one is a public service you need to keep, these are the commands:")"
        for p in $risky_tcp; do
            echo "       sudo ufw allow ${p}/tcp"
        done
        for p in $risky_udp; do
            echo "       sudo ufw allow ${p}/udp"
        done
        echo
        # --yes responde "sí" a continuar, pero abrir puertos nuevos es otra
        # decisión: en modo desatendido se dejan filtrados y se avisa.
        if [[ $NON_INTERACTIVE -eq 1 || $ASSUME_YES -eq 1 ]]; then
            warn "$(ui "No abro esos puertos automáticamente (--yes no abre accesos nuevos)." "I will not open those ports automatically (--yes does not open new accesses).")"
            warn "$(ui "Quedarán filtrados por UFW; ábrelos tú con los comandos de arriba." "They will stay blocked by UFW; open them yourself with the commands above.")"
        elif confirm "$(ui "¿Mantener accesibles TODOS los puertos listados? Elige 's' solo si reconoces cada servicio." "Keep ALL listed ports reachable? Choose 'y' only if you recognize every service.")"; then
            for p in $risky_tcp; do
                if ! ufw allow "${p}/tcp" >> "$LOG_FILE" 2>&1; then
                    error "$(ui "No pude permitir el puerto TCP $p." "Could not allow TCP port $p.")"
                    return 1
                fi
                info "$(ui "Puerto $p permitido." "Port $p allowed.")"
            done
            for p in $risky_udp; do
                if ! ufw allow "${p}/udp" >> "$LOG_FILE" 2>&1; then
                    error "$(ui "No pude permitir el puerto UDP $p." "Could not allow UDP port $p.")"
                    return 1
                fi
                info "$(ui "Puerto $p permitido." "Port $p allowed.")"
            done
        else
            info "$(ui "No abro nada: esos puertos quedarán filtrados al activar UFW. Puedes permitir uno más tarde con el comando mostrado." "Opening nothing: those ports will stay blocked once UFW is enabled. You can allow one later with the shown command.")"
        fi
    else
        success "$(ui "Todo lo que escucha tiene regla en UFW (o solo es SSH)." "Everything listening already has a UFW rule (or is just SSH).")"
    fi
}

fase_4_ufw() {
    clear_screen
    header "$(ui "FASE 4: Activar cortafuegos UFW" "PHASE 4: Enable the UFW firewall")"
    RECOVERY_OCCURRED=0
    RECOVERY_REASON=""
    phase_guide "4/7" \
        "Cortafuegos UFW" "UFW firewall" \
        "Permitiré SSH en el puerto $CURRENT_PORT y bloquearé conexiones entrantes que no tengan una regla explícita." "I will allow SSH on port $CURRENT_PORT and block incoming connections without an explicit rule." \
        "Revisa la lista de puertos. Conserva abiertos solo los servicios que reconoces y necesitas publicar; después repetirás la prueba SSH desde otra terminal." "Review the port list. Keep open only services you recognize and need to expose; then repeat the SSH test from another terminal." \
        "La prueba después de UFW es obligatoria porque la prueba anterior ocurrió antes de que el firewall filtrara la red." "The test after UFW is required because the earlier test happened before the firewall filtered the network."

    if ! command -v ufw &>/dev/null; then
        info "$(ui "Instalando UFW..." "Installing UFW...")"
        apt-get update && apt-get install -y ufw || return 1
    fi

    CURRENT_PORT=$(current_ssh_port)
    local status was_active=0
    status=$(ufw status) || return 1
    [[ "$status" == *"Status: active"* ]] && was_active=1
    # Se guardan también los cambios aditivos cuando UFW ya estaba activo.
    snapshot_state || return 1
    if [[ $was_active -eq 0 && $NON_INTERACTIVE -eq 0 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        arm_rollback || return 1
    fi
    info "$(ui "Permitiendo SSH en el puerto $CURRENT_PORT..." "Allowing SSH on port $CURRENT_PORT...")"
    if ! ufw limit "${CURRENT_PORT}/tcp" >> "$LOG_FILE" 2>&1; then
        revert_now "$(ui "No pude permitir SSH; no activaré UFW." "Could not allow SSH; I will not enable UFW.")"
        return 1
    fi
    if ! warn_listening_services; then
        revert_now "$(ui "No pude preparar las reglas UFW." "Could not prepare the UFW rules.")"
        return 1
    fi
    if [[ $was_active -eq 1 ]]; then
        success "$(ui "UFW ya está activo." "UFW is already active.")"
    elif [[ $NON_INTERACTIVE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        warn "$(ui "Reglas preparadas; no activo UFW sin prueba de acceso en modo no interactivo." "Rules prepared; not enabling UFW without an access test in non-interactive mode.")"
    elif confirm "$(ui "¿Activar UFW ahora? SSH seguirá permitido; todo servicio sin regla quedará bloqueado." "Enable UFW now? SSH stays allowed; every service without a rule will be blocked.")"; then
        if ! ufw --force enable; then
            revert_now "$(ui "Falló la activación de UFW." "Enabling UFW failed.")"
            return 1
        fi
        if [[ $ALLOW_LOCKDOWN -eq 0 && $ON_CONSOLE -eq 1 ]]; then
            warn "$(ui "Desde la consola no puedes terminar esta prueba: necesitas una terminal de tu computadora para validar SSH a través de UFW." "You cannot finish this test from the console: you need a terminal on your computer to validate SSH through UFW.")"
            if [[ -n "$ROLLBACK_JOB" ]]; then
                info "$(ui "La protección temporal sigue activa durante ${ROLLBACK_MINUTES} min. No la desarmes desde la consola: prueba SSH externo primero y vuelve a ejecutar el asistente si necesitas conservar este cambio." "Temporary protection remains active for ${ROLLBACK_MINUTES} min. Do not disarm it from the console: test external SSH first and rerun the assistant if you need to keep this change.")"
            fi
        elif [[ $ALLOW_LOCKDOWN -eq 0 ]]; then
            if ! confirm_access "$CURRENT_PORT" "$(ui "Esta es la segunda prueba: UFW ya está activo. Confirma SSH, sudo y los servicios que elegiste conservar." "This is the second test: UFW is active now. Confirm SSH, sudo and the services you chose to keep.")"; then
                revert_now "$(ui "Elegiste restaurar o no se pudo confirmar el acceso después de activar UFW." "You chose restore or access could not be confirmed after enabling UFW.")"
                return 1
            fi
            disarm_rollback || return 1
        fi
        success "$(ui "UFW activado. Las reglas mostradas son las únicas puertas de entrada públicas que conserva." "UFW enabled. The displayed rules are the only public entry points it keeps.")"
    else
        revert_now "$(ui "Activación de UFW cancelada." "UFW activation cancelled.")"
        return 0
    fi

    ufw status verbose | sed 's/^/    /'
    log "Fase 4 completada (ssh=$CURRENT_PORT)."
    pause
}

# ============================================================
# FASE 5: FAIL2BAN
# ============================================================
# En 24.04 /var/log/auth.log solo existe si rsyslog sigue instalado; si no,
# fail2ban debe leer de journald o no ve ningún intento.
fail2ban_detect_logging() {
    if [[ -s /var/log/auth.log ]]; then
        FAIL2BAN_BACKEND="auto"
        FAIL2BAN_LOGPATH="/var/log/auth.log"
    else
        FAIL2BAN_BACKEND="systemd"
        FAIL2BAN_LOGPATH=""
    fi
    info "$(ui "Fail2ban usará backend=$FAIL2BAN_BACKEND${FAIL2BAN_LOGPATH:+ logpath=$FAIL2BAN_LOGPATH}" "Fail2ban will use backend=$FAIL2BAN_BACKEND${FAIL2BAN_LOGPATH:+ logpath=$FAIL2BAN_LOGPATH}")"
}

write_fail2ban_jail() {
    # Acepta varios puertos: durante el cambio de puerto conviene cubrir los dos.
    local ports
    ports=$(printf '%s,' "$@"); ports="${ports%,}"
    [[ -z "$ports" ]] && ports=22
    cat > "$JAIL_LOCAL" <<EOF || return 1
# Generado por secure-vps; se reescribe al volver a ejecutar.
[sshd]
backend  = $FAIL2BAN_BACKEND
findtime = 10m
# IPs de las sesiones SSH abiertas ahora: sin esto, fail2ban puede bloquearte
# a ti tras tres intentos fallidos y quedarte fuera por tu propio error.
ignoreip = 127.0.0.1/8 ::1 $ADMIN_IPS

enabled  = true
port     = $ports
maxretry = 3
bantime  = 24h
EOF
    [[ "$FAIL2BAN_BACKEND" == "auto" ]] && printf 'logpath  = %s\n' "$FAIL2BAN_LOGPATH" >> "$JAIL_LOCAL"
    return 0
}

# Quién está conectado por SSH ahora mismo: esas IPs no deben bloquearse.
# Se sacan de 'who', que lee utmp y no depende de variables del entorno sudo.
detect_admin_ips() {
    local ips ip_input=""
    ips=$(current_admin_ips)
    if [[ -z "$ips" ]]; then
        ADMIN_IPS=""
        warn "$(ui "No detecté sesiones SSH abiertas: fail2ban no tendrá tu IP excluida." "No open SSH sessions detected: fail2ban will not whitelist your IP.")"
        if guided_active && [[ -t 0 && $NON_INTERACTIVE -eq 0 && $ASSUME_YES -eq 0 ]]; then
            info "$(ui "Fail2ban bloquea tras unos pocos intentos fallidos: si tu IP no está excluida, te bloqueas a ti mismo desde tu propia computadora." "Fail2ban blocks after a few failed attempts: if your IP is not excluded, you lock yourself out from your own computer.")"
            ui_read "$(ui "Escribe la IP de tu computadora actual (Enter para no excluir ninguna): " "Type your computer's current IP (Enter to exclude none): ")" ip_input
            # Va a a parar a 'ignoreip' del jail: solo se acepta forma de IP, o
            # el texto del operador quedaría interpuesto en la configuración.
            if valid_ip_or_cidr "$ip_input"; then
                ADMIN_IPS="$ip_input"
                success "$(ui "Excluida $ADMIN_IPS del banneo." "Excluded $ADMIN_IPS from banning.")"
            elif [[ -n "$ip_input" ]]; then
                error "$(ui "Eso no parece una IP: no excluyo nada." "That does not look like an IP: excluding nothing.")"
            fi
        fi
        [[ -z "$ADMIN_IPS" ]] && warn "$(ui "Añádela a mano en $JAIL_LOCAL (ignoreip) antes de reiniciar fail2ban." "Add it manually in $JAIL_LOCAL (ignoreip) before restarting fail2ban.")"
    else
        ADMIN_IPS="$ips"
        info "$(ui "IPs de administradores conectados (excluidas de fail2ban): $ADMIN_IPS" "Connected admin IPs (excluded from fail2ban): $ADMIN_IPS")"
    fi
}

fase_5_fail2ban() {
    clear_screen
    header "$(ui "FASE 5: Instalar Fail2ban" "PHASE 5: Install Fail2ban")"
    phase_guide "5/7" \
        "Bloqueo de intentos repetidos" "Repeated-attempt blocking" \
        "Fail2ban bloqueará durante 24 horas una IP que falle 3 veces al iniciar SSH dentro de 10 minutos." "Fail2ban will block an IP for 24 hours after 3 failed SSH logins within 10 minutes." \
        "Revisa la IP que se excluirá. Si tu IP cambia por VPN o red móvil, no dependas de esa exclusión y conserva la consola del proveedor como recuperación." "Review the IP that will be excluded. If your IP changes through VPN or mobile data, do not rely on that exclusion and keep the provider console for recovery." \
        "Esta fase no pide otra prueba SSH; evita intentos de contraseña repetidos mientras el jail queda activo." "This phase does not require another SSH test; avoid repeated password attempts while the jail becomes active."

    if ! command -v fail2ban-client &>/dev/null; then
        info "$(ui "Instalando Fail2ban..." "Installing Fail2ban...")"
        apt-get update && apt-get install -y fail2ban || return 1
    else
        success "$(ui "Fail2ban ya está instalado." "Fail2ban is already installed.")"
    fi

    CURRENT_PORT=$(current_ssh_port)
    detect_admin_ips
    fail2ban_detect_logging
    snapshot_state || return 1
    write_fail2ban_jail "$CURRENT_PORT" || return 1
    if ! fail2ban-client -t; then
        revert_now "$(ui "Fail2ban rechazó la nueva configuración." "Fail2ban rejected the new configuration.")"
        return 1
    fi
    success "$(ui "Jail sshd en puerto $CURRENT_PORT con backend $FAIL2BAN_BACKEND." "sshd jail on port $CURRENT_PORT with backend $FAIL2BAN_BACKEND.")"

    systemctl daemon-reload 2>/dev/null || true
    if ! systemctl restart fail2ban; then
        error "$(ui "fail2ban no arrancó. Revisa: journalctl -u fail2ban -n 30" "fail2ban did not start. Check: journalctl -u fail2ban -n 30")"
        revert_now "$(ui "Restauro la configuración anterior de Fail2ban." "Restoring the previous Fail2ban configuration.")"
        return 1
    fi
    sleep 2
    if ! fail2ban-client status sshd >/dev/null 2>&1; then
        error "$(ui "El jail sshd no quedó activo. Revisa 'fail2ban-client status' y el backend de logs." "The sshd jail is not active. Check 'fail2ban-client status' and the log backend.")"
        revert_now "$(ui "Restauro la configuración anterior de Fail2ban." "Restoring the previous Fail2ban configuration.")"
        return 1
    fi
    fail2ban-client status sshd 2>/dev/null | sed 's/^/    /' || true
    success "$(ui "Fail2ban activo con el jail sshd." "Fail2ban active with the sshd jail.")"
    info "$(ui "Resultado: 3 fallos en 10 minutos bloquean 24 h. La exclusión configurada es: ${ADMIN_IPS:-ninguna}." "Result: 3 failures in 10 minutes block for 24 h. The configured exclusion is: ${ADMIN_IPS:-none}.")"

    log "Fase 5 completada (backend=$FAIL2BAN_BACKEND port=$CURRENT_PORT ignore='$ADMIN_IPS')."
    pause
}

# ============================================================
# FASE 6: ACTUALIZACIONES AUTOMÁTICAS
# ============================================================
fase_6_auto_updates() {
    clear_screen
    header "$(ui "FASE 6: Actualizaciones automáticas" "PHASE 6: Automatic updates")"
    phase_guide "6/7" \
        "Actualizaciones automáticas" "Automatic updates" \
        "Activaré la comprobación diaria e instalación automática de actualizaciones de seguridad." "I will enable daily checks and automatic installation of security updates." \
        "No necesitas responder salvo que apt muestre un error. Revisa los avisos de reinicio cuando el sistema los indique." "You do not need to respond unless apt shows an error. Review reboot notices when the system indicates them." \
        "Esto programa futuras actualizaciones; no sustituye la actualización de hoy de la fase 2.5." "This schedules future updates; it does not replace today's update in phase 2.5."

    if [[ "$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null || true)" != 'install ok installed' ]]; then
        info "$(ui "Instalando unattended-upgrades..." "Installing unattended-upgrades...")"
        apt-get update && apt-get install -y unattended-upgrades apt-listchanges || return 1
    else
        success "$(ui "unattended-upgrades ya instalado." "unattended-upgrades already installed.")"
    fi

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF' || return 1
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    success "$(ui "Configuración escrita." "Configuration written.")"

    systemctl restart unattended-upgrades || return 1
    systemctl is-active --quiet unattended-upgrades || return 1

    info "$(ui "Ejecutando dry-run..." "Running dry-run...")"
    unattended-upgrade --dry-run >> "$LOG_FILE" 2>&1 || return 1

    success "$(ui "Actualizaciones automáticas activadas: el VPS revisará seguridad cada día. Si un parche pide reinicio, hazlo después de confirmar acceso y vuelve a usar la opción 2.3." "Automatic updates enabled: the VPS will review security daily. If a patch needs a reboot, do it after confirming access and use option 2.3 again.")"

    log "Fase 6 completada."
    pause
}

# ============================================================
# FASE 7: CAMBIAR PUERTO SSH
# ============================================================
# Deja el archivo de endurecimiento con exactamente estos puertos.
hardening_set_ports() {
    local p tmp
    tmp=$(mktemp)
    grep -vE '^[[:space:]]*Port[[:space:]]+[0-9]+[[:space:]]*$' "$HARDENING_FILE" > "$tmp" 2>/dev/null || true
    for p in "$@"; do
        printf 'Port %s\n' "$p" >> "$tmp"
    done
    mv "$tmp" "$HARDENING_FILE"
    chmod 644 "$HARDENING_FILE"
}

# El pipeline corto invita a `grep -q`, pero con pipefail el SIGPIPE del
# productor daría 141 y el puerto parecería libre estando ocupado. Se captura
# primero y se busca sobre la variable.
port_in_use_by_other() {
    local port="$1" addrs
    addrs=$(ss -Htln 2>/dev/null | awk '{print $4}' || true)
    grep -qE "[:.]${port}\$" <<< "$addrs"
}

# Sugerencia fácil de recordar, fuera del rango efímero habitual de Ubuntu.
# No reserva el puerto: la fase vuelve a comprobarlo antes de modificar SSH.
suggest_ssh_port() {
    local candidate addrs
    addrs=$(ss -Htlnu 2>/dev/null | awk '{print $4}') || return 1
    for ((candidate=24022; candidate<24122; candidate++)); do
        [[ "$candidate" == "$CURRENT_PORT" ]] && continue
        if ! grep -qE "[:.]${candidate}\$" <<< "$addrs"; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

fase_7_change_port() {
    clear_screen
    header "$(ui "FASE 7: Cambiar puerto SSH (opcional)" "PHASE 7: Change the SSH port (optional)")"
    RECOVERY_OCCURRED=0
    RECOVERY_REASON=""
    phase_guide "7/7" \
        "Puerto SSH opcional" "Optional SSH port" \
        "Abriré el puerto nuevo junto al actual, probarás el nuevo desde tu computadora y solo después cerraré el antiguo." "I will open the new port alongside the current one, you will test it from your computer, and only then close the old one." \
        "Esta fase es opcional. Cambiar de puerto reduce ruido automático, pero no reemplaza clave SSH, UFW ni Fail2ban." "This phase is optional. Changing port reduces automated noise, but does not replace an SSH key, UFW or Fail2ban." \
        "La cuenta atrás conserva el puerto actual hasta que la prueba del nuevo funcione." "The countdown keeps the current port until the new-port test works."

    detect_ssh_activation
    ssh_activation_summary
    CURRENT_PORT=$(current_ssh_port)

    if [[ -z "$NEW_PORT" ]]; then
        if [[ $NON_INTERACTIVE -eq 1 ]]; then
            info "$(ui "Modo no interactivo sin --port. Omitiendo fase 7." "Non-interactive mode without --port. Skipping phase 7.")"
            UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
            return 0
        fi
        if [[ $ASSUME_YES -eq 1 ]]; then
            info "$(ui "--yes no decide cambiar el puerto SSH; omite la fase o pasa --port." "--yes does not decide to change the SSH port; skip the phase or pass --port.")"
            UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
            return 0
        fi
        # Mover el puerto sin poder probar la conexión nueva es exactamente el
        # caso que el rollback no puede cubrir: la consola no sabe de puertos.
        if [[ $ON_CONSOLE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            info "$(ui "Desde la consola no puedo probar el puerto nuevo, así que lo dejo en $CURRENT_PORT. Hazlo por SSH desde tu computadora cuando entres: sudo bash secure-vps.sh --user ${USERNAME:-<tuusuario>} --port 24022" "From the console I cannot test the new port, so leaving it on $CURRENT_PORT. Do it over SSH from your computer once you are in: sudo bash secure-vps.sh --user ${USERNAME:-<youruser>} --port 24022")"
            UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
            return 0
        fi
        if ! confirm "$(ui "¿Quieres cambiar el puerto SSH? Es opcional: la protección principal sigue siendo la clave, UFW y Fail2ban." "Do you want to change the SSH port? It is optional: the main protection remains the key, UFW and Fail2ban.")"; then
            info "$(ui "Omitiendo cambio de puerto: SSH sigue en $CURRENT_PORT y continuamos con el resto." "Skipping port change: SSH stays on $CURRENT_PORT and we carry on.")"
            UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
            return 0
        fi
        local suggested=""
        suggested=$(suggest_ssh_port) || true
        info "$(ui 'Si tu proveedor tiene un cortafuegos externo, permite primero el puerto nuevo TCP allí. El asistente solo configura UFW dentro del VPS.' 'If your provider has an external firewall, allow the new TCP port there first. The assistant only configures UFW inside the VPS.')"
        while true; do
            if ! ui_read "$(ui "Nuevo puerto SSH${suggested:+ [$suggested]} (Enter acepta la sugerencia): " "New SSH port${suggested:+ [$suggested]} (Enter accepts the suggestion): ")" NEW_PORT; then
                info "$(ui 'Entrada cerrada: conservo el puerto actual.' 'Input closed: keeping the current port.')"
                UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
                return 0
            fi
            NEW_PORT="${NEW_PORT:-$suggested}"
            if ! is_port "$NEW_PORT"; then
                warn "$(ui 'Escribe un número entre 1 y 65535.' 'Enter a number between 1 and 65535.')"
            elif [[ "$NEW_PORT" != "$CURRENT_PORT" ]] && port_in_use_by_other "$NEW_PORT"; then
                warn "$(ui "El puerto $NEW_PORT está ocupado. Elige otro." "Port $NEW_PORT is busy. Choose another.")"
            else
                break
            fi
        done
    fi

    if ! is_port "$NEW_PORT"; then
        error "$(ui "Puerto inválido: '$NEW_PORT' (debe ser 1-65535)." "Invalid port: '$NEW_PORT' (must be 1-65535).")"
        return 1
    fi
    if [[ "$NEW_PORT" == "$CURRENT_PORT" ]]; then
        success "$(ui "SSH ya escucha en $NEW_PORT; nada que hacer." "SSH already listens on $NEW_PORT; nothing to do.")"
        UI_PHASE_RESULT="$(ui 'Sin cambios; se conserva el puerto actual' 'No changes; current port retained')"
        return 0
    fi
    if port_in_use_by_other "$NEW_PORT"; then
        error "$(ui "El puerto $NEW_PORT ya lo está usando otro servicio:" "Port $NEW_PORT is already used by another service:")"
        ss -tlnp 2>/dev/null | grep -E "[:.]$NEW_PORT\b" | sed 's/^/      /' || true
        return 1
    fi

    if ! snapshot_state; then
        error "$(ui "No pude crear el snapshot; no cambio el puerto." "Could not create the snapshot; not changing the port.")"
        return 1
    fi

    local drop_old=1
    if [[ $NON_INTERACTIVE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        drop_old=0
        info "$(ui "Modo no interactivo: dejo $CURRENT_PORT Y $NEW_PORT abiertos. Nadie puede" "Non-interactive mode: leaving BOTH $CURRENT_PORT and $NEW_PORT open. Nobody can")"
        info "$(ui "confirmar la nueva conexión, así que quito el puerto viejo solo si pasas" "confirm the new connection, so I remove the old port only if you pass")"
        info "$(ui "--allow-lockdown (o corres el script de forma interactiva)." "--allow-lockdown (or run the script interactively).")"
    fi

    if [[ $NON_INTERACTIVE -eq 0 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        arm_rollback || return 1
    fi
    if ! hardening_set_ports "$CURRENT_PORT" "$NEW_PORT"; then
        revert_now "$(ui "No pude escribir la transición de puertos." "Could not write the port transition.")"
        return 1
    fi
    if [[ $SOCKET_ACTIVATED -eq 1 ]] && ! has_socket_generator; then
        socket_dropin_write "$CURRENT_PORT" "$NEW_PORT" || { revert_now "No pude escribir el socket."; return 1; }
    fi
    sshd -t || { revert_now "$(ui "sshd rechaza la nueva config de puertos." "sshd rejects the new port configuration.")"; return 1; }
    if ! ufw limit "${NEW_PORT}/tcp" >> "$LOG_FILE" 2>&1; then
        revert_now "$(ui "No pude abrir el puerto nuevo en UFW." "Could not open the new port in UFW.")"
        return 1
    fi
    if ! restart_ssh; then
        revert_now "$(ui "Falló el arranque de SSH con ambos puertos." "Starting SSH with both ports failed.")"
        return 1
    fi
    local now_listening
    now_listening=$(listening_ports)
    if ! printf ' %s ' "$now_listening" | grep -q " $NEW_PORT "; then
        revert_now "$(ui "SSH NO quedó escuchando en $NEW_PORT (escucha:$now_listening)." "SSH did NOT end up listening on $NEW_PORT (listening:$now_listening).")"
        return 1
    fi
    success "$(ui "SSH escuchando en:$now_listening" "SSH listening on:$now_listening")"

    fail2ban_detect_logging
    if command -v fail2ban-client >/dev/null; then
        if ! write_fail2ban_jail "$CURRENT_PORT" "$NEW_PORT" || ! systemctl restart fail2ban; then
            revert_now "$(ui "No pude actualizar Fail2ban para ambos puertos." "Could not update Fail2ban for both ports.")"
            return 1
        fi
    fi
    success "$(ui "Puerto nuevo preparado; falta comprobar una conexión desde el cliente." "New port prepared; still need to verify a connection from the client.")"

    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        if [[ $drop_old -eq 1 ]]; then
            confirm_port_change || return 1
        else
            info "$(ui "Puerto $CURRENT_PORT sigue abierto: ciérralo tú cuando verifiques." "Port $CURRENT_PORT is still open: close it yourself once you verify.")"
        fi
    else
        if confirm_access "$NEW_PORT" "$(ui "Esta prueba usa el puerto nuevo $NEW_PORT. El puerto $CURRENT_PORT sigue abierto hasta que confirmes el resultado." "This test uses new port $NEW_PORT. Port $CURRENT_PORT stays open until you confirm the result.")"; then
            confirm_port_change || return 1
        else
            revert_now "$(ui "Elegiste restaurar o no se pudo confirmar SSH por el puerto nuevo $NEW_PORT." "You chose restore or SSH could not be confirmed on new port $NEW_PORT.")"
            return 1
        fi
    fi

    log "Fase 7 completada: puerto final=$(current_ssh_port)"
    pause
}

confirm_port_change() {
    if [[ $ROLLBACK_ARMED -eq 1 ]]; then
        if ! disarm_rollback finalize_old_port_removal; then
            if [[ ! -f "$ROLLBACK_SNAP_DIR/CONFIRMED" ]]; then
                revert_now "$(ui "No se pudo confirmar el puerto; restauro el estado pendiente." "Could not confirm the port; restoring the pending state.")" || return 1
            fi
            return 1
        fi
    elif ! finalize_old_port_removal; then
        revert_now "$(ui "Falló el cambio al puerto definitivo." "Switching to the final port failed.")" || return 1
        return 1
    fi
}

finalize_old_port_removal() {
    info "$(ui "Quitando el puerto $CURRENT_PORT..." "Removing port $CURRENT_PORT...")"
    hardening_set_ports "$NEW_PORT" || return 1
    if [[ $SOCKET_ACTIVATED -eq 1 ]] && ! has_socket_generator; then
        socket_dropin_write "$NEW_PORT" || return 1
    fi
    sshd -t || return 1
    if ! restart_ssh; then
        return 1
    fi
    local now_listening
    now_listening=$(listening_ports) || return 1
    if [[ "$now_listening" != "$NEW_PORT " ]]; then
        return 1
    fi
    local alias=""
    [[ "$CURRENT_PORT" == 22 ]] && alias=ssh
    ufw_purge_port "$CURRENT_PORT" "$alias" || return 1
    fail2ban_detect_logging
    if command -v fail2ban-client >/dev/null; then
        if ! write_fail2ban_jail "$NEW_PORT" || ! systemctl restart fail2ban; then
            return 1
        fi
    fi
    success "$(ui "SSH solo en $NEW_PORT (escucha:$now_listening)." "SSH on $NEW_PORT only (listening:$now_listening).")"
}

# ============================================================
# RESUMEN FINAL
# ============================================================
final_summary() {
    local UI_PLAIN=1
    header "$(ui "RESUMEN DEL ESTADO" "STATE SUMMARY")"
    detect_ssh_activation
    local port eff permitroot passauth allowusers pending listening ufw_state f2b_state updates_state
    port=$(current_ssh_port)
    listening=$(listening_ports)
    eff=$(sshd -T 2>/dev/null || true)
    permitroot=$(printf '%s\n' "$eff"    | awk '/^permitrootlogin /{print $2}')
    passauth=$(printf '%s\n' "$eff"      | awk '/^passwordauthentication /{print $2}')
    allowusers=$(printf '%s\n' "$eff"    | awk '/^allowusers /{$1=""; sub(/^[[:space:]]+/,""); print}')
    pending=$(list_pending_rollbacks)
    ufw_state=$(ufw status 2>/dev/null | awk '/^Status:/{print $2; exit}' || true)
    f2b_state=$(systemctl is-active fail2ban 2>/dev/null || true)
    updates_state=$(systemctl is-active unattended-upgrades 2>/dev/null || true)

    if [[ $RECOVERY_OCCURRED -eq 1 ]]; then
        error "$(ui "CAMBIOS DE ACCESO RESTAURADOS DE FORMA SEGURA" "ACCESS CHANGES RESTORED SAFELY")"
        echo "  $(ui "Motivo:" "Reason:") $RECOVERY_REASON"
        echo "  $(ui "Se restauraron SSH, UFW y Fail2ban al estado anterior al cambio que no se confirmó." "SSH, UFW and Fail2ban were restored to the state before the unconfirmed change.")"
        echo "  $(ui "Se conservaron el usuario, la clave pública instalada, sudo y las actualizaciones." "The user, installed public key, sudo and updates were kept.")"
        echo "  $(ui "Siguiente paso: revisa la prueba desde otra terminal y vuelve a ejecutar solo la fase pendiente." "Next step: review the test from another terminal and rerun only the pending phase.")"
    elif [[ "$permitroot" == "no" && "$passauth" == "no" ]]; then
        success "$(ui "HARDENING DEL ACCESO COMPLETADO" "ACCESS HARDENING COMPLETED")"
        echo "  $(ui "Root y la contraseña SSH están desactivados. Entran con clave los usuarios permitidos: ${allowusers:-$USERNAME}." "Root and SSH password access are disabled. Users allowed with a key: ${allowusers:-$USERNAME}.")"
        if [[ $ACCESS_TEST_CONFIRMED -eq 1 ]]; then
            echo "  $(ui "La prueba externa de esta ejecución fue confirmada por la persona operadora." "The operator confirmed this run's external test.")"
        else
            echo "  $(ui "El estado técnico está endurecido. Si no hiciste una prueba externa en esta ejecución, usa la opción 2.3 ahora." "The technical state is hardened. If you did not do an external test in this run, use option 2.3 now.")"
        fi
    else
        warn "$(ui "HARDENING DEL ACCESO PENDIENTE" "ACCESS HARDENING PENDING")"
        echo "  $(ui "Root SSH: ${permitroot:-desconocido}; contraseña SSH: ${passauth:-desconocida}. No declares el hardening terminado todavía." "Root SSH: ${permitroot:-unknown}; SSH password: ${passauth:-unknown}. Do not consider hardening finished yet.")"
        echo "  $(ui "Siguiente paso: instala/prueba una clave desde tu computadora (fase 2) y repite la fase 3." "Next step: install/test a key from your computer (phase 2) and repeat phase 3.")"
    fi

    if guided_active; then
        echo
        if [[ "$permitroot" == "no" && "$passauth" == "no" ]]; then
            warn "$(ui "Respalda la clave privada en TU computadora. No la copies al VPS ni la pegues en este script." "Back up the private key on YOUR computer. Do not copy it to the VPS or paste it into this script.")"
        else
            warn "$(ui "Tarea pendiente: todavía se entra con contraseña. No es un hardening completo hasta probar una clave y repetir la fase 3." "Pending task: password access still works. This is not complete hardening until you test a key and repeat phase 3.")"
        fi
        echo "  $(ui "Cómo entrar mañana desde TU computadora:" "How to get in tomorrow from YOUR computer:")"
        ui_command "ssh -p ${port} ${USERNAME:-<tuusuario>}@${PUBLIC_IP}" "$(ui 'EN TU COMPUTADORA · ACCESO AL VPS' 'ON YOUR COMPUTER · VPS ACCESS')"
        echo "  $(ui "Para probar solo con clave, añade: -o PasswordAuthentication=no" "To test key-only access, add: -o PasswordAuthentication=no")"
        echo "  $(ui "Si un día no puedes entrar:" "If one day you cannot get in:")"
        echo "    $(ui "1. Abre la consola web del proveedor (VNC/KVM): es recuperación, no una prueba SSH." "1. Open the provider's web console (VNC/KVM): it is recovery, not an SSH test.")"
        echo "    $(ui "2. Entra con tu usuario y su contraseña de sistema, que no es la de SSH." "2. Log in with your user and its system password, which is not the SSH one.")"
        echo "    $(ui "3. Corre de nuevo este script y usa la opción de revertir al último snapshot." "3. Run this script again and use the revert-to-last-snapshot option.")"
        if [[ -n "${USERNAME:-}" ]] && [[ "$(password_state "$USERNAME")" != P ]]; then
            echo "  $(ui "Tu usuario aún no tiene contraseña de sistema: sin ella la consola del proveedor no te deja entrar. Ponla con" "Your user still has no system password: without it the provider console will not let you in. Set one with")"
            echo "    sudo passwd $USERNAME"
        fi
        echo "  $(ui "Si la cuenta atrás restaura cambios, es una protección normal: el resumen de arriba indica exactamente qué volvió atrás." "If the countdown restores changes, that is normal protection: the summary above states exactly what went back.")"
    fi

    cat <<EOF

  🔐 SSH  $(ui "(puerto efectivo: ${port}," "(effective port: ${port},)") $( [[ $SOCKET_ACTIVATED -eq 1 ]] && echo "$(ui 'ssh.socket manda el puerto)' 'ssh.socket drives the port)')" || echo "$(ui 'sshd_config manda el puerto)' 'sshd_config drives the port)')")
EOF
    printf '     %s%s\n' "$(ui 'puertos a la escucha:' 'listening ports:')" "${listening:- $(ui '<sshd no informa>' '<sshd does not report>')}"
    printf '%s\n' "$eff" | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|maxsessions|allowusers|clientaliveinterval)" | sed 's/^/     /' || true
    if [[ -z "$allowusers" ]]; then
        echo "     ${YELLOW}$(ui "AllowUsers sin definir: cualquiera con clave puede entrar." "AllowUsers not set: anyone with a key can log in.")${NC}"
    fi
    if [[ "$SOCKET_ACTIVATED" -eq 1 ]] && ! printf ' %s ' "$listening" | grep -q " $port "; then
        echo "     ${RED}$(ui "Ojo: sshd dice puerto $port pero el socket escucha en otra cosa." "Careful: sshd reports port $port but the socket listens elsewhere.")${NC}"
    fi
    echo
    echo "  🔥 $(ui "UFW (estado: ${ufw_state:-desconocido}):" "UFW (status: ${ufw_state:-unknown}):")"
    ufw status 2>/dev/null | grep -E "Status|^$port/tcp|ALLOW" | head -12 | sed 's/^/     /' || true
    echo
    echo "  🚫 $(ui "Fail2ban (estado: ${f2b_state:-desconocido}):" "Fail2ban (status: ${f2b_state:-unknown}):")"
    fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Total" | sed 's/^/     /' || true
    grep -E "^ignoreip" "$JAIL_LOCAL" 2>/dev/null | sed "s/^/     $(ui 'excluidos: ' 'excluded: ')/" || true
    echo
    echo "  🔄 $(ui "Actualizaciones automáticas (estado: ${updates_state:-desconocido}):" "Automatic updates (status: ${updates_state:-unknown}):")"
    systemctl is-active unattended-upgrades 2>/dev/null | sed 's/^/     /' || true
    if [[ "$permitroot" == "no" && "$passauth" == "no" && -z "$pending" && $RECOVERY_OCCURRED -eq 0 ]]; then
        reboot_hint
    else
        reboot_hint after_access_test
    fi
    echo
    echo "  ⏱  $(ui "Protección temporal pendiente: ${pending:-ninguna}" "Pending temporary protection: ${pending:-none}")"
    if [[ -n "$pending" ]]; then
        warn "$(ui "No declares éxito ni la desarmes todavía. Prueba SSH desde tu computadora y completa la fase que la creó; si no haces nada, se restaurará sola." "Do not declare success or disarm it yet. Test SSH from your computer and complete the phase that created it; if you do nothing, it restores itself.")"
    fi
    local last
    last=$(last_snapshot)
    echo "  💾 $(ui "Snapshot más reciente: ${last:-ninguno}" "Latest snapshot: ${last:-none}")"
    echo "     $(ui "Backup del config principal: $BACKUP_FILE" "Main config backup: $BACKUP_FILE")"
    echo "  📋 $(ui "Log completo: $LOG_FILE" "Full log: $LOG_FILE")"
    echo
    echo "  🔗 $(ui "Conexión:" "Connect:")"
    if [[ -n "${USERNAME:-}" ]]; then
        ui_command "ssh -p $port $USERNAME@$PUBLIC_IP" "$(ui 'EN TU COMPUTADORA · ACCESO AL VPS' 'ON YOUR COMPUTER · VPS ACCESS')"
    fi
    echo
    warn "$(ui "Guarda tu clave privada SSH en un lugar seguro." "Keep your private SSH key somewhere safe.")"
    warn "$(ui "Ten siempre a mano la consola VNC de tu proveedor." "Always keep your provider VNC console at hand.")"
    echo
    if [[ $RECOVERY_OCCURRED -eq 1 ]]; then
        warn "$(ui "El proceso terminó con restauración segura; revisa el siguiente paso indicado arriba." "The process ended with a safe restoration; review the next step above.")"
    elif [[ "$permitroot" == "no" && "$passauth" == "no" && -z "$pending" ]]; then
        success "$(ui "Resultado: acceso endurecido. Usa la opción 2.3 cuando quieras una verificación completa con reporte." "Result: access hardened. Use option 2.3 when you want a complete verification with a report.")"
    else
        warn "$(ui "Resultado: quedan tareas pendientes; no se presenta como hardening exitoso." "Result: tasks remain; this is not presented as successful hardening.")"
    fi
}

# ============================================================
# MODO AUDITORÍA: --audit
# ============================================================
# Para quien quiere saber QUÉ tiene flojo antes de dejar que un script lo cambie
# (o para que un tercero te mande el diagnóstico por escrito). Todo lo de esta
# sección es de lectura: sin mkdir, sin backup, sin snapshot, sin flock, sin
# apt-get update, sin crear /run/sshd y sin escribir en el log. Lo único que se
# invoca son ss, sshd -T/-t, ufw status, fail2ban-client status, systemctl
# is-*/list-units, apt-get -s y lecturas de archivos.

AUDIT_EFF=""              # config efectiva de sshd (salida de 'sshd -T')
AUDIT_FINDINGS=""
AUDIT_N=0
AUDIT_SUGGEST_USER=""

audit_note() {
    AUDIT_N=$((AUDIT_N + 1))
    AUDIT_FINDINGS="${AUDIT_FINDINGS}  ${AUDIT_N}) $1
"
    return 0
}

# Etiquetas sin tilde: con LC_ALL=C printf rellena por bytes y una tilde desplaza
# media columna del valor.
audit_line() {
    local mark="   "
    case "$1" in
        ok)   mark="${GREEN}  ✔${NC}" ;;
        warn) mark="${YELLOW}  !${NC} " ;;
        bad)  mark="${RED}  ✘${NC} " ;;
    esac
    printf '%s %-23s %s\n' "$mark" "$2" "${3:-—}"
    return 0
}

audit_head() {
    printf '\n%s %s\n' "${BOLD}${CYAN}[$1/8]${NC}" "${BOLD}$2${NC}"
    return 0
}

# SSH_CONNECTION trae "ip_cliente puerto_cliente ip_servidor puerto_servidor": el
# tercer campo es la dirección a la que el operador se conectó, que es la que
# sirve para el comando ssh. Vacío si la sesión no es SSH.
audit_session_ip() {
    printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}'
}

# audit_expect <valor> <valor-bueno> <etiqueta> <severidad> <hallazgo>
audit_expect() {
    local mark=ok
    if [[ "$1" != "$2" ]]; then mark="${4:-warn}"; fi
    audit_line "$mark" "$3" "${1:-?}"
    if [[ "$mark" != ok && -n "${5:-}" ]]; then audit_note "${5}"; fi
    return 0
}

# 'sshd -T' es la config REAL tras resolver los Include: la única forma de ver
# qué valor está vigente cuando cloud-init y el archivo de endurecido discrepan.
audit_eff_val() {
    printf '%s\n' "$AUDIT_EFF" | awk -v k="$1" 'tolower($1) == k {print $2; exit}'
}

audit_eff_rest() {
    printf '%s\n' "$AUDIT_EFF" | awk -v k="$1" 'tolower($1) == k {sub(/^[^ ]+ +/, ""); print; exit}'
}

# Puertos escuchados por protocolo, sin loopback. Vacío si no escucha nada.
audit_listening() {
    local raw=""
    case "$1" in
        tcp) raw=$(ss -Htln 2>/dev/null || true) ;;
        udp) raw=$(ss -Huln 2>/dev/null || true) ;;
    esac
    printf '%s\n' "$raw" | awk '{print $4}' \
        | grep -vE '^(127\.|\[::1\]|::1)' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
    return 0
}

# Predicados aparte (y no un 'command -v' en el cuerpo de la sección) para que
# las pruebas unitarias puedan forzar la rama "no instalado" sin desinstalar.
has_ufw() { command -v ufw >/dev/null 2>&1; }
has_fail2ban() { command -v fail2ban-client >/dev/null 2>&1; }

audit_section_system() {
    local up
    audit_head 1 "$(ui "Sistema y sesión" "System and session")"
    audit_line ok "Ubuntu" "$PRETTY_NAME"
    audit_line info "Kernel" "$(uname -r)"
    up=$(awk '{printf "%.0fd %.0dh", $1/86400, ($1 % 86400)/3600}' /proc/uptime 2>/dev/null) || true
    audit_line info "$(ui "Tiempo encendido" "Uptime")" "${up:-?}"
    audit_line info "$(ui "IP publica" "Public IP")" "${PUBLIC_IP:-$(ui "sin consultar: --audit no hace peticiones salientes" "not looked up: --audit makes no outbound request")}"
    case "$VERSION_ID" in
        22.04|24.04)
            audit_line ok "$(ui "Version probada" "Tested version")" "$VERSION_ID"
            ;;
        *)
            audit_line warn "$(ui "Version probada" "Tested version")" "$VERSION_ID"
            audit_note "$(ui "Ubuntu $VERSION_ID no está en la matriz probada (22.04 y 24.04): el endurecido te pedirá revisar cada cambio." "Ubuntu $VERSION_ID is not in the tested matrix (22.04 and 24.04): hardening will ask you to review every change.")"
            ;;
    esac
    if [[ $ON_CONSOLE -eq 1 ]]; then
        audit_line warn "$(ui "Sesion actual" "Current session")" "$(ui "consola web del proveedor, no SSH" "provider web console, not SSH")"
        echo "     $(ui "Desde la consola no se puede probar un login nuevo: por eso el script nunca cierra el acceso desde ahí." "A new login cannot be tested from the console: that is why the script never locks down from there.")"
    else
        audit_line ok "$(ui "Sesion actual" "Current session")" "SSH"
    fi
}

# StrictModes hace que sshd ignore authorized_keys si el home o el .ssh son
# escribibles por grupo u otros: es la causa nº1 de "puse la clave y sigue
# pidiendo contraseña".
audit_key_perms() {
    local u="$1" home hm sm km
    home=$(user_home "$u")
    [[ -n "$home" && -d "$home/.ssh" ]] || return 0
    hm=$(_file_mode "$home")
    sm=$(_file_mode "$home/.ssh")
    km=$(_file_mode "$home/.ssh/authorized_keys")
    if world_or_group_writable "$hm" || world_or_group_writable "$sm" || world_or_group_writable "$km"; then
        audit_line warn "permisos $u" "home=$hm .ssh=$sm keys=$km"
        audit_note "$(ui "Los permisos de '$u' (home=$hm .ssh=$sm authorized_keys=$km) hacen que sshd ignore su clave." "The permissions of '$u' (home=$hm .ssh=$sm authorized_keys=$km) make sshd ignore its key.")"
        return 1
    fi
    return 0
}

audit_section_users() {
    local humans u home keys st usable total=0 sudo_grp
    audit_head 2 "$(ui "Quienes pueden entrar" "Who can get in")"
    humans=$(other_human_users)
    sudo_grp=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' ' ') || true
    if [[ -z "$humans" ]]; then
        audit_line bad "$(ui "Usuarios humanos" "Human users")" "$(ui "solo existe root" "only root exists")"
        audit_note "$(ui "Sin un usuario administrador no hay forma segura de cerrar el acceso: la fase 1 crea uno (--user NOMBRE lo especifica)." "Without an admin user there is no safe way to lock down: phase 1 creates one (--user NAME sets it).")"
    else
        audit_line ok "$(ui "Usuarios humanos" "Human users")" "$humans"
        AUDIT_SUGGEST_USER="${humans%% *}"
    fi
    if [[ -n "$sudo_grp" ]]; then
        audit_line ok "sudo" "$sudo_grp"
    else
        audit_line bad "sudo" "$(ui "nadie esta en el grupo sudo" "nobody is in the sudo group")"
        audit_note "$(ui "Ningún usuario puede escalar a root: si se cierra SSH y no hay sudo, no hay forma de administrar el equipo." "No user can escalate to root: if SSH gets closed and there is no sudo, the machine cannot be administered.")"
    fi

    for u in root $humans; do
        st=$(password_state "$u")
        keys=0
        home=$(user_home "$u")
        if [[ -n "$home" && -r "$home/.ssh/authorized_keys" ]]; then
            keys=$(grep -cE '^[[:space:]]*(ssh-|ecdsa-|sk-)' "$home/.ssh/authorized_keys" 2>/dev/null) || true
        fi
        keys="${keys:-0}"
        total=$((total + keys))
        usable="sudo:no"
        case " $sudo_grp " in *" $u "*) usable="sudo:si" ;; esac
        if [[ "$u" == root ]]; then
            usable="root"
        fi
        audit_line "$([[ "$keys" -gt 0 ]] && echo ok || echo warn)" "$u" "$usable claves:$keys pass:${st:-?}"
        if [[ "$keys" -eq 0 ]]; then
            audit_note "$(ui "'$u' no tiene ninguna clave autorizada: mientras esté así no se puede cerrar el login por contraseña." "'$u' has no authorized key: while that is true, password login cannot be closed.")"
        fi
        audit_key_perms "$u" || true
        # Las huellas, para que cada quien reconozca la suya antes de fiarse del
        # conteo: es lo que se compara con 'ssh-keygen -lf ~/.ssh/id_ed25519.pub'.
        if [[ -n "$home" && -r "$home/.ssh/authorized_keys" ]]; then
            echo "     $home/.ssh/authorized_keys"
            ssh-keygen -lf "$home/.ssh/authorized_keys" 2>/dev/null | head -5 | sed 's/^/       /' || true
        fi
    done

    audit_line info "$(ui "Entradas de clave totales" "Total key entries")" "$total"
    if [[ -f /etc/sudoers.d/90-"${AUDIT_SUGGEST_USER:-none}" ]]; then
        audit_line info "sudoers.d" "$(ui "drop-in NOPASSWD presente para $AUDIT_SUGGEST_USER" "NOPASSWD drop-in present for $AUDIT_SUGGEST_USER")"
    fi
}

audit_section_ssh() {
    local listening err st f pr pa pu ka au
    audit_head 3 "SSH"
    detect_ssh_activation
    CURRENT_PORT=$(current_ssh_port) || true
    CURRENT_PORT="${CURRENT_PORT:-22}"
    listening=$(listening_ports) || true
    if [[ "$CURRENT_PORT" == "22" ]]; then
        audit_line warn "$(ui "Puerto que escucha" "Port listening")" "22"
        audit_note "$(ui "SSH sigue en el 22, el puerto que escanea todo internet: sacarlo baja el ruido de los logs y los intentos de fuerza bruta." "SSH is still on 22, the port the whole internet scans: moving it cuts log noise and brute-force attempts.")"
    else
        audit_line ok "$(ui "Puerto que escucha" "Port listening")" "$CURRENT_PORT"
    fi
    audit_line info "$(ui "Puertos de sshd" "sshd ports")" "${listening:-$(ui "sshd no informa" "sshd reports nothing")}"
    ssh_activation_summary

    AUDIT_EFF=$(sshd -T 2>/dev/null) || true
    if [[ -z "$AUDIT_EFF" ]]; then
        err=$(sshd -T 2>&1 >/dev/null | head -2 | tr '\n' ' ') || true
        audit_line bad "$(ui "Config efectiva" "Effective config")" "${err:-$(ui "sshd -T no responde" "sshd -T does not answer")}"
        audit_note "$(ui "No pude leer la config efectiva de sshd: el resto de la sección SSH queda sin datos." "I could not read the effective sshd config: the rest of the SSH section has no data.")"
        return 0
    fi

    pr=$(audit_eff_val permitrootlogin)
    pa=$(audit_eff_val passwordauthentication)
    pu=$(audit_eff_val pubkeyauthentication)
    ka=$(audit_eff_val kbdinteractiveauthentication)
    au=$(audit_eff_rest allowusers)
    audit_expect "$pr" "no" "PermitRootLogin" bad \
        "$(ui "root puede entrar por SSH (PermitRootLogin=$pr): es la cuenta que todo intento de adivinanza persigue." "root can log in over SSH (PermitRootLogin=$pr): the account every guessing attempt targets.")"
    audit_expect "$pa" "no" "PasswordAuthentication" bad \
        "$(ui "El login por contraseña sigue abierto (PasswordAuthentication=$pa) mientras que root acepte $pr." "Password login is still open (PasswordAuthentication=$pa) while root accepts $pr.")"
    audit_expect "$pu" "yes" "PubkeyAuthentication" bad \
        "$(ui "PubkeyAuthentication=$pu: sin claves aceptadas no se puede cerrar la contraseña sin quedarse fuera." "PubkeyAuthentication=$pu: with no keys accepted, password login cannot be closed without locking everyone out.")"
    audit_expect "$ka" "no" "KbdInteractiveAuthentication" "" ""
    if [[ -n "$au" ]]; then
        audit_line ok "AllowUsers" "$au"
    else
        audit_line warn "AllowUsers" "$(ui "sin definir: entra cualquier usuario con clave" "not set: any user with a key gets in")"
        audit_note "$(ui "AllowUsers vacío: cualquier cuenta con una clave instalada (incluidas las que puso un proveedor o un ex-colaborador) puede entrar." "AllowUsers empty: any account with an installed key (including ones a provider or an ex-coworker put there) can get in.")"
    fi
    audit_line info "MaxAuthTries" "$(audit_eff_val maxauthtries)"
    audit_line info "MaxSessions" "$(audit_eff_val maxsessions)"
    audit_line info "X11Forwarding" "$(audit_eff_val x11forwarding)"
    audit_line info "ClientAliveInterval" "$(audit_eff_val clientaliveinterval)"

    if st=$(sshd -t 2>&1); then
        audit_line ok "$(ui "Sintaxis de sshd" "sshd syntax")" "OK"
    else
        audit_line bad "$(ui "Sintaxis de sshd" "sshd syntax")" "$(printf '%s\n' "$st" | tail -1)"
        audit_note "$(ui "sshd -t falla: 'sshd -T' y el cierre de acceso no son fiables hasta arreglarlo." "sshd -t fails: neither sshd -T nor a lock-down is trustworthy until this is fixed.")"
    fi

    # sshd guarda el PRIMER valor que ve de cada clave: un drop-in ajeno con
    # nombre anterior a 99-hardening gana aunque el nuestro diga lo contrario.
    audit_dropin_scan /etc/ssh/sshd_config.d
}

# audit_dropin_scan <directorio>  (separa el glob del resto de la sección para
# poder probarlo con un directorio de trabajo)
audit_dropin_scan() {
    local f
    for f in "$1"/*.conf; do
        [[ -f "$f" ]] || continue
        audit_line info "$(basename "$f")" "$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null || true) $(ui "lineas" "lines")"
        if grep -qiE '^[[:space:]]*(PasswordAuthentication[[:space:]]+yes|KbdInteractiveAuthentication[[:space:]]+yes|PermitRootLogin[[:space:]]+(yes|without-password|prohibit-password))' "$f"; then
            audit_note "$(ui "El drop-in $f reabre contraseña o root y sshd usa el primer valor que lee: hay que corregirlo (la fase 3 lo hace)." "The drop-in $f reopens password or root access and sshd uses the first value it reads: it must be corrected (phase 3 does it).")"
        fi
    done
    return 0
}

audit_section_firewall() {
    local tcp udp ports proto p numbered status rules def_in active mark risky risky_tcp="" risky_udp=""
    audit_head 4 "$(ui "Cortafuegos y puertos expuestos" "Firewall and exposed ports")"
    tcp=$(audit_listening tcp) || true
    udp=$(audit_listening udp) || true
    audit_line info "$(ui "TCP a la escucha" "TCP listening")" "${tcp:-$(ui "nada expuesto" "nothing exposed")}"
    audit_line info "$(ui "UDP a la escucha" "UDP listening")" "${udp:-$(ui "nada expuesto" "nothing exposed")}"

    if ! has_ufw; then
        audit_line bad "UFW" "$(ui "no instalado" "not installed")"
        audit_note "$(ui "Sin cortafuegos, todo puerto a la escucha responde a internet: la fase 4 instala y activa UFW con SSH permitido." "Without a firewall every listening port answers to the internet: phase 4 installs and enables UFW with SSH allowed.")"
        return 0
    fi
    numbered=$(ufw status numbered 2>/dev/null) || true
    status=$(ufw status 2>/dev/null) || true
    active=no
    case "$status" in *"Status: active"*) active=yes ;; esac
    rules=$(printf '%s\n' "$numbered" | grep -cE '^[[:space:]]*\[[[:space:]]*[0-9]+\]') || true
    def_in=$(awk -F= '/^DEFAULT_INPUT_POLICY/{print $2}' /etc/default/ufw 2>/dev/null) || true
    if [[ "$active" == yes ]]; then
        audit_line ok "UFW" "$(ui "activo, $rules reglas de entrada" "active, $rules inbound rules")"
    else
        audit_line bad "UFW" "$(ui "INACTIVO" "NOT ACTIVE")"
        audit_note "$(ui "UFW inactivo: todo lo que escucha arriba está expuesto a internet ahora mismo." "UFW inactive: everything listed above is exposed to the internet right now.")"
    fi
    audit_line "$([[ -n "$def_in" ]] && echo ok || echo warn)" "DEFAULT_INPUT_POLICY" "${def_in:-?}"

    # Qué puertos no tienen regla. Con UFW inactivo la lectura es "expuesto";
    # con UFW activo la lista ya está filtrada, así que solo queda lo permitido.
    for proto in tcp udp; do
        ports="$tcp"
        if [[ "$proto" == udp ]]; then ports="$udp"; fi
        for p in $ports; do
            if [[ "$proto" == tcp ]]; then
                if grep -qE "[[:space:]]${p}(/tcp)?([[:space:]]|\(|$)" <<< "$numbered"; then
                    continue
                fi
                risky_tcp="$risky_tcp $p"
            else
                if grep -qE "[[:space:]]${p}/udp([[:space:]]|\(|$)" <<< "$numbered"; then
                    continue
                fi
                risky_udp="$risky_udp $p"
            fi
        done
    done
    if [[ -n "${risky_tcp// /}" || -n "${risky_udp// /}" ]]; then
        risky="${risky_tcp} ${risky_udp}"
        risky=$(printf '%s' "$risky" | tr -s ' ' | sed 's/^ //;s/ $//')
        audit_line warn "$(ui "Sin regla en UFW" "Without a UFW rule")" "$risky"
        for p in $risky_tcp; do echo "       sudo ufw allow ${p}/tcp"; done
        for p in $risky_udp; do echo "       sudo ufw allow ${p}/udp"; done
        audit_note "$(ui "Puertos escuchando sin regla: hoy expuestos si UFW está inactivo, y que se cortarían al activarlo. Decide uno por uno antes de activar." "Ports listening without a rule: exposed today while UFW is inactive, and cut off the moment it is enabled. Decide them one by one before enabling.")"
    fi
    # El puerto SSH es el único cuya regla no admite error: sin él, el cierre
    # deja fuera al operador. La fase 4 lo abre; aquí solo se avisa.
    if ! grep -qE "[[:space:]]${CURRENT_PORT}(/tcp)?([[:space:]]|\(|$)" <<< "$numbered"; then
        audit_line warn "$(ui "Regla para el puerto SSH" "Rule for the SSH port")" "$(ui "no hay regla para $CURRENT_PORT" "no rule for $CURRENT_PORT")"
        audit_note "$(ui "Al activar UFW sin abrir $CURRENT_PORT te quedas fuera del VPS. El script lo permite antes de activarlo; si lo haces a mano: sudo ufw allow $CURRENT_PORT/tcp" "Enabling UFW without allowing $CURRENT_PORT locks you out. The script permits it before enabling; by hand it is: sudo ufw allow $CURRENT_PORT/tcp")"
    fi
    return 0
}

audit_section_fail2ban() {
    local act en raw ignores ips mark
    audit_head 5 "Fail2ban"
    if ! has_fail2ban; then
        audit_line warn "fail2ban" "$(ui "no instalado" "not installed")"
        audit_note "$(ui "Nada frena los intentos fallidos de login; la fase 5 lo instala y deja excluidas tus IPs actuales." "Nothing slows down failed logins; phase 5 installs it and whitelists your current IPs.")"
        return 0
    fi
    act=$(systemctl is-active fail2ban 2>/dev/null) || true
    en=$(systemctl is-enabled fail2ban 2>/dev/null) || true
    mark=warn
    if [[ "$act" == active ]]; then mark=ok; fi
    audit_line "$mark" "fail2ban" "$(ui "servicio" "service") ${en:-?}/${act:-?}"

    # 'fail2ban-client status' puede colgarse si el daemon está a medio arrancar
    # (el socket existe pero no responde): timeout lo corta y el reporte sigue.
    raw=$(timeout 15 fail2ban-client status sshd 2>/dev/null) || true
    if [[ -n "$raw" ]]; then
        audit_line ok "$(ui "jail sshd" "sshd jail")" "$(ui "activo" "active")"
        printf '%s\n' "$raw" | grep -E "Currently|Total|Failures" | sed 's/^[[:space:]]*/       /' || true
    else
        audit_line warn "$(ui "jail sshd" "sshd jail")" "$(ui "sshd no esta en los jails" "sshd is not in the jails")"
        if [[ "$act" == active ]]; then
            audit_note "$(ui "fail2ban corre pero sin jail sshd: no bloquea nada. La fase 5 escribe /etc/fail2ban/jail.d/99-secure-vps.local." "fail2ban runs with no sshd jail: it blocks nothing. Phase 5 writes /etc/fail2ban/jail.d/99-secure-vps.local.")"
        fi
    fi
    ignores=$(grep -E '^ignoreip' "$JAIL_LOCAL" 2>/dev/null) || true
    ignores=$(printf '%s' "$ignores" | sed -E 's/^ignoreip[[:space:]]*//')
    audit_line info "ignoreip" "${ignores:-$(ui "sin excluir" "nothing excluded")}"
    ips=$(current_admin_ips)
    if [[ "$act" == active && -z "$ignores" && -n "$ips" ]]; then
        audit_note "$(ui "fail2ban corre sin ignoreip y tu IP actual es $ips: tres erratas de contraseña te dejan fuera hasta que venza el ban." "fail2ban runs with no ignoreip and your current IP is $ips: three mistyped passwords leave you out until the ban expires.")"
    fi
    return 0
}

audit_section_updates() {
    local uu act en conf mark
    audit_head 6 "$(ui "Parches del sistema" "System patches")"
    # apt_pending_counts usa 'apt-get -s' (simulación): lee los índices, no los
    # toca. Refrescarlos sería apt-get update, que sí escribe en /var/lib/apt.
    apt_pending_counts || true
    audit_line "$([[ ${PENDING_COUNT:-0} -eq 0 ]] && echo ok || echo warn)" \
        "$(ui "Paquetes actualizables" "Upgradable packages")" "${PENDING_COUNT:-0}"
    audit_line "$([[ ${PENDING_SECURITY:-0} -eq 0 ]] && echo ok || echo bad)" \
        "$(ui "De seguridad" "Of them security")" "${PENDING_SECURITY:-0}"
    echo "     $(ui "Contado sobre los índices que hay en disco: --audit no corre apt-get update porque eso escribe." "Counted from the indexes on disk: --audit does not run apt-get update, because that writes.")"
    if [[ ${PENDING_SECURITY:-0} -gt 0 ]]; then
        audit_note "$(ui "Hay $PENDING_SECURITY parches de seguridad sin aplicar. La fase 2.5 los aplica antes de cerrar el acceso, con contraseña todavía viva." "$PENDING_SECURITY security patches are not applied yet. Phase 2.5 applies them before locking down, while password access still works.")"
    fi
    uu=$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null) || true
    if [[ "$uu" == "install ok installed" ]]; then
        en=$(systemctl is-enabled unattended-upgrades 2>/dev/null) || true
        act=$(systemctl is-active unattended-upgrades 2>/dev/null) || true
        if [[ "$act" == active ]]; then mark=ok; else mark=warn; fi
        audit_line "$mark" "unattended-upgrades" "${en:-?}/${act:-?}"
    else
        audit_line warn unattended-upgrades "$(ui "no instalado" "not installed")"
        audit_note "$(ui "Nadie aplica los parches de seguridad solos: la fase 6 instala unattended-upgrades y lo deja activo." "Nothing applies security patches on its own: phase 6 installs unattended-upgrades and leaves it running.")"
    fi
    conf=$(tr '\n' ' ' < /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null) || true
    audit_line info "20auto-upgrades" "${conf:-$(ui "ausente" "absent")}"
    if [[ -f "$REBOOT_FLAG" ]]; then
        audit_line warn "$(ui "Reinicio pendiente" "Reboot pending")" "$(ui "hace falta sudo reboot" "sudo reboot is needed")"
        audit_note "$(ui "El kernel en ejecución sigue siendo el viejo: los parches de seguridad aplicados no hacen efecto hasta reiniciar." "The running kernel is still the old one: the security patches applied take effect only after a reboot.")"
    fi
    return 0
}

audit_section_tool() {
    local count pending last f unconfirmed=0 backups
    audit_head 7 "$(ui "Rastros de secure-vps aqui" "secure-vps traces here")"
    if [[ -d "$SNAPSHOTS_DIR" ]]; then
        count=$(find "$SNAPSHOTS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ') || true
        for f in "$SNAPSHOTS_DIR"/*/; do
            [[ -d "$f" ]] || continue
            if [[ -f "$f/READY" && ! -f "$f/CONFIRMED" && ! -f "$f/REVERTED" ]]; then
                unconfirmed=$((unconfirmed + 1))
            fi
        done
        last=$(last_snapshot)
        audit_line info "snapshots" "$count ($(ui "sin confirmar: $unconfirmed" "unconfirmed: $unconfirmed"))"
        audit_line info "$(ui "mas reciente" "latest")" "${last:-$(ui "ninguno" "none")}"
        if [[ "$unconfirmed" -gt 0 ]]; then
            audit_note "$(ui "Hay $unconfirmed snapshot(s) sin marcar CONFIRMED: fueron cambios cuya prueba de acceso no terminó de cerrarse." "$unconfirmed snapshot(s) have no CONFIRMED mark: those were changes whose access test never closed.")"
        fi
    else
        audit_line info "snapshots" "$(ui "nunca se corrio el endurecido aqui" "hardening never ran here")"
    fi
    pending=$(list_pending_rollbacks) || true
    if [[ -n "$pending" ]]; then
        audit_line bad "$(ui "Cuenta atras armada" "Countdown armed")" "$pending"
        audit_note "$(ui "Hay una cuenta atrás viva de otra corrida ($pending): si nadie la cancela, revierte los cambios. sudo systemctl stop $pending" "A countdown from another run is alive ($pending): unless somebody cancels it, it reverts the changes. sudo systemctl stop $pending")"
    else
        audit_line ok "$(ui "Cuenta atras armada" "Countdown armed")" "$(ui "ninguna" "none")"
    fi
    backups=$(ls -1 /etc/ssh/sshd_config.bak.* 2>/dev/null | tr '\n' ' ') || true
    audit_line info "$(ui "Backups de sshd_config" "sshd_config backups")" "${backups:-$(ui "ninguno" "none")}"
    for f in "$HARDENING_FILE" "$SOCKET_DROPIN" "$JAIL_LOCAL" "$ROLLBACK_BIN"; do
        if [[ -e "$f" ]]; then
            audit_line ok "$(basename "$f")" "$(ui "presente" "present")"
        else
            audit_line info "$(basename "$f")" "-"
        fi
    done
    if [[ -f "$LOG_FILE" ]]; then
        audit_line info "$(ui "Log de la herramienta" "Tool log")" "$(wc -l < "$LOG_FILE" | tr -d ' ') $(ui "lineas" "lines")"
    fi
    return 0
}

audit_findings() {
    local who port_flag
    audit_head 8 "$(ui "Hallazgos" "Findings")"
    if [[ $AUDIT_N -eq 0 ]]; then
        success "$(ui "No encontré nada que corregir: el equipo ya está cerrado razonablemente." "Nothing to fix: this machine is already reasonably closed.")"
        return 0
    fi
    printf '%s' "$AUDIT_FINDINGS"
    echo
    echo "  $(ui "Para aplicar todo eso con la red de seguridad (snapshot + cuenta atrás + prueba de acceso real):" "To apply all of it with the safety net (snapshot + countdown + a real access test):")"
    who="${AUDIT_SUGGEST_USER:-TUUSUARIO}"
    port_flag=""
    if [[ "$CURRENT_PORT" == "22" ]]; then
        port_flag="--port 24022 "
    fi
    # install.sh corre el script desde un temporal que borra al salir: imprimir
    # esa ruta daría un comando que ya no existe cuando se quiera copiar.
    local cmd="$0"
    case "$cmd" in /tmp/*|/var/*|/private/*) cmd="secure-vps.sh" ;; esac
    echo -e "    ${CYAN}sudo bash $cmd ${port_flag}--user $who --pubkey-file /ruta/a/tu_clave.pub${NC}"
    echo
    echo "  $(ui "El reporte no tocó nada: --audit solo lee." "The report touched nothing: --audit only reads.")"
    echo "  $(ui "Guarda el reporte para revisarlo o para pasarlo a alguien:" "Save the report to review it or to hand it to somebody:")"
    echo -e "    ${CYAN}sudo bash $cmd --audit > auditoria.txt${NC}"
    return 0
}

audit_report() {
    local UI_PLAIN=1
    local RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
    banner
    header "$(ui "AUDITORÍA DE SOLO LECTURA" "READ-ONLY AUDIT")"
    echo "  $(ui "Esto no escribe nada: ni configuración, ni backups, ni snapshots, ni cuenta atrás." "This writes nothing: no configuration, no backups, no snapshots, no countdown.")"
    echo "  $(ui "Tarda unos segundos y se puede correr las veces que haga falta." "It takes a few seconds and can be run as many times as needed.")"
    # detect_public_ip NO se llama: sus cuatro curl a servicios externos son la
    # única salida de red de la corrida, y un reporte pensado para guardarse y
    # pasarse a alguien no debe generar tráfico. La dirección por la que se entró
    # se lee del propio entorno de la sesión.
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(audit_session_ip)
    fi
    detect_session_kind
    audit_section_system
    audit_section_users
    audit_section_ssh
    audit_section_firewall
    audit_section_fail2ban
    audit_section_updates
    audit_section_tool
    audit_findings
    return 0
}

# ============================================================
# VERIFICACIÓN FINAL: consulta el estado, no aplica ni confirma cambios
# ============================================================
verification_item() {
    local level="$1" label="$2" detail="$3" mark
    case "$level" in
        bad) VERIFY_FAILURES=$((VERIFY_FAILURES + 1)); mark="$(ui 'FALLO' 'FAIL')" ;;
        warn) VERIFY_PENDING=$((VERIFY_PENDING + 1)); mark="$(ui 'PENDIENTE' 'PENDING')" ;;
        ok) mark=OK ;;
        *) mark=INFO ;;
    esac
    # Texto sin colores: también se usa como reporte persistente.
    printf '  [%s] %s: %s\n' "$mark" "$label" "$detail"
    return 0
}

verification_expect() {
    local actual="$1" expected="$2" label="$3" level="${4:-warn}"
    if [[ "$actual" == "$expected" ]]; then level=ok; fi
    verification_item "$level" "$label" "${actual:-$(ui 'sin datos' 'no data')} ($(ui 'esperado' 'expected'): $expected)"
}

verification_port_contains() {
    local list="${1//,/ }" wanted="$2" token start end resolved
    for token in $list; do
        if [[ "$token" == "$wanted" ]]; then return 0; fi
        if [[ "$token" =~ ^([0-9]+):([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
            if (( 10#$wanted >= 10#$start && 10#$wanted <= 10#$end )); then return 0; fi
        elif [[ "$token" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
            resolved=$(getent services "$token" 2>/dev/null | awk '{split($2,p,"/"); print p[1]; exit}' || true)
            [[ "$resolved" == "$wanted" ]] && return 0
        fi
    done
    return 1
}

verification_key_ok() {
    local user="$1" home path mode owner
    home=$(user_home "$user")
    [[ -n "$home" ]] && existing_key_present "$user" >/dev/null 2>&1 || return 1
    for path in "$home" "$home/.ssh" "$home/.ssh/authorized_keys"; do
        mode=$(_file_mode "$path"); owner=$(_file_owner "$path")
        [[ -n "$mode" && ( "$owner" == "$user" || "$owner" == root ) ]] || return 1
        world_or_group_writable "$mode" && return 1
    done
    return 0
}

verification_ssh() {
    local addr="${SSH_CONNECTION:-}" ports port root_eff keys_file
    addr="${addr%% *}"
    addr="${addr:-127.0.0.1}"
    [[ "$addr" =~ ^[0-9a-fA-F:.]+$ ]] || addr=127.0.0.1
    AUDIT_EFF=""
    if ! sshd -t >/dev/null 2>&1 || ! AUDIT_EFF=$(sshd -T -C "user=$USERNAME,host=$addr,addr=$addr" 2>/dev/null); then
        verification_item bad SSH "$(ui 'No pude validar la sintaxis/configuración efectiva.' 'Could not validate syntax/effective configuration.')"
        return 0
    fi
    verification_item info "$(ui 'Contexto SSH' 'SSH context')" "user=$USERNAME addr=$addr"
    for port in passwordauthentication kbdinteractiveauthentication permitemptypasswords x11forwarding; do
        verification_expect "$(audit_eff_val "$port")" no "$port"
    done
    verification_expect "$(audit_eff_val pubkeyauthentication)" yes PubkeyAuthentication bad
    # Match User root puede abrir root aunque las políticas del administrador no.
    root_eff=$(sshd -T -C "user=root,host=$addr,addr=$addr" 2>/dev/null) || root_eff=""
    verification_expect "$(awk '$1 == "permitrootlogin" {print $2; exit}' <<< "$root_eff")" no PermitRootLogin
    if ! grep -qxF "$USERNAME" < <(audit_eff_rest allowusers | tr ' ' '\n'); then
        verification_item warn AllowUsers "$(ui "No se verificó una entrada exacta para $USERNAME; revisa la política." "An exact entry for $USERNAME was not verified; review the policy.")"
    else
        verification_item ok AllowUsers "$USERNAME"
    fi
    for port in denyusers denygroups allowgroups authenticationmethods; do
        # Estas restricciones requieren contrastar los grupos y métodos del cliente.
        # El perfil escrito por kenroka no las añade: se informa sin afirmar acceso.
        keys_file=$(audit_eff_rest "$port")
        if [[ -n "$keys_file" && ! ( "$port" == authenticationmethods && ( "$keys_file" == any || "$keys_file" == publickey ) ) ]]; then
            verification_item warn "$port" "$(ui 'Restricción adicional que debe revisarse' 'Additional restriction to review'): $keys_file"
        fi
    done
    verification_expect "$(audit_eff_val maxauthtries)" 3 MaxAuthTries
    verification_expect "$(audit_eff_val maxsessions)" 2 MaxSessions
    verification_expect "$(audit_eff_val logingracetime)" 30 LoginGraceTime
    verification_expect "$(audit_eff_val clientaliveinterval)" 300 ClientAliveInterval
    verification_expect "$(audit_eff_val clientalivecountmax)" 2 ClientAliveCountMax
    keys_file=$(audit_eff_rest authorizedkeysfile)
    if [[ " $keys_file " != *' .ssh/authorized_keys '* ]]; then
        verification_item warn AuthorizedKeysFile "$(ui 'sshd no usa la ruta de clave que verifica kenroka.' 'sshd does not use the key path that kenroka checks.')"
    fi
    if ! systemctl is-active --quiet ssh.service || ! pgrep -x sshd >/dev/null; then
        verification_item bad SSH "$(ui 'El servicio no está funcionando.' 'The service is not running.')"
    fi
    ports=$(listening_ports) || ports=""
    if [[ -z "$ports" ]]; then
        verification_item bad "$(ui 'Escucha SSH' 'SSH listeners')" "$(ui 'No se encontró ningún listener.' 'No listener found.')"
    else
        verification_item ok "$(ui 'Escucha SSH' 'SSH listeners')" "$ports"
    fi
    if [[ -n "$NEW_PORT" && "$ports" != "$NEW_PORT " ]]; then
        verification_item bad "$(ui 'Puerto esperado' 'Expected port')" "$(ui "Se esperaba solo $NEW_PORT; escucha: $ports" "Expected only $NEW_PORT; listening: $ports")"
    fi
    if [[ $SOCKET_ACTIVATED -eq 1 ]]; then
        port=ssh.socket
    else
        port=ssh.service
    fi
    verification_expect "$(systemctl is-enabled "$port" 2>/dev/null || true)" enabled "$port ($(ui 'al arrancar' 'at boot'))"
}

verification_user() {
    local mode="$SUDO_MODE" state
    if ! valid_username "$USERNAME" || ! id "$USERNAME" >/dev/null 2>&1 || [[ "$(id -u "$USERNAME")" == 0 ]]; then
        verification_item bad "$(ui 'Administrador' 'Administrator')" "$(ui 'No existe un administrador no-root válido.' 'No valid non-root administrator exists.')"
        return 0
    fi
    verification_item ok "$(ui 'Administrador' 'Administrator')" "$USERNAME"
    if verification_key_ok "$USERNAME"; then
        verification_item ok "$(ui 'Clave y permisos' 'Key and permissions')" "$(ui 'Clave válida; propietario y permisos correctos.' 'Valid key; owner and permissions are correct.')"
    else
        verification_item bad "$(ui 'Clave y permisos' 'Key and permissions')" "$(ui 'Clave ausente/inválida o permisos/propietario incorrectos.' 'Missing/invalid key or incorrect permissions/owner.')"
    fi
    if ! visudo -c >/dev/null 2>&1 || ! sudo -l -U "$USERNAME" -- true >/dev/null 2>&1; then
        verification_item bad sudo "$(ui 'La política efectiva no permite administrar.' 'The effective policy does not allow administration.')"
        return 0
    fi
    if [[ -z "$mode" && -f /etc/sudoers.d/90-"$USERNAME" ]]; then
        if grep -q 'NOPASSWD:ALL' /etc/sudoers.d/90-"$USERNAME"; then mode=nopasswd
        elif grep -q 'PASSWD:ALL' /etc/sudoers.d/90-"$USERNAME"; then mode=prompt; fi
    fi
    state=$(password_state "$USERNAME")
    if runuser -u "$USERNAME" -- sudo -k -n true >/dev/null 2>&1; then
        if [[ "$mode" == prompt ]]; then
            verification_item bad sudo "$(ui 'Se eligió contraseña, pero sudo funciona sin ella.' 'Password mode was selected, but sudo works without it.')"
        else
            verification_item ok sudo NOPASSWD
        fi
    elif [[ "$mode" == nopasswd || "$state" != P ]]; then
        verification_item bad sudo "$(ui 'No se comprobó una vía sudo utilizable.' 'No usable sudo path was verified.')"
    else
        verification_item ok sudo "$(ui 'Permisos válidos y contraseña utilizable; falta probarla desde el cliente.' 'Valid privileges and usable password; still needs a client test.')"
    fi
}

verification_firewall() {
    local verbose ports port numbered alias
    if ! has_ufw; then
        verification_item warn UFW "$(ui 'No instalado.' 'Not installed.')"
        return 0
    fi
    if ! verbose=$(ufw status verbose 2>/dev/null); then
        verification_item bad UFW "$(ui 'No pude consultar el firewall.' 'Could not query the firewall.')"
        return 0
    fi
    if ! grep -q '^Status: active' <<< "$verbose"; then
        verification_item warn UFW "$(ui 'Inactivo.' 'Inactive.')"
        return 0
    fi
    verification_item ok UFW "$(ui 'Activo.' 'Active.')"
    if ! grep -qE '^Default: (deny|reject) \(incoming\)' <<< "$verbose"; then
        verification_item warn UFW "$(ui 'La política de entrada no es restrictiva.' 'The incoming policy is not restrictive.')"
    else
        verification_item ok "$(ui 'Entrada por defecto' 'Default incoming')" deny/reject
    fi
    numbered=$(ufw status numbered 2>/dev/null) || numbered=""
    ports=$(listening_ports) || ports=""
    for port in $ports; do
        alias="${port}(/tcp)?"
        [[ "$port" == 22 ]] && alias="$alias|OpenSSH"
        if grep -qE "^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+($alias)([[:space:]]+\\(v6\\))?[[:space:]]+(ALLOW|LIMIT)[[:space:]]+IN([[:space:]]|$)" <<< "$numbered"; then
            verification_item ok "$(ui 'Regla SSH' 'SSH rule')" "$port/tcp"
        else
            verification_item bad "$(ui 'Regla SSH' 'SSH rule')" "$(ui "No se verificó una regla que permita $port/tcp." "No rule allowing $port/tcp was verified.")"
        fi
    done
    verification_item info "$(ui 'Otros servicios TCP/UDP' 'Other TCP/UDP services')" "$(ui 'El usuario debe comprobar desde su equipo los servicios que necesita.' 'The user must test the services they need from their computer.')"
}

verification_fail2ban() {
    local actions action port ports covered value protocol
    if ! has_fail2ban; then
        verification_item warn Fail2ban "$(ui 'No instalado.' 'Not installed.')"
        return 0
    fi
    if ! systemctl is-active --quiet fail2ban || ! timeout 15 fail2ban-client status sshd >/dev/null 2>&1; then
        verification_item bad Fail2ban "$(ui 'Servicio o jail sshd inactivo.' 'Service or sshd jail inactive.')"
        return 0
    fi
    verification_item ok Fail2ban "$(ui 'Servicio y jail sshd activos.' 'Service and sshd jail active.')"
    verification_expect "$(systemctl is-enabled fail2ban 2>/dev/null || true)" enabled "Fail2ban ($(ui 'al arrancar' 'at boot'))"
    actions=$(timeout 15 fail2ban-client get sshd actions 2>/dev/null | tail -n +2 | tr ',' ' ') || actions=""
    ports=$(listening_ports) || ports=""
    for port in $ports; do
        covered=0
        for action in $actions; do
            value=$(timeout 15 fail2ban-client get sshd action "$action" port 2>/dev/null) || value=""
            protocol=$(timeout 15 fail2ban-client get sshd action "$action" protocol 2>/dev/null) || protocol=""
            if [[ "$protocol" == tcp || "$protocol" == all ]] && verification_port_contains "$value" "$port"; then
                covered=1; break
            fi
        done
        if [[ $covered -eq 1 ]]; then
            verification_item ok "$(ui 'Puerto protegido por Fail2ban' 'Port protected by Fail2ban')" "$port"
        else
            verification_item warn Fail2ban "$(ui "No pude verificar que una acción activa cubra el puerto $port." "Could not verify that an active action covers port $port.")"
        fi
    done
}

verification_updates() {
    local config
    if ! systemctl is-active --quiet unattended-upgrades; then
        verification_item warn "$(ui 'Actualizaciones automáticas' 'Automatic updates')" "$(ui 'Servicio inactivo.' 'Service inactive.')"
    else
        verification_item ok unattended-upgrades active
    fi
    verification_expect "$(systemctl is-enabled unattended-upgrades 2>/dev/null || true)" enabled "unattended-upgrades ($(ui 'al arrancar' 'at boot'))"
    if config=$(apt-config dump 2>/dev/null); then
        if ! grep -qE '^APT::Periodic::Update-Package-Lists "1";' <<< "$config" ||
           ! grep -qE '^APT::Periodic::Unattended-Upgrade "1";' <<< "$config"; then
            verification_item warn "$(ui 'Configuración APT efectiva' 'Effective APT configuration')" "$(ui 'Las actualizaciones periódicas no están habilitadas.' 'Periodic updates are not enabled.')"
        else
            verification_item ok "$(ui 'Configuración APT efectiva' 'Effective APT configuration')" "$(ui 'Habilitada.' 'Enabled.')"
        fi
    else
        verification_item bad APT "$(ui 'No pude consultar la configuración efectiva.' 'Could not query effective configuration.')"
    fi
    for config in apt-daily.timer apt-daily-upgrade.timer; do
        if systemctl is-enabled --quiet "$config" && systemctl is-active --quiet "$config"; then
            verification_item ok "$config" "$(ui 'Programado.' 'Scheduled.')"
        else
            verification_item warn "$config" "$(ui 'No está programado para ejecutarse.' 'Not scheduled to run.')"
        fi
    done
    if [[ -f "$REBOOT_FLAG" ]]; then
        verification_item warn "$(ui 'Reinicio pendiente' 'Reboot pending')" "$(ui 'Reinicia y repite la verificación.' 'Reboot and repeat verification.')"
    fi
}

verification_rollbacks() {
    local pending dir
    if ! pending=$(list_pending_rollbacks); then
        verification_item bad "$(ui 'Reversión' 'Rollback')" "$(ui 'No pude consultar los temporizadores.' 'Could not query timers.')"
    elif [[ -n "$pending" ]]; then
        verification_item warn "$(ui 'Cuenta atrás pendiente' 'Pending countdown')" "$pending"
    else
        verification_item ok "$(ui 'Cuenta atrás' 'Countdown')" "$(ui 'Ninguna pendiente.' 'None pending.')"
    fi
    for dir in "$SNAPSHOTS_DIR"/*; do
        [[ -d "$dir" && ! -f "$dir/REVERTED" ]] || continue
        if [[ -f "$dir/ROLLBACK_FAILED" ]]; then
            verification_item bad "$(ui 'Rollback fallido' 'Failed rollback')" "$dir"
        elif [[ -f "$dir/ROLLING_BACK" ]]; then
            verification_item warn "$(ui 'Reversión en curso' 'Rollback in progress')" "$dir"
        fi
    done
}

verification_collect() {
    VERIFY_FAILURES=0
    VERIFY_PENDING=0
    printf '%s\n' "$(ui 'VERIFICACIÓN DEL HARDENING' 'HARDENING VERIFICATION')"
    printf '%s\n' "$(ui 'Fecha' 'Date'): $(date -Is)"
    printf '%s\n' "$(ui 'Equipo' 'Host'): $(hostname)"
    printf '%s\n' "$(ui 'Versión' 'Version'): $SCRIPT_VERSION"
    printf '%s\n' "$(ui 'Administrador' 'Administrator'): $USERNAME"
    printf '%s\n' "$(ui 'Política sudo solicitada' 'Requested sudo policy'): ${SUDO_MODE:-$(ui 'conservar la efectiva' 'keep effective policy')}"
    printf '%s\n' "$(ui 'Puerto solicitado' 'Requested port'): ${NEW_PORT:-$(ui 'actual' 'current')}"
    detect_ssh_activation
    verification_user
    verification_ssh
    verification_firewall
    verification_fail2ban
    verification_updates
    verification_rollbacks
}

verification_result() {
    if [[ $VERIFY_FAILURES -gt 0 ]]; then
        VERIFY_STATUS="$(ui 'CON FALLOS' 'FAILED')"
        return 1
    elif [[ $VERIFY_PENDING -gt 0 || "$VERIFY_EXTERNAL" != confirmed ]]; then
        VERIFY_STATUS="$(ui 'CON PENDIENTES' 'PENDING')"
        return 2
    fi
    VERIFY_STATUS="$(ui 'EXITOSO' 'SUCCESSFUL')"
    return 0
}

verification_run() {
    local UI_PLAIN=1
    local RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
    local token="" rc=0 reports="$STATE_DIR/reports" address=""
    if [[ -z "$USERNAME" ]]; then
        ui_read "$(ui 'Usuario administrador a verificar: ' 'Administrator to verify: ')" USERNAME || return 1
    fi
    if ! valid_username "$USERNAME"; then
        error "$(ui 'Indica un administrador válido con --user NOMBRE.' 'Specify a valid administrator with --user NAME.')"
        return 1
    fi
    # El único estado que escribe esta opción es su reporte, privado de root.
    mkdir -p "$reports" || return 1
    chmod 700 "$STATE_DIR" "$reports" || return 1
    VERIFY_REPORT=$(mktemp "$reports/$(date +%Y%m%d-%H%M%S).XXXXXX") || return 1
    mv "$VERIFY_REPORT" "$VERIFY_REPORT.txt" || return 1
    VERIFY_REPORT="$VERIFY_REPORT.txt"
    chmod 600 "$VERIFY_REPORT" || return 1
    VERIFY_EXTERNAL=unconfirmed
    verification_collect > "$VERIFY_REPORT" || return 1
    cat "$VERIFY_REPORT"
    if [[ $VERIFY_FAILURES -eq 0 && $VERIFY_PENDING -eq 0 && $NON_INTERACTIVE -eq 0 && $ASSUME_YES -eq 0 && -t 0 ]]; then
        echo
        address="${PUBLIC_IP:-$(audit_session_ip)}"
        address="${address:-DIRECCION_DEL_VPS}"
        # show_access_test_steps usa PUBLIC_IP. Para una auditoría donde no se
        # pudo detectar, se muestra el fallback solo durante esta pantalla.
        local saved_public_ip="$PUBLIC_IP"
        PUBLIC_IP="$address"
        show_access_test_steps "$(current_ssh_port)" "$(ui 'Verificación final: la configuración técnica pasó. Falta tu comprobación real desde otra terminal y de los servicios que necesitas.' 'Final verification: technical configuration passed. Your real check from another terminal and of the services you need is still required.')"
        PUBLIC_IP="$saved_public_ip"
        if ask_access_result \
            "marcar la prueba externa como confirmada" "mark the external test confirmed" \
            "dejar la verificación pendiente" "leave verification pending"; then
            VERIFY_EXTERNAL=confirmed
            # Nunca reutilizar un resultado anterior a la confirmación: un timer,
            # un reinicio o un cambio concurrente puede haber alterado el servidor.
            verification_collect > "$VERIFY_REPORT" || return 1
            if [[ $VERIFY_FAILURES -gt 0 || $VERIFY_PENDING -gt 0 ]]; then
                info "$(ui 'El estado cambió durante la confirmación; estas son las comprobaciones actuales:' 'The state changed during confirmation; these are the current checks:')"
                cat "$VERIFY_REPORT"
            fi
        fi
    fi
    verification_result || rc=$?
    {
        printf '\n%s: %s\n' "$(ui 'Resultado' 'Result')" "$VERIFY_STATUS"
        printf '%s: %s; %s: %s\n' "$(ui 'Fallos' 'Failures')" "$VERIFY_FAILURES" "$(ui 'Pendientes técnicos' 'Technical pending')" "$VERIFY_PENDING"
        printf '%s: %s\n' "$(ui 'Acceso, sudo y servicios externos (declaración del usuario)' 'External access, sudo and services (user declaration)')" \
            "$( [[ "$VERIFY_EXTERNAL" == confirmed ]] && ui 'confirmados' 'confirmed' || ui 'sin confirmar' 'unconfirmed')"
        printf '%s\n' "$(ui 'Solo se verificó el perfil indicado y el contexto SSH mostrado; no se cambiaron configuraciones ni temporizadores.' 'Only the stated profile and displayed SSH context were checked; no configurations or timers were changed.')"
    } >> "$VERIFY_REPORT" || return 1
    echo
    printf '%s: %s\n' "$(ui 'Resultado' 'Result')" "$VERIFY_STATUS"
    printf '%s: %s\n' "$(ui 'Reporte guardado' 'Report saved')" "$VERIFY_REPORT"
    case "$rc" in
        0) success "$(ui 'Verificación completada para el perfil y contexto mostrados. La prueba externa fue una confirmación de la persona operadora.' 'Verification completed for the displayed profile and context. The external test was an operator confirmation.')" ;;
        2) info "$(ui 'Verificación pendiente: abre otra terminal, ejecuta el comando mostrado y repite la opción 2.3 tras completar los pendientes.' 'Verification pending: open another terminal, run the displayed command, and repeat option 2.3 after completing pending items.')" ;;
        *) warn "$(ui 'Verificación con fallos: revisa el componente marcado en el reporte antes de cambiar o declarar exitoso el hardening.' 'Verification failed: review the component marked in the report before changing anything or declaring hardening successful.')" ;;
    esac
    return "$rc"
}

offer_final_verification() {
    local answer=""
    if [[ ${RECOVERY_OCCURRED:-0} -eq 1 || -n "$(list_pending_rollbacks)" ]]; then
        info "$(ui 'No ofrezco la verificación final todavía: primero completa la fase pendiente o deja que la protección temporal restaure el estado.' 'The final verification is not offered yet: first complete the pending phase or let temporary protection restore the state.')"
        return 0
    fi
    if [[ $NON_INTERACTIVE -eq 1 || $ASSUME_YES -eq 1 || ! -t 0 ]]; then
        info "$(ui 'Verificación opcional disponible en el menú (13) o con --verify --user NOMBRE.' 'Optional verification is available in menu (13) or with --verify --user NAME.')"
        return 0
    fi
    ui_read "$(ui '¿Quieres verificar ahora el hardening aplicado? [S/n] ' 'Verify the applied hardening now? [Y/n] ')" answer || return 0
    case "$answer" in
        ""|s|S|y|Y) verification_run ;;
        *) return 0 ;;
    esac
}

# ============================================================
# MENÚ PRINCIPAL
# ============================================================
# Solo cuentas atrás que AÚN van a disparar (--state=active): al cumplir, el
# timer pasa a inactivo pero puede seguir cargado mientras corre el rollback.
list_pending_rollbacks() {
    systemctl list-units --all --no-legend --no-pager --type=timer --state=active \
        'secure-vps-rollback*' 2>/dev/null | awk '{print $1}'
}

cancel_all_rollbacks() {
    local units u killed=0 left
    units=$(list_pending_rollbacks)
    if [[ -z "$units" ]]; then
        info "$(ui "No hay cuentas atrás pendientes." "There are no pending countdowns.")"
        return 0
    fi
    for u in $units; do
        if kill_rollback_timer "${u%.timer}"; then
            info "$(ui "Cancelada $u" "Cancelled $u")"
            killed=1
        else
            error "$(ui "NO pude cancelar $u: el temporizador sigue armado." "COULD NOT cancel $u: the timer is still armed.")"
        fi
    done
    left=$(list_pending_rollbacks)
    if [[ -z "$left" ]]; then
        ROLLBACK_ARMED=0
        success "$(ui "Cuenta(s) atrás cancelada(s); ya no queda ninguna pendiente." "Countdown(s) cancelled; none pending anymore.")"
    else
        error "$(ui "Quedan pendientes: $left" "Still pending: $left")"
        return 1
    fi
}

last_snapshot() {
    find "$SNAPSHOTS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1
}

# Snapshot más reciente que todavía admite una restauración manual. Un rollback
# automático marca el directorio con REVERTED; el binario de rollback lo omite,
# por eso la opción del menú no debe seleccionarlo ni anunciar un falso éxito.
last_restorable_snapshot() {
    local candidate latest=""
    for candidate in "$SNAPSHOTS_DIR"/*; do
        [[ -d "$candidate" && -f "$candidate/READY" && ! -f "$candidate/REVERTED" ]] || continue
        # El timer ya puede estar inactivo mientras su servicio sigue revirtiendo.
        # El trap del rollback quita esta marca al fallar, por lo que ese snapshot
        # queda disponible para reintentar la restauración.
        [[ ! -f "$candidate/ROLLING_BACK" ]] || continue
        latest="$candidate"
    done
    printf '%s' "$latest"
}

# Una cuenta atrás viva de OTRA ejecución (típicamente la que quedó armada al
# correr desde la consola del proveedor, donde nadie puede confirmar) no debe
# bloquear sin salida: se explica qué es y, si hay terminal, se ofrece
# cancelarla y continuar. Cancelarla hace permanentes los cambios de aquélla.
pending_rollback_gate() {
    local jobs="$1"
    if [[ -z "$jobs" ]]; then
        return 0
    fi
    warn "$(ui "Hay una cuenta atrás pendiente de una ejecución anterior:" "There is a countdown pending from an earlier run:")"
    echo "    $jobs"
    echo "    $(ui "Se cancela con:" "Cancel it with:") sudo systemctl stop $jobs"
    if [[ $NON_INTERACTIVE -eq 1 || $ASSUME_YES -eq 1 ]]; then
        error "$(ui "Modo desatendido: no la cancelo por mi cuenta. Resuélvela y vuelve a ejecutar." "Unattended mode: I will not cancel it on my own. Resolve it and run again.")"
        return 1
    fi
    # La pregunta va en una variable por una limitación del parser de bash 3.2
    # (el de macOS): este texto, anidado en "$(ui ...)" dentro de comillas, lo
    # dejaba colgado buscando una comilla de cierre.
    local pregunta
    pregunta="$(ui "La cancelo ahora (los cambios de aquella ejecución pasan a ser permanentes) y continúo?" "Cancel it now (those changes become permanent) and continue?")"
    if ! confirm "$pregunta"; then
        return 1
    fi
    cancel_all_rollbacks || return 1
    return 0
}

restore_last_snapshot() {
    local last
    last=$(last_restorable_snapshot)
    if [[ -z "$last" ]]; then
        warn "$(ui "No hay snapshots recuperables en $SNAPSHOTS_DIR (sin revertir automáticamente)." "There are no restorable snapshots in $SNAPSHOTS_DIR (not already automatically reverted).")"
        return 1
    fi
    header "$(ui "Revertir al snapshot" "Revert to the snapshot")"
    echo "  $(ui "Destino:" "Target:") $last"
    [[ -f "$last/meta" ]] && sed 's/^/  /' "$last/meta"
    echo
    if ! confirm "$(ui "¿Restaurar ese estado ahora (SSH, UFW y fail2ban)?" "Restore that state now (SSH, UFW and fail2ban)?")"; then
        info "$(ui "Cancelado." "Cancelled.")"
        return 0
    fi
    cancel_all_rollbacks
    [[ -x "$ROLLBACK_BIN" ]] || install_rollback_bin
    rm -f "$last/CONFIRMED"
    if "$ROLLBACK_BIN" "$last"; then
        success "$(ui "Estado restaurado desde $last" "State restored from $last")"
    else
        error "$(ui "El rollback falló. Entra por la consola VNC del proveedor." "The rollback failed. Get in through the provider VNC console.")"
        return 1
    fi
}

phase_label() {
    case "$1" in
        fase_1_user)           ui "fase 1 (cuenta administradora)" "phase 1 (admin account)" ;;
        fase_2_ssh_key)        ui "fase 2 (clave SSH)" "phase 2 (SSH key)" ;;
        fase_2b_updates)       ui "fase 2.5 (actualizaciones de hoy)" "phase 2.5 (today's updates)" ;;
        fase_3_harden_ssh)     ui "fase 3 (protección SSH)" "phase 3 (SSH protection)" ;;
        fase_4_ufw)            ui "fase 4 (cortafuegos)" "phase 4 (firewall)" ;;
        fase_5_fail2ban)       ui "fase 5 (Fail2ban)" "phase 5 (Fail2ban)" ;;
        fase_6_auto_updates)   ui "fase 6 (actualizaciones automáticas)" "phase 6 (automatic updates)" ;;
        fase_7_change_port)    ui "fase 7 (puerto SSH)" "phase 7 (SSH port)" ;;
        *)                     printf '%s' "$1" ;;
    esac
}

run_all_fases() {
    local step
    for step in fase_1_user fase_2_ssh_key fase_2b_updates fase_3_harden_ssh fase_4_ufw \
                fase_5_fail2ban fase_6_auto_updates; do
        if ! run_phase "$step"; then
            error "$(ui "El proceso se detuvo en $(phase_label "$step")." "The process stopped in $(phase_label "$step").")"
            return 1
        fi
    done
    # La fase 7 se llama siempre: sin --port decide sola (pregunta en modo
    # interactivo; en desatendido u --yes se omite desde su propio guard).
    if ! run_phase fase_7_change_port; then
        error "$(ui "El proceso se detuvo en $(phase_label fase_7_change_port)." "The process stopped in $(phase_label fase_7_change_port).")"
        return 1
    fi
    clear_screen
    return 0
}

main_menu() {
    local option section=all menu_width
    while true; do
        clear_screen
        banner
        ui_text "$(ui 'Servidor' 'Server'): ${PUBLIC_IP:-?} · SSH: $CURRENT_PORT"
        ui_text "$(ui 'Administrador' 'Administrator'): ${USERNAME:-${ORIGINAL_USER:-?}}"
        ui_panel "$(ui '¿QUÉ QUIERES HACER?' 'WHAT WOULD YOU LIKE TO DO?')"
        menu_width=$(ui_width)
        if [[ $section == all ]]; then
            UI_RENDER_WIDTH="$menu_width" ui_menu_text <<EOF
1) $(ui 'Configurar el VPS con la guía completa' 'Configure the VPS with the complete guide')
    1.1) $(ui 'Preparar cuenta administradora con sudo' 'Prepare an admin account with sudo')
    1.2) $(ui 'Añadir una clave pública SSH' 'Add an SSH public key')
    1.3) $(ui 'Revisar y aplicar actualizaciones pendientes' 'Review and apply pending updates')
    1.4) $(ui 'Probar clave y cerrar root/contraseña' 'Test key and close root/password')
    1.5) $(ui 'Activar UFW y repetir prueba de acceso' 'Enable UFW and repeat access test')
    1.6) $(ui 'Activar Fail2ban' 'Enable Fail2ban')
    1.7) $(ui 'Activar actualizaciones automáticas' 'Enable automatic updates')
    1.8) $(ui 'Cambiar puerto SSH (opcional)' 'Change SSH port (optional)')
EOF
        fi
        if [[ $section == all || $section == review ]]; then
            UI_RENDER_WIDTH="$menu_width" ui_menu_text <<EOF
2) $(ui 'Revisar el VPS' 'Review the VPS')
    2.1) $(ui 'Ver resultado y tareas pendientes' 'View results and pending tasks')
    2.2) $(ui 'Revisar el estado sin cambiar nada' 'Review state without changing anything')
    2.3) $(ui 'Verificar el hardening aplicado y guardar reporte' 'Verify applied hardening and save a report')
EOF
        fi
        if [[ $section == all || $section == recovery ]]; then
            UI_RENDER_WIDTH="$menu_width" ui_menu_text <<EOF
3) $(ui 'Confirmar o recuperar cambios de acceso' 'Confirm or recover access changes')
    3.1) $(ui 'Conservar cambios tras probar SSH y sudo' 'Keep changes after testing SSH and sudo')
    3.2) $(ui 'Restaurar el último snapshot de acceso' 'Restore the latest access snapshot')
EOF
        fi
        ui_text "4) $(ui 'Ayuda' 'Help')"
        if [[ $section != all ]]; then ui_text "b) $(ui 'Volver al menú completo' 'Back to the complete menu')"; fi
        ui_text "0) $(ui 'Salir' 'Exit')"
        echo
        ui_text "$(ui 'Escribe el número completo (ejemplo: 1.1 o 2.3) y pulsa Enter. El 1 inicia toda la guía; el 2 y el 3 muestran su grupo.' 'Type the complete number (example: 1.1 or 2.3) and press Enter. 1 starts the full guide; 2 and 3 show their group.')"
        if ! ui_read "$(ui 'Escribe una opción: ' 'Type an option: ')" option; then return 0; fi

        case "$option" in
            2) section=review ;;
            3) section=recovery ;;
            b|B) section=all ;;
            4|h|H|\?) ui_help; pause ;;
            1)
                if ! fase_0_welcome; then continue; fi
                if ! run_all_fases; then
                    error "$(ui "Proceso incompleto. El resumen indica qué se restauró o qué fase debes repetir." "Process incomplete. The summary states what was restored or which phase you must repeat.")"
                    final_summary
                    pause
                    continue
                fi
                final_summary
                offer_final_verification || true
                pause
                ;;
            1.1) run_phase fase_1_user || true ;;
            1.2) run_phase fase_2_ssh_key || true ;;
            1.3) run_phase fase_2b_updates || true ;;
            1.4) run_phase fase_3_harden_ssh || true ;;
            1.5) run_phase fase_4_ufw || true ;;
            1.6) run_phase fase_5_fail2ban || true ;;
            1.7) run_phase fase_6_auto_updates || true ;;
            1.8) run_phase fase_7_change_port || true ;;
            2.1) final_summary; pause ;;
            3.1)
                header "$(ui "Conservar cambios pendientes" "Keep pending changes")"
                info "$(ui "Usa esta opción solo después de probar desde otra terminal que SSH con clave y sudo funcionan. Cancelarla convierte en permanentes los cambios protegidos." "Use this option only after testing from another terminal that key-based SSH and sudo work. Cancelling makes the protected changes permanent.")"
                if confirm "$(ui "¿Ya hiciste esa prueba y quieres conservar los cambios?" "Have you done that test and want to keep the changes?")"; then
                    cancel_all_rollbacks
                else
                    info "$(ui "No se cambió nada; la protección temporal sigue activa." "Nothing changed; temporary protection remains active.")"
                fi
                pause
                ;;
            3.2) restore_last_snapshot; pause ;;
            2.2) audit_report; pause ;;
            2.3) verification_run || true; pause ;;
            0) echo "$(ui "Saliendo..." "Exiting...")"; exit 0 ;;
            *) warn "$(ui "Opción no válida." "Invalid option.")"; sleep 1 ;;
        esac
    done
}

# ============================================================
# ENTRYPOINT
# ============================================================
on_exit() {
    local rc=$?
    if [[ $ROLLBACK_ARMED -eq 1 ]]; then
        echo
        warn "$(ui "Sales con protección temporal activa. Si no completas la prueba, en ${ROLLBACK_MINUTES} min SSH, UFW y Fail2ban volverán al estado anterior." "You are leaving with temporary protection active. If you do not complete the test, SSH, UFW and Fail2ban return to the previous state in ${ROLLBACK_MINUTES} min.")"
        info "$(ui "No hagas nada con el temporizador por ahora. Vuelve a entrar desde tu computadora, prueba SSH con clave y sudo, y completa la fase para conservar los cambios." "Do not touch the timer for now. Log in again from your computer, test key-based SSH and sudo, and complete the phase to keep the changes.")"
    fi
    return $rc
}

main() {
    export LC_ALL=C
    umask 077
    parse_args "$@"
    if [[ $NON_INTERACTIVE -eq 1 || $AUDIT_MODE -eq 1 || $VERIFY_MODE -eq 1 || ${TERM:-dumb} == dumb ]]; then
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
    fi
    check_os || exit 1
    require_root
    check_dependencies || exit 1
    # Antes de cualquier paso que escriba: ni backup, ni STATE_DIR, ni flock, ni
    # cuenta atrás pendiente, ni /run/sshd. El reporte no necesita nada de eso.
    if [[ $AUDIT_MODE -eq 1 ]]; then
        audit_report
        exit 0
    fi
    if [[ $VERIFY_MODE -eq 1 ]]; then
        local verify_rc=0
        verification_run || verify_rc=$?
        exit "$verify_rc"
    fi
    detect_session_kind
    resolve_guided_mode
    choose_ui_language
    check_original_user
    mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"
    chmod 700 "$STATE_DIR" "$SNAPSHOTS_DIR"
    exec 9>"$STATE_DIR/run.lock"
    flock -n 9 || { error "$(ui "Ya hay otra ejecución de secure-vps en curso." "Another secure-vps run is already in progress.")"; exit 1; }
    pending_rollback_gate "$(list_pending_rollbacks)" || exit 1
    check_backup_exists
    detect_public_ip || warn "$(ui "No se detectó la IP pública; usa la dirección habitual del VPS." "Public IP not detected; use the VPS usual address.")"
    ensure_sshd_runtime
    detect_ssh_activation
    CURRENT_PORT=$(current_ssh_port)
    trap on_exit EXIT

    log "Inicio secure-vps v$SCRIPT_VERSION (ip=$PUBLIC_IP lanzador=$ORIGINAL_USER user=${USERNAME:-<pendiente>} puerto=$CURRENT_PORT socket=$SOCKET_ACTIVATED no-interactive=$NON_INTERACTIVE consola=$ON_CONSOLE guia=$GUIDED_MODE)"
    info "$(ui "Puerto SSH actual: $CURRENT_PORT ($( [[ $SOCKET_ACTIVATED -eq 1 ]] && echo 'ssh.socket' || echo 'ssh.service' ))" "Current SSH port: $CURRENT_PORT ($( [[ $SOCKET_ACTIVATED -eq 1 ]] && echo 'ssh.socket' || echo 'ssh.service' ))")"
    if [[ $ON_CONSOLE -eq 1 ]]; then
        warn "$(ui "Esta sesión viene de la consola del proveedor, no de SSH: no hay forma de probar un acceso nuevo desde aquí, así que el script no cerrará el login por contraseña (lo hace tu guía al final)." "This session comes from the provider console, not SSH: a new login cannot be tested from here, so the script will not close password login (its guide does that at the end).")"
    fi
    report_pending_updates

    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        if ! run_all_fases; then
            error "$(ui "Proceso incompleto; revisa $LOG_FILE" "Process incomplete; check $LOG_FILE")"
            exit 1
        fi
        final_summary
    elif [[ $RUN_ALL -eq 1 ]]; then
        if ! fase_0_welcome; then
            info "$(ui "Cancelado; solo vuelve a lanzar el comando." "Cancelled; just run the command again.")"
            exit 0
        fi
        if ! run_all_fases; then
            error "$(ui "Proceso incompleto; revisa $LOG_FILE" "Process incomplete; check $LOG_FILE")"
            final_summary
            exit 1
        fi
        final_summary
        offer_final_verification || return $?
    else
        main_menu
    fi
}

main "$@"
