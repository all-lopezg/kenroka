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
#                       --sudo nopasswd --port 2222 --allow-lockdown --no-rollback --yes
#                     (--allow-lockdown asume el riesgo: cierra sin prueba humana)
#
# Autor: Allan López
# Versión: 1.0.0
#

set -euo pipefail

# ============================================================
# CONFIGURACIÓN GLOBAL
# ============================================================
readonly SCRIPT_VERSION="1.0.0"
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

# Colores (se desactivan si no hay TTY)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# Idioma de la interfaz: detección automática (es* → español, resto → inglés),
# overridable con --lang. ui() devuelve el texto en el idioma activo y SIEMPRE
# devuelve algo: si falta la traducción, cae al texto en español.
UI_LANG="en"
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
info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✘${NC}  $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

confirm() {
    local prompt="$1"
    if [[ $ASSUME_YES -eq 1 ]]; then
        info "$prompt $(ui "→ asumido 's' (modo --yes)" "→ assumed 's' (--yes mode)")"
        return 0
    fi
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        error "$(ui "Confirmación requerida en modo no interactivo sin --yes: $prompt" "Confirmation required in non-interactive mode without --yes: $prompt")"
        exit 1
    fi
    local response
    while true; do
        # EOF en stdin = respuesta "n": sin esto el bucle no termina nunca
        # cuando se corre con la entrada redirigida o cerrada.
        read -rp "$(echo -e "${YELLOW}?${NC}  $prompt [s/n]: ")" response || return 1
        case "$response" in
            [sSyY]) return 0 ;;
            [nN])   return 1 ;;
            *)      echo "$(ui "Responde 's' o 'n'." "Answer 's' or 'n'.")" ;;
        esac
    done
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "$(ui "Este script debe ejecutarse como root (usa: sudo bash $0)" "This script must run as root (use: sudo bash $0)")"
        exit 1
    fi
}

pause() {
    # Sin terminal no tiene sentido esperar un Enter: tragarlo rompería además
    # las respuestas que el operador está escribiendo para las fases siguientes.
    if [[ $NON_INTERACTIVE -eq 1 ]] || [[ ! -t 0 ]]; then
        return 0
    fi
    read -rp "$(echo -e "${CYAN}$(ui "Presiona Enter para continuar..." "Press Enter to continue...")${NC}")" || true
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
        info "$(ui "    desde OTRA terminal y escribas acceso-ok. Si no puedes, revierte solo." "    from ANOTHER terminal and type acceso-ok. If you cannot, it reverts on its own.")"
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
  --port PUERTO        Nuevo puerto SSH (opcional, ej: 2222).
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
  --help               Mostrar esta ayuda.

Ejemplo interactivo (el recomendado: la fase 3 te pide confirmar desde otra terminal):
  sudo bash secure-vps.sh --user administrador --port 2222

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
  --port PUERTO        New SSH port (optional, e.g.: 2222).
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
  --help               Show this help.

Interactive example (recommended: phase 3 asks you to confirm from another terminal):
  sudo bash secure-vps.sh --user administrador --port 2222

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
            --lang)            require_val "$@"
                               case "$2" in es|en) UI_LANG="$2";; *) error "$(ui "Idioma no soportado: usa --lang es o --lang en" "Unsupported language: use --lang es or --lang en")"; exit 1;; esac
                               shift 2 ;;
            --help|-h)         usage; exit 0 ;;
            *)                 error "$(ui "Opción desconocida: $1" "Unknown option: $1")"; usage; exit 1 ;;
        esac
    done

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

    if [[ $NON_INTERACTIVE -eq 1 ]]; then
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
trap 'touch "$SNAP/ROLLBACK_FAILED"' ERR
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
        ROLLBACK_ARMED=1
        warn "$(ui "Cuenta atrás armada: en ${ROLLBACK_MINUTES}m todo vuelve atrás solo." "Countdown armed: in ${ROLLBACK_MINUTES}m everything rolls back on its own.")"
        info "$(ui "Al confirmar el acceso se cancela, o a mano (ojo: stop, no cancel):" "Confirming access cancels it, or manually (note: stop, not cancel):")"
        echo "    systemctl stop $ROLLBACK_JOB.timer"
        log "rollback armado en $ROLLBACK_JOB (${ROLLBACK_MINUTES}m) -> $SNAP_DIR"
    else
        error "$(ui "No pude armar el rollback temporizado." "Could not arm the timed rollback.")"
        return 1
    fi
}

disarm_rollback() {
    [[ $ROLLBACK_ARMED -eq 1 ]] || return 0
    if ! (
        exec 8>"$SNAP_DIR/lock" || exit 1
        flock -x 8 || exit 1
        [[ ! -f "$SNAP_DIR/ROLLING_BACK" ]] || exit 1
        touch "$SNAP_DIR/CONFIRMED"
    ); then
        error "$(ui "El rollback ya comenzó o no pude registrar la confirmación. No continuaré." "The rollback already started or the confirmation could not be recorded. I will not continue.")"
        return 1
    fi
    if kill_rollback_timer "$ROLLBACK_JOB"; then
        ROLLBACK_ARMED=0
        success "$(ui "Cuenta atrás cancelada. Los cambios son permanentes." "Countdown cancelled. The changes are permanent.")"
        log "rollback cancelado: $ROLLBACK_JOB"
    else
        # Si el timer sigue vivo, en N minutos el servidor revierte solo justo
        # cuando creías que habías confirmado el acceso: hay que decirlo fuerte.
        error "$(ui "El temporizador $ROLLBACK_JOB.timer SIGUE ARMADO pese a confirmar." "Timer $ROLLBACK_JOB.timer is STILL ARMED despite confirmation.")"
        error "$(ui "Detenlo ahora a mano: systemctl stop $ROLLBACK_JOB.timer" "Stop it now manually: systemctl stop $ROLLBACK_JOB.timer")"
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
fase_0_welcome() {
    clear 2>/dev/null || true
    header "SECURE-VPS v$SCRIPT_VERSION"
if [[ $UI_LANG == es ]]; then
cat <<EOF
IP pública detectada: ${BOLD}${PUBLIC_IP}${NC}
Usuario lanzador:    ${BOLD}${ORIGINAL_USER:-root}${NC}

Este script va a endurecer la seguridad de tu VPS Ubuntu:
  1. Crear un usuario con sudo que realmente funcione (contraseña o NOPASSWD)
  2. Instalar tu clave pública y verificar que sshd la acepta
  3. Aplicar límites de seguridad (MaxAuthTries, MaxSessions, etc.)
  4. Deshabilitar login de root y autenticación por contraseña
  5. Activar el cortafuegos UFW avisando de lo que va a bloquear
  6. Instalar y configurar Fail2ban (con tu IP excluida del bloqueo)
  7. Configurar actualizaciones automáticas de seguridad
  8. Cambiar el puerto SSH fuera del 22 (recomendado)

Red de seguridad:
  • Antes de cerrar el acceso se comprueba la config efectiva de sshd.
  • Al cerrar el acceso arranca una cuenta atrás de ${ROLLBACK_MINUTES}m: si no
    confirmas que entras con la clave, todo vuelve atrás solo.
  • Habrá 2-3 momentos en los que el script se detiene y te pide probar la
    conexión nueva desde OTRA terminal y escribir acceso-ok aquí. Tenla lista.
  • Cada cambio deja un snapshot en $SNAPSHOTS_DIR (opción 11 del menú).

⚠️  ADVERTENCIAS:
  • NO cierres tu sesión SSH actual hasta que el script termine.
  • Ten abierta la consola VNC/KVM de tu proveedor como respaldo.

El script es IDEMPOTENTE: puedes ejecutarlo varias veces sin efectos
secundarios. Detectará lo ya configurado y lo omitirá.
EOF
else
cat <<EOF
Detected public IP: ${BOLD}${PUBLIC_IP}${NC}
Launching user:     ${BOLD}${ORIGINAL_USER:-root}${NC}

This script will harden your Ubuntu VPS:
  1. Create a user with sudo that actually works (password or NOPASSWD)
  2. Install your public key and verify sshd accepts it
  3. Apply security limits (MaxAuthTries, MaxSessions, etc.)
  4. Disable root login and password authentication
  5. Enable the UFW firewall, warning you about what it will block
  6. Install and configure Fail2ban (with your IP excluded from bans)
  7. Configure automatic security updates
  8. Move SSH off port 22 (recommended)

Safety net:
  • Before locking down, the effective sshd configuration is verified.
  • Locking down starts a ${ROLLBACK_MINUTES}m countdown: if you do not confirm
    that you can get in with the key, everything reverts on its own.
  • There will be 2-3 moments where the script stops and asks you to test the
    new connection from ANOTHER terminal and type acceso-ok here. Have it ready.
  • Every change leaves a snapshot in $SNAPSHOTS_DIR (menu option 11).

⚠️  WARNINGS:
  • Do NOT close your current SSH session until the script finishes.
  • Keep your provider's VNC/KVM console open as a fallback.

The script is IDEMPOTENT: you can run it several times without side
effects. It detects what is already configured and skips it.
EOF
fi
    if guided_active; then
        echo
        info "$(ui "Si es tu primer VPS: no hay prisa. Cada fase dice qué hace y qué tienes que teclear; si algo no te cuadra, responde 'n' y el script vuelve atrás solo." "If this is your first VPS: no rush. Each phase says what it does and what you have to type; if something is off, answer 'n' and the script reverts on its own.")"
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

install_sudoers_nopasswd() {
    local user="$1" file="/etc/sudoers.d/90-$user"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "$file.tmp" || return 1
    if visudo -cf "$file.tmp" >/dev/null 2>&1; then
        mv "$file.tmp" "$file"
        chmod 0440 "$file"
        success "$(ui "Drop-in instalado en $file" "Drop-in installed at $file")"
    else
        rm -f "$file.tmp"
        error "$(ui "El drop-in de sudoers no pasó visudo; no lo instalé." "The sudoers drop-in failed visudo; not installed.")"
        return 1
    fi
}

ask_sudo_mode() {
    [[ -n "$SUDO_MODE" ]] && return 0
    if [[ $ASSUME_YES -eq 1 ]]; then
        SUDO_MODE=prompt
        return 0
    fi
    echo
    echo "  $(ui "'$USERNAME' necesita una forma real de escalar a root:" "'$USERNAME' needs a real way to escalate to root:")"
    echo "    $(ui "1) contraseña   (recomendado; sudo la pide en la terminal, no afecta a SSH)" "1) password   (recommended; sudo asks for it in the terminal, unrelated to SSH)")"
    echo "    $(ui "2) NOPASSWD     (cómodo, más superficie de ataque si te roban la sesión)" "2) NOPASSWD     (convenient, larger attack surface if your session is stolen)")"
    echo "    $(ui "3) ninguna      (lo dejas para después)" "3) none        (leave it for later)")"
    read -rp "  $(ui "Elige 1/2/3 [1]: " "Choose 1/2/3 [1]: ")" answer
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
    ask_sudo_mode
    state=$(password_state "$user")

    case "$SUDO_MODE" in
        nopasswd)
            install_sudoers_nopasswd "$user" || return 1
            ;;
        prompt)
            if [[ "$state" == "P" ]]; then
                success "$(ui "$user ya tiene contraseña: sudo la pedirá y listo." "$user already has a password: sudo will just ask for it.")"
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

fase_1_user() {
    header "$(ui "FASE 1: Crear usuario con sudo utilizable" "PHASE 1: Create a usable sudo user")"

    if [[ -z "$USERNAME" ]]; then
        read -rp "$(ui "Usuario administrador no-root (existente o nuevo): " "Non-root admin user (existing or new): ")" USERNAME || return 1
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
        success "$(ui "Usuario creado." "User created.")"
    fi

    if groups "$USERNAME" | grep -qw sudo; then
        success "$(ui "El usuario '$USERNAME' ya tiene sudo." "User '$USERNAME' already has sudo.")"
    else
        usermod -aG sudo "$USERNAME" || return 1
        success "$(ui "Privilegios sudo otorgados a '$USERNAME'." "Sudo privileges granted to '$USERNAME'.")"
    fi

    ensure_usable_sudo "$USERNAME" || return 1

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
    chown -R "$user:$user" "$ssh_dir"
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
    if [[ -t 0 && $NON_INTERACTIVE -eq 0 && $ASSUME_YES -eq 0 ]]; then
        echo
        echo "  $(ui "1) macOS" "1) macOS")"
        echo "  $(ui "2) Windows 10/11 (PowerShell)" "2) Windows 10/11 (PowerShell)")"
        echo "  $(ui "3) Linux u otro" "3) Linux or other")"
        read -rp "$(ui "  ¿Desde qué computadora trabajas? [1/2/3]: " "  Which computer are you working from? [1/2/3]: ")" answer
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
       $( [[ $win -eq 1 ]] && echo 'type $env:USERPROFILE\.ssh\id_ed25519.pub' || echo 'cat ~/.ssh/id_ed25519.pub' )
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
       $( [[ $win -eq 1 ]] && echo 'type $env:USERPROFILE\.ssh\id_ed25519.pub' || echo 'cat ~/.ssh/id_ed25519.pub' )
  3. Copy that line (it starts with 'ssh-ed25519') and paste it when this script asks.

  The private key (id_ed25519, without .pub) is NOT copied anywhere: it stays on
  your computer. Whoever holds it holds your access.
EOF
    fi
}

fase_2_ssh_key() {
    header "$(ui "FASE 2: Configurar clave SSH" "PHASE 2: Set up the SSH key")"

    resolve_pubkey
    if [[ -z "$SSH_PUBKEY" ]]; then
        info "$(ui "Necesitas copiar tu clave pública SSH al usuario '$USERNAME'." "You need to copy your SSH public key to user '$USERNAME'.")"
        echo
        if guided_active && collect_key_candidates; then
            echo "$(ui "Ya hay claves autorizadas en este equipo. Si alguna es la tuya (con la que entraste hoy), reutilízala y no muevas nada:" "This machine already has authorized keys. If one of them is yours (the one you used to get in today), reuse it and move nothing:")"
            print_key_candidates
            echo
            read -rp "$(ui "  Número de TU clave (o Enter para pegar una distinta): " "  Number of YOUR key (or Enter to paste a different one): ")" choice
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
                echo "$(ui "Para entrar por SSH sin contraseña hace falta un par de claves. Se crea en TU computadora, no aquí:" "To log in over SSH without a password you need a key pair. It is created on YOUR computer, not here:")"
                ask_client_os
                key_howto_text
                echo
                echo "$(ui "Si ya tienes tu clave en la computadora, puedes copiarla a este usuario con:" "If you already have your key on your computer, you can copy it to this user with:")"
                echo -e "  ${CYAN}ssh-copy-id -p $CURRENT_PORT $USERNAME@$PUBLIC_IP${NC}"
                echo
            else
                echo "$(ui "Desde donde tengas tu clave privada, ejecuta:" "From wherever your private key is, run:")"
                echo -e "  ${CYAN}ssh-copy-id -p $CURRENT_PORT $USERNAME@$PUBLIC_IP${NC}"
                echo
            fi
            echo "$(ui "O pega aquí la clave pública:" "Or paste the public key here:")"
            read -rp "$(ui "Clave pública SSH (o Enter para omitir): " "SSH public key (or Enter to skip): ")" SSH_PUBKEY
            resolve_pubkey
        fi
    fi

    if [[ -z "$SSH_PUBKEY" ]]; then
        KEY_READY=0
        warn "$(ui "No hay clave instalada. Sin ella NO se puede cerrar root/contraseña." "No key installed. Without it root/password CANNOT be locked down.")"
        if [[ $NON_INTERACTIVE -eq 1 ]]; then
            error "$(ui "Modo no interactivo sin --pubkey: cancelo antes de tocar sshd." "Non-interactive mode without --pubkey: aborting before touching sshd.")"
            return 1
        fi
        if ! confirm "$(ui "¿Continuar a la fase 3 en modo --skip-lockdown (solo límites, sin cerrar acceso)?" "Continue to phase 3 in --skip-lockdown mode (limits only, no lockdown)?")"; then
            return 1
        fi
        OPT_SKIP_LOCKDOWN=1
        log "Fase 2 omitida por falta de clave; fase 3 sin cierre de acceso."
        pause
        return 0
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
    info "$(ui "Sigue: la fase 3 deshabilita root y la autenticación por contraseña." "Next: phase 3 disables root and password authentication.")"
    info "$(ui "Antes de eso te pediremos probar ESTA clave desde otra terminal; tenla lista." "Before that you will be asked to test THIS key from another terminal; have it ready.")"
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
    if [[ -f /var/run/reboot-required ]]; then
        warn "$(ui "Hace falta reiniciar: el kernel que está corriendo sigue siendo el viejo, así que los parches nuevos aún no hacen efecto." "A reboot is needed: the running kernel is still the old one, so the new patches are not in effect yet.")"
        echo "    sudo reboot"
    fi
    return 0
}

fase_2b_updates() {
    header "$(ui "FASE 2.5: Aplicar actualizaciones pendientes" "PHASE 2.5: Apply the pending updates")"

    if [[ $UPGRADE_MODE == no ]]; then
        info "$(ui "--no-upgrade: dejo las pendientes para unattended-upgrades (fase 6)." "--no-upgrade: leaving the pending ones to unattended-upgrades (phase 6).")"
        return 0
    fi
    apt_pending_counts
    if [[ "${PENDING_COUNT:-0}" -eq 0 ]]; then
        success "$(ui "Nada pendiente que aplicar." "Nothing pending to apply.")"
        reboot_hint
        return 0
    fi
    if [[ $NON_INTERACTIVE -eq 1 && $UPGRADE_MODE != yes ]]; then
        warn "$(ui "Modo desatendido: no actualizo por tu cuenta. Repite con --upgrade si quieres que lo haga ahora." "Unattended mode: I will not upgrade on my own. Repeat with --upgrade to have it done now.")"
        return 0
    fi
    if [[ $UPGRADE_MODE != yes ]] && ! confirm "$(ui "Quedan $PENDING_COUNT paquetes ($PENDING_SECURITY de seguridad). ¿Los aplico ahora, antes de cerrar el acceso? Puede tardar varios minutos." "$PENDING_COUNT packages remain ($PENDING_SECURITY of them security). Apply them now, before locking down? It may take several minutes.")"; then
        info "$(ui "Los dejas pendientes; la fase 6 hará que se apliquen solos más adelante." "You leave them pending; phase 6 will have them applied on their own later.")"
        return 0
    fi
    info "$(ui "Aplicando actualizaciones (sin retirar ni instalar paquetes nuevos)..." "Applying updates (removing and installing no new packages)...")"
    if ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
            -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef >> "$LOG_FILE" 2>&1; then
        error "$(ui "El upgrade falló: revisa $LOG_FILE y /var/log/dpkg.log. Me detengo ANTES de tocar el acceso." "The upgrade failed: check $LOG_FILE and /var/log/dpkg.log. I stop BEFORE touching access.")"
        return 1
    fi
    success "$(ui "Actualizaciones aplicadas." "Updates applied.")"
    reboot_hint
    log "Fase 2.5 completada: upgrades=$PENDING_COUNT security=$PENDING_SECURITY"
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

confirm_access() {
    local motivo="${1:-}" token="" ipes
    ipes=$(current_admin_ips)
    echo
    warn "$(ui "Abre OTRA sesión (otra terminal, otro cliente, o la consola del proveedor) y prueba; esta sesión queda viva de respaldo:" "Open ANOTHER session (another terminal, another client, or the provider console) and test; this one stays alive as backup:")"
    echo "   ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -p $CURRENT_PORT $USERNAME@$PUBLIC_IP"
    echo "$(ui "En esa sesión comprueba también: sudo -v && sudo -l" "In that session also verify: sudo -v && sudo -l")"
    if [[ -n "$ipes" ]]; then
        warn "$(ui "Necesitas tu clave privada, y conviene partir de esta misma IP: es la única que fail2ban dejó excluida ($ipes). Desde otra IP, tres erratas te bloquean." "You need your private key, and stick to this same IP: it is the only one fail2ban whitelisted ($ipes). From another IP, three typos will ban you.")"
    else
        warn "$(ui "Necesitas tu clave privada a mano para esta prueba." "You need your private key at hand for this test.")"
    fi
    [[ -n "$motivo" ]] && info "$motivo"
    if [[ $ROLLBACK_ARMED -eq 1 ]]; then
        warn "$(ui "La cuenta atrás corre mientras pruebas: te quedan ~${ROLLBACK_MINUTES}m." "The countdown runs while you test: ~${ROLLBACK_MINUTES}m left.")"
        warn "$(ui "Si no funciona, escribe cualquier otra cosa y revierto al instante; si te vas, revierte solo." "If it does not work, type anything else and I revert immediately; if you walk away, it reverts on its own.")"
    fi
    read -rp "$(ui "Si la conexión nueva y sudo funcionan, escribe acceso-ok (otra cosa revierte): " "If the new connection and sudo work, type acceso-ok (anything else reverts): ")" token
    [[ "$token" == "acceso-ok" ]]
}

revert_now() {
    local reason="$1"
    error "$reason"
    if [[ -z "$SNAP_DIR" || ! -f "$SNAP_DIR/READY" ]]; then
        error "$(ui "No hay snapshot válido; no borraré configuración existente. Usa la consola del proveedor." "No valid snapshot; I will not delete existing configuration. Use the provider console.")"
        return 1
    fi
    install_rollback_bin || return 1
    info "$(ui "Revirtiendo desde $SNAP_DIR" "Reverting from $SNAP_DIR")"
    if "$ROLLBACK_BIN" "$SNAP_DIR"; then
        if [[ $ROLLBACK_ARMED -eq 1 ]]; then
            kill_rollback_timer "$ROLLBACK_JOB" || return 1
            ROLLBACK_ARMED=0
        fi
        warn "$(ui "Configuración restaurada desde $SNAP_DIR." "Configuration restored from $SNAP_DIR.")"
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
    header "$(ui "FASE 3: Endurecer configuración SSH" "PHASE 3: Harden the SSH configuration")"
    LOCKDOWN=1

    if [[ $KEY_READY -ne 1 ]]; then
        if [[ -n "$USERNAME" ]] && existing_key_present "$USERNAME"; then
            if [[ $NON_INTERACTIVE -eq 0 ]] && confirm "$(ui "¿Puedes entrar AHORA con clave como '$USERNAME' desde otra terminal?" "Can you log in RIGHT NOW with a key as '$USERNAME' from another terminal?")"; then
                KEY_READY=1
                log "$(ui "Fase 3: clave preexistente confirmada por el operador." "Phase 3: pre-existing key confirmed by the operator.")"
            else
                info "$(ui "Hay clave pero no la confirmaste: modo suave." "A key exists but you did not confirm it: soft mode.")"
            fi
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
    detect_ssh_activation
    CURRENT_PORT=$(current_ssh_port)
    ssh_activation_summary

    if [[ $LOCKDOWN -eq 0 ]]; then
        warn "$(ui "FASE 3 EN MODO SUAVE: aplico límites, dejo root y contraseña como están." "PHASE 3 IN SOFT MODE: applying limits; root and password stay as they are.")"
        [[ $KEY_READY -ne 1 ]] && info "$(ui "Motivo: no hay clave verificada en la fase 2." "Reason: no key was verified in phase 2.")"
        [[ $OPT_SKIP_LOCKDOWN -eq 1 ]] && info "$(ui "Motivo: --skip-lockdown." "Reason: --skip-lockdown.")"
        if [[ $ON_CONSOLE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            info "$(ui "Motivo: estás en la consola del proveedor; desde ahí no puedes probar una conexión SSH nueva." "Reason: you are on the provider console; a new SSH connection cannot be tested from there.")"
        fi
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
        success "$(ui "SSH recargado con los límites (sin cierre de acceso)." "SSH reloaded with the limits (without locking down).")"
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
        if confirm_access; then
            disarm_rollback || return 1
        else
            revert_now "$(ui "No confirmaste el acceso: revierto inmediatamente." "You did not confirm access: reverting immediately.")"
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
        warn "$(ui "Al activar UFW se quedarían sin acceso estos puertos:$risky_tcp$risky_udp" "Enabling UFW would cut access to these ports:$risky_tcp$risky_udp")"
        echo "     $(ui "Si alguno te sirve (web 80/443, DB, panel), ábrelo ahora:" "If you need any of them (web 80/443, DB, panel), open it now:")"
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
        elif confirm "$(ui "¿Abrir ahora esos puertos antes de activar UFW?" "Open those ports now, before enabling UFW?")"; then
            for p in $risky_tcp; do
                ufw allow "${p}/tcp" >> "$LOG_FILE" 2>&1 && info "$(ui "Puerto $p permitido." "Port $p allowed.")"
            done
            for p in $risky_udp; do
                ufw allow "${p}/udp" >> "$LOG_FILE" 2>&1 && info "$(ui "Puerto $p permitido." "Port $p allowed.")"
            done
        else
            info "$(ui "No abro nada: esos puertos quedarán filtrados al activar UFW." "Opening nothing: those ports will stay blocked once UFW is enabled.")"
        fi
    else
        success "$(ui "Todo lo que escucha tiene regla en UFW (o solo es SSH)." "Everything listening already has a UFW rule (or is just SSH).")"
    fi
}

fase_4_ufw() {
    header "$(ui "FASE 4: Activar cortafuegos UFW" "PHASE 4: Enable the UFW firewall")"

    if ! command -v ufw &>/dev/null; then
        info "$(ui "Instalando UFW..." "Installing UFW...")"
        apt-get update && apt-get install -y ufw || return 1
    fi

    CURRENT_PORT=$(current_ssh_port)
    local status was_active=0
    status=$(ufw status) || return 1
    [[ "$status" == *"Status: active"* ]] && was_active=1
    if [[ $was_active -eq 0 ]]; then
        snapshot_state || return 1
        if [[ $NON_INTERACTIVE -eq 0 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            arm_rollback || return 1
        fi
    fi
    info "$(ui "Permitiendo SSH en el puerto $CURRENT_PORT..." "Allowing SSH on port $CURRENT_PORT...")"
    if ! ufw limit "${CURRENT_PORT}/tcp" >> "$LOG_FILE" 2>&1; then
        [[ $was_active -eq 0 ]] && revert_now "$(ui "No pude permitir SSH; no activaré UFW." "Could not allow SSH; I will not enable UFW.")"
        return 1
    fi
    if ! warn_listening_services; then
        [[ $was_active -eq 0 ]] && revert_now "$(ui "No pude preparar las reglas UFW." "Could not prepare the UFW rules.")"
        return 1
    fi
    if [[ $was_active -eq 1 ]]; then
        success "$(ui "UFW ya está activo." "UFW is already active.")"
    elif [[ $NON_INTERACTIVE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
        warn "$(ui "Reglas preparadas; no activo UFW sin prueba de acceso en modo no interactivo." "Rules prepared; not enabling UFW without an access test in non-interactive mode.")"
    elif confirm "$(ui "¿Activar UFW ahora? Los servicios sin reglas quedarán filtrados." "Enable UFW now? Services without rules will stay blocked.")"; then
        if ! ufw --force enable; then
            revert_now "$(ui "Falló la activación de UFW." "Enabling UFW failed.")"
            return 1
        fi
        if [[ $ALLOW_LOCKDOWN -eq 0 && $ON_CONSOLE -eq 1 ]]; then
            warn "$(ui "Desde la consola no puedes probar el SSH nuevo, así que no te pido el acceso-ok." "From the console you cannot test the new SSH, so I will not ask you for acceso-ok.")"
            if [[ -n "$ROLLBACK_JOB" ]]; then
                warn "$(ui "La cuenta atrás de ${ROLLBACK_MINUTES}m sigue armada: si algo quedó mal, revierte sola. Al entrar por SSH desde tu computadora, cancélala con:" "The ${ROLLBACK_MINUTES}m countdown stays armed: if something is wrong it reverts on its own. When you are in over SSH from your computer, cancel it with:")"
                echo "    sudo systemctl stop $ROLLBACK_JOB.timer"
            fi
        elif [[ $ALLOW_LOCKDOWN -eq 0 ]]; then
            if ! confirm_access "$(ui "Prueba adicional por el firewall: si un puerto que necesitas quedó filtrado, aquí lo vas a notar." "Extra test because of the firewall: if a port you need got blocked, you will notice here.")"; then
                revert_now "$(ui "No confirmaste acceso después de activar UFW." "You did not confirm access after enabling UFW.")"
                return 1
            fi
            disarm_rollback || return 1
        fi
        success "$(ui "UFW activado." "UFW enabled.")"
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
            read -rp "$(ui "Escribe la IP de tu computadora actual (Enter para no excluir ninguna): " "Type your computer's current IP (Enter to exclude none): ")" ip_input
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
    header "$(ui "FASE 5: Instalar Fail2ban" "PHASE 5: Install Fail2ban")"

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
        return 1
    fi
    sleep 2
    if ! fail2ban-client status sshd >/dev/null 2>&1; then
        error "$(ui "El jail sshd no quedó activo. Revisa 'fail2ban-client status' y el backend de logs." "The sshd jail is not active. Check 'fail2ban-client status' and the log backend.")"
        return 1
    fi
    fail2ban-client status sshd 2>/dev/null | sed 's/^/    /' || true
    success "$(ui "Fail2ban activo con el jail sshd." "Fail2ban active with the sshd jail.")"

    log "Fase 5 completada (backend=$FAIL2BAN_BACKEND port=$CURRENT_PORT ignore='$ADMIN_IPS')."
    pause
}

# ============================================================
# FASE 6: ACTUALIZACIONES AUTOMÁTICAS
# ============================================================
fase_6_auto_updates() {
    header "$(ui "FASE 6: Actualizaciones automáticas" "PHASE 6: Automatic updates")"

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

fase_7_change_port() {
    header "$(ui "FASE 7: Cambiar puerto SSH (opcional)" "PHASE 7: Change the SSH port (optional)")"

    detect_ssh_activation
    ssh_activation_summary
    CURRENT_PORT=$(current_ssh_port)

    if [[ -z "$NEW_PORT" ]]; then
        if [[ $NON_INTERACTIVE -eq 1 ]]; then
            info "$(ui "Modo no interactivo sin --port. Omitiendo fase 7." "Non-interactive mode without --port. Skipping phase 7.")"
            return 0
        fi
        if [[ $ASSUME_YES -eq 1 ]]; then
            info "$(ui "--yes no decide cambiar el puerto SSH; omite la fase o pasa --port." "--yes does not decide to change the SSH port; skip the phase or pass --port.")"
            return 0
        fi
        # Mover el puerto sin poder probar la conexión nueva es exactamente el
        # caso que el rollback no puede cubrir: la consola no sabe de puertos.
        if [[ $ON_CONSOLE -eq 1 && $ALLOW_LOCKDOWN -eq 0 ]]; then
            info "$(ui "Desde la consola no puedo probar el puerto nuevo, así que lo dejo en $CURRENT_PORT. Hazlo por SSH desde tu computadora cuando entres: sudo bash secure-vps.sh --user ${USERNAME:-<tuusuario>} --port 2222" "From the console I cannot test the new port, so leaving it on $CURRENT_PORT. Do it over SSH from your computer once you are in: sudo bash secure-vps.sh --user ${USERNAME:-<youruser>} --port 2222")"
            return 0
        fi
        if ! confirm "$(ui "Recomendado: sacar SSH del puerto 22 (por ejemplo a 2222). El 22 se lleva todo el barrido automático de bots; cambiarlo no sustituye a la clave, pero limpia los logs y reduce bloqueos de fail2ban. ¿Lo cambiamos?" "Recommended: move SSH off port 22 (to 2222, for example). Port 22 absorbs all the automated bot scanning; changing it does not replace a key, but it keeps the logs clean and reduces fail2ban bans. Change it?")"; then
            info "$(ui "Omitiendo cambio de puerto: SSH sigue en $CURRENT_PORT y continuamos con el resto." "Skipping port change: SSH stays on $CURRENT_PORT and we carry on.")"
            return 0
        fi
        read -rp "$(ui "Nuevo puerto SSH [2222]: " "New SSH port [2222]: ")" NEW_PORT
        NEW_PORT="${NEW_PORT:-2222}"
    fi

    if ! is_port "$NEW_PORT"; then
        error "$(ui "Puerto inválido: '$NEW_PORT' (debe ser 1-65535)." "Invalid port: '$NEW_PORT' (must be 1-65535).")"
        return 1
    fi
    if [[ "$NEW_PORT" == "$CURRENT_PORT" ]]; then
        success "$(ui "SSH ya escucha en $NEW_PORT; nada que hacer." "SSH already listens on $NEW_PORT; nothing to do.")"
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

    echo
    warn "$(ui "Prueba en OTRA sesión, desde donde tengas tu clave privada (esta sesión sigue viva):" "Test in ANOTHER session, from wherever your private key is (this one stays alive):")"
    echo -e "   ${CYAN}ssh -p $NEW_PORT $USERNAME@$PUBLIC_IP${NC}"
    echo
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        if [[ $drop_old -eq 1 ]]; then
            finalize_old_port_removal || return 1
        else
            info "$(ui "Puerto $CURRENT_PORT sigue abierto: ciérralo tú cuando verifiques." "Port $CURRENT_PORT is still open: close it yourself once you verify.")"
        fi
    else
        local token=""
        read -rp "$(ui "Si entró por $NEW_PORT, escribe acceso-ok (otra cosa revierte): " "If you got in via $NEW_PORT, type acceso-ok (anything else reverts): ")" token
        if [[ "$token" == "acceso-ok" ]]; then
            finalize_old_port_removal || return 1
            disarm_rollback || return 1
        else
            revert_now "$(ui "Sin confirmación, vuelvo al puerto $CURRENT_PORT." "Without confirmation, back to port $CURRENT_PORT.")"
            return 1
        fi
    fi

    log "Fase 7 completada: puerto final=$(current_ssh_port)"
    pause
}

finalize_old_port_removal() {
    info "$(ui "Quitando el puerto $CURRENT_PORT..." "Removing port $CURRENT_PORT...")"
    hardening_set_ports "$NEW_PORT" || { revert_now "$(ui "No pude escribir el puerto definitivo." "Could not write the final port.")"; return 1; }
    if [[ $SOCKET_ACTIVATED -eq 1 ]] && ! has_socket_generator; then
        socket_dropin_write "$NEW_PORT" || { revert_now "No pude actualizar el socket."; return 1; }
    fi
    sshd -t || { revert_now "$(ui "sshd rechaza la config sin el puerto $CURRENT_PORT." "sshd rejects the configuration without port $CURRENT_PORT.")"; return 1; }
    if ! restart_ssh; then
        revert_now "$(ui "Falló el arranque de SSH en el puerto definitivo." "Starting SSH on the final port failed.")"
        return 1
    fi
    local now_listening
    now_listening=$(listening_ports) || return 1
    if [[ "$now_listening" != "$NEW_PORT " ]]; then
        revert_now "$(ui "Los listeners reales no coinciden con el puerto solicitado." "The real listeners do not match the requested port.")"
        return 1
    fi
    local alias=""
    [[ "$CURRENT_PORT" == 22 ]] && alias=ssh
    ufw_purge_port "$CURRENT_PORT" "$alias" || { revert_now "$(ui "No pude retirar la regla anterior." "Could not remove the previous rule.")"; return 1; }
    fail2ban_detect_logging
    if command -v fail2ban-client >/dev/null; then
        if ! write_fail2ban_jail "$NEW_PORT" || ! systemctl restart fail2ban; then
            revert_now "$(ui "No pude actualizar Fail2ban al puerto definitivo." "Could not update Fail2ban to the final port.")"
            return 1
        fi
    fi
    success "$(ui "SSH solo en $NEW_PORT (escucha:$now_listening)." "SSH on $NEW_PORT only (listening:$now_listening).")"
}

# ============================================================
# RESUMEN FINAL
# ============================================================
final_summary() {
    header "$(ui "RESUMEN DEL ESTADO" "STATE SUMMARY")"
    detect_ssh_activation
    local port eff permitroot passauth allowusers pending listening
    port=$(current_ssh_port)
    listening=$(listening_ports)
    eff=$(sshd -T 2>/dev/null || true)
    permitroot=$(printf '%s\n' "$eff"    | awk '/^permitrootlogin /{print $2}')
    passauth=$(printf '%s\n' "$eff"      | awk '/^passwordauthentication /{print $2}')
    allowusers=$(printf '%s\n' "$eff"    | awk '/^allowusers /{$1=""; sub(/^[[:space:]]+/,""); print}')
    pending=$(list_pending_rollbacks)

    if [[ "$permitroot" == "no" && "$passauth" == "no" ]]; then
        echo "  $(ui "Acceso cerrado: solo clave pública, solo usuarios listados." "Access locked: key only, listed users only.")"
    else
        echo "  ${YELLOW}$(ui "Acceso AÚN abierto:" "Access STILL open:")${NC} permitrootlogin=${permitroot:-?} passwordauthentication=${passauth:-?}"
    fi

    if guided_active; then
        echo
        if [[ "$permitroot" == "no" && "$passauth" == "no" ]]; then
            warn "$(ui "Respalda la clave privada de tu computadora AHORA: sin ella no hay acceso, y no se puede recuperar." "Back up the private key on your computer NOW: without it there is no access, and it cannot be recovered.")"
        else
            warn "$(ui "Tarea pendiente: todavía se entra con contraseña, porque desde aquí no se pudo probar una conexión nueva." "Pending task: a password still works, because a new connection could not be tested from here.")"
        fi
        echo "  $(ui "Cómo entrar mañana desde TU computadora:" "How to get in tomorrow from YOUR computer:")"
        echo -e "    ${CYAN}ssh -p ${port} ${USERNAME:-<tuusuario>}@${PUBLIC_IP}${NC}"
        echo "  $(ui "Si un día no puedes entrar:" "If one day you cannot get in:")"
        echo "    $(ui "1. Abre la consola web del proveedor (VNC/KVM): funciona con SSH cerrado." "1. Open the provider's web console (VNC/KVM): it works with SSH closed.")"
        echo "    $(ui "2. Entra con tu usuario y su contraseña de sistema, que no es la de SSH." "2. Log in with your user and its system password, which is not the SSH one.")"
        echo "    $(ui "3. Corre de nuevo este script y usa la opción de revertir al último snapshot." "3. Run this script again and use the revert-to-last-snapshot option.")"
        if [[ -n "${USERNAME:-}" ]] && [[ "$(password_state "$USERNAME")" != P ]]; then
            echo "  $(ui "Tu usuario aún no tiene contraseña de sistema: sin ella la consola del proveedor no te deja entrar. Ponla con" "Your user still has no system password: without it the provider console will not let you in. Set one with")"
            echo "    sudo passwd $USERNAME"
        fi
        echo "  $(ui "Si la cuenta atrás llegó a tiempo, todo volvió solo: es un resultado normal, no un fallo." "If the countdown fired, everything reverted by itself: that is a normal outcome, not a failure.")"
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
    echo "  🔥 $(ui "UFW:" "UFW:")"
    ufw status 2>/dev/null | grep -E "Status|^$port/tcp|ALLOW" | head -12 | sed 's/^/     /' || true
    echo
    echo "  🚫 $(ui "Fail2ban:" "Fail2ban:")"
    fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Total" | sed 's/^/     /' || true
    grep -E "^ignoreip" "$JAIL_LOCAL" 2>/dev/null | sed "s/^/     $(ui 'excluidos: ' 'excluded: ')/" || true
    echo
    echo "  🔄 $(ui "Actualizaciones automáticas:" "Automatic updates:")"
    systemctl is-active unattended-upgrades 2>/dev/null | sed 's/^/     /' || true
    reboot_hint
    echo
    echo "  ⏱  $(ui "Cuenta atrás pendiente: ${pending:-ninguna}" "Pending countdown: ${pending:-none}")"
    if [[ -n "$pending" ]]; then
        echo "     $(ui "Todavía no confirmaste el acceso: pruébalo desde otra terminal y cancela con:" "You have not confirmed access yet: test it from another terminal and cancel with:")"
        echo "       sudo systemctl stop $pending"
    fi
    local last
    last=$(last_snapshot)
    echo "  💾 $(ui "Snapshot más reciente: ${last:-ninguno}" "Latest snapshot: ${last:-none}")"
    echo "     $(ui "Backup del config principal: $BACKUP_FILE" "Main config backup: $BACKUP_FILE")"
    echo "  📋 $(ui "Log completo: $LOG_FILE" "Full log: $LOG_FILE")"
    echo
    echo "  🔗 $(ui "Conexión:" "Connect:")"
    if [[ -n "${USERNAME:-}" ]]; then
        echo "     ssh -p $port $USERNAME@$PUBLIC_IP"
    fi
    echo
    warn "$(ui "Guarda tu clave privada SSH en un lugar seguro." "Keep your private SSH key somewhere safe.")"
    warn "$(ui "Ten siempre a mano la consola VNC de tu proveedor." "Always keep your provider VNC console at hand.")"
    echo
    success "$(ui "Resumen terminado." "Summary finished.")"
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
    last=$(last_snapshot)
    if [[ -z "$last" ]]; then
        warn "$(ui "No hay snapshots en $SNAPSHOTS_DIR." "There are no snapshots in $SNAPSHOTS_DIR.")"
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

run_all_fases() {
    local step
    for step in fase_1_user fase_2_ssh_key fase_2b_updates fase_3_harden_ssh fase_4_ufw \
                fase_5_fail2ban fase_6_auto_updates; do
        if ! "$step"; then
            error "$(ui "El proceso se detuvo en $step." "The process stopped at $step.")"
            return 1
        fi
    done
    # La fase 7 se llama siempre: sin --port decide sola (pregunta en modo
    # interactivo; en desatendido u --yes se omite desde su propio guard).
    if ! fase_7_change_port; then
        error "$(ui "El proceso se detuvo en fase_7_change_port." "The process stopped at fase_7_change_port.")"
        return 1
    fi
    return 0
}

main_menu() {
    local option
    while true; do
        clear 2>/dev/null || true
        header "$(ui "SECURE-VPS v$SCRIPT_VERSION - MENÚ" "SECURE-VPS v$SCRIPT_VERSION - MENU")"
        cat <<EOF
  $(ui "IP pública:" "Public IP:")   ${PUBLIC_IP}
  $(ui "Usuario:" "User:")      ${USERNAME:-$(ui "<sin definir>" "<undefined>")}
  $(ui "Puerto SSH:" "SSH port:")   ${CURRENT_PORT}  $( [[ $SOCKET_ACTIVATED -eq 1 ]] && echo '(ssh.socket)' || echo '(ssh.service)' )
  $(ui "Snapshots:" "Snapshots:")    $(find "$SNAPSHOTS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')  $(ui "Cuenta atrás:" "Countdown:") $( [[ -n "$(list_pending_rollbacks)" ]] && echo "$(ui 'PENDIENTE' 'PENDING')" || echo "$(ui 'ninguna' 'none')" )

  1) $(ui "Ejecutar TODAS las fases (recomendado)" "Run ALL phases (recommended)")
  2) $(ui "Fase 1: Crear usuario con sudo utilizable" "Phase 1: Create a user with working sudo")
  3) $(ui "Fase 2: Clave SSH (validada)" "Phase 2: SSH key (validated)")
  4) $(ui "Fase 3: Endurecer SSH + prueba de acceso" "Phase 3: Harden SSH + access test")
  5) $(ui "Fase 4: Activar UFW" "Phase 4: Enable UFW")
  6) $(ui "Fase 5: Instalar Fail2ban" "Phase 5: Install Fail2ban")
  7) $(ui "Fase 6: Actualizaciones automáticas" "Phase 6: Automatic updates")
  8) $(ui "Fase 7: Cambiar puerto SSH" "Phase 7: Change the SSH port")
  9) $(ui "Ver resumen del estado actual" "Show the current state summary")
 10) $(ui "Cancelar cuenta atrás pendiente" "Cancel a pending countdown")
 11) $(ui "Revertir al último snapshot" "Revert to the latest snapshot")
  0) $(ui "Salir" "Exit")
EOF
        echo
        read -rp "$(ui "Elige una opción: " "Choose an option: ")" option

        case "$option" in
            1)
                if ! fase_0_welcome; then continue; fi
                if ! run_all_fases; then
                    error "$(ui "Proceso incompleto; la cuenta atrás pendiente revierte sola si no la cancelas." "Process incomplete; the pending countdown reverts on its own unless you cancel it.")"
                fi
                final_summary
                pause
                ;;
            2) fase_1_user || pause ;;
            3) fase_2_ssh_key || pause ;;
            4) fase_3_harden_ssh || pause ;;
            5) fase_4_ufw || pause ;;
            6) fase_5_fail2ban || pause ;;
            7) fase_6_auto_updates || pause ;;
            8) fase_7_change_port || pause ;;
            9) final_summary; pause ;;
            10) cancel_all_rollbacks; pause ;;
            11) restore_last_snapshot; pause ;;
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
        error "$(ui "Sales con la cuenta atrás ARMADA ($ROLLBACK_JOB.service)." "You are leaving with the countdown ARMED ($ROLLBACK_JOB.service).")"
        error "$(ui "Si nadie la cancela, en ${ROLLBACK_MINUTES}m SSH/UFW/fail2ban vuelven atrás." "If nobody cancels it, in ${ROLLBACK_MINUTES}m SSH/UFW/fail2ban revert.")"
        error "$(ui "Ya compruebas el acceso y la cancelas con:" "Confirm access, then cancel it with:")"
        echo "    sudo systemctl stop $ROLLBACK_JOB.timer"
    fi
    return $rc
}

main() {
    export LC_ALL=C
    umask 077
    parse_args "$@"
    check_os || exit 1
    require_root
    check_dependencies || exit 1
    check_original_user
    detect_session_kind
    resolve_guided_mode
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
    else
        main_menu
    fi
}

main "$@"