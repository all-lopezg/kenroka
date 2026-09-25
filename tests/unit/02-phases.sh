#!/usr/bin/env bash
# Unit 02: lógica de las fases que no necesita un sistema real (puertos, jail
# de fail2ban, config efectiva de sshd, permisos, snapshots de IPs).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

error()   { printf '    [error] %s\n' "$*" >&2; }
info()    { :; }
warn()    { printf '    [warn] %s\n' "$*"; }
success() { :; }
log()     { :; }

SCRIPT_VERSION="test"
HARDENING_FILE="$WORK/99-hardening.conf"
JAIL_LOCAL="$WORK/jail.local"
LOG_FILE="$WORK/out.log"
PUBLIC_IP="203.0.113.9"
CURRENT_PORT=22
NEW_PORT=2222
USERNAME="tester"
LOCKDOWN=1
SOCKET_ACTIVATED=1
FAIL2BAN_BACKEND="systemd"
FAIL2BAN_LOGPATH=""
ADMIN_IPS="198.51.100.7"

extract_fns hardening_set_ports write_fail2ban_jail \
            listening_ports current_ssh_port verify_effective_access user_home \
            validate_pubkey warn_listening_services existing_key_present \
            detect_admin_ips resolve_pubkey _pubkey_normalize lockdown_possible \
            _file_mode _file_owner world_or_group_writable \
            password_state write_hardening_file valid_username ui current_admin_ips \
            guided_active resolve_guided_mode detect_session_kind valid_ip_or_cidr \
            apt_pending_counts report_pending_updates reboot_hint fase_2b_updates \
            other_human_users check_original_user \
            collect_key_candidates print_key_candidates pick_key_candidate

ensure_sshd_runtime() { :; }
NON_INTERACTIVE=0
ASSUME_YES=0
GUIDED_MODE=auto
GUIDED=0
ON_CONSOLE=0
SSH_PUBKEY=""
PUBKEY_FILE=""

echo "== hardening_set_ports"
printf 'MaxAuthTries 3\nPort 22\nX11Forwarding no\nPort 2222\n' > "$HARDENING_FILE"
silence hardening_set_ports 2222
out="$(cat "$HARDENING_FILE")"
check "deja un solo Port" "2222" "$(printf '%s\n' "$out" | awk '/^Port /{print $2}' | paste -sd' ' -)"
has "conserva las demás líneas" "MaxAuthTries 3" "$out"
silence hardening_set_ports 22 2222
check "permite dos puertos en transición" "22 2222" "$(grep '^Port' "$HARDENING_FILE" | awk '{print $2}' | paste -sd' ' -)"

for ports in "2222" "22 2222"; do
    hardening_set_ports $ports
    silence write_hardening_file
    check "reescribir conserva Port $ports" "$ports" "$(awk '/^Port /{print $2}' "$HARDENING_FILE" | paste -sd' ' -)"
    hasnt "no concatena Port y su valor" "Port2222" "$(cat "$HARDENING_FILE")"
done

echo "== write_fail2ban_jail"
write_fail2ban_jail 2222 > /dev/null 2>&1
j="$(cat "$JAIL_LOCAL")"
has "excluye la IP del administrador conectado" "ignoreip = 127.0.0.1/8 ::1 $ADMIN_IPS" "$j"
has "jail en el puerto nuevo" "port     = 2222" "$j"
has "backend systemd" "backend  = systemd" "$j"
hasnt "sin logpath cuando el backend es systemd" "logpath" "$j"
write_fail2ban_jail 22 2222 > /dev/null 2>&1
has "cubre los dos puertos en transición" "port     = 22,2222" "$(cat "$JAIL_LOCAL")"
write_fail2ban_jail > /dev/null 2>&1
has "sin argumentos no deja el port vacío" "port     = 22" "$(cat "$JAIL_LOCAL")"
FAIL2BAN_BACKEND="auto"; FAIL2BAN_LOGPATH="/var/log/auth.log"
write_fail2ban_jail 22 > /dev/null 2>&1
has "logpath solo con backend auto" "logpath  = /var/log/auth.log" "$(cat "$JAIL_LOCAL")"
FAIL2BAN_BACKEND="systemd"; FAIL2BAN_LOGPATH=""

echo "== current_ssh_port con ssh.socket (Ubuntu 24.04)"
# El bug original: leer Port de sshd_config cuando quien manda es el socket.
ss() {
    printf '%s\n' 'LISTEN 0 128 0.0.0.0:22 *:* users:(("sshd",pid=100,fd=3))' \
        'LISTEN 0 128 [::]:22 *:* users:(("sshd",pid=100,fd=4))' \
        'LISTEN 0 128 0.0.0.0:2222 *:* users:(("sshd",pid=100,fd=5))' \
        'LISTEN 0 128 127.0.0.11:43210 *:* users:(("dns",pid=101,fd=3))'
}
check "listening_ports dedupea v4/v6 y excluye otros servicios" "22 2222" "$(listening_ports | xargs)"
lp="$(listening_ports)"
case "$lp" in
    *" ") ok "el resultado lleva espacio final (la fase 7 compara contra \"\$NEW_PORT \")" ;;
    *)    bad "falta el espacio final: la fase 7 lo daría por no escuchando (real='$lp')" ;;
esac
ss() { :; }

echo "== resistencia cuando sshd está caído (pipefail + set -e)"
# Sin listeners, grep no encuentra nada y devuelve 1. Con `set -euo pipefail`
# eso mataba al script justo en el momento en que había que diagnosticar.
systemctl() { return 0; }
out="$( set -euo pipefail
        SOCKET_ACTIVATED=1
        printf 'ok:%s' "$(current_ssh_port)" )"
check "current_ssh_port cae a 22 en vez de abortar" "ok:22" "$out"
out="$( set -euo pipefail
        SOCKET_ACTIVATED=1
        lp="$(listening_ports)"
        printf 'ok:%s' "${lp:-vacio}" )"
check "listening_ports devuelve vacío sin abortar" "ok:vacio" "$out"
unset -f systemctl

echo "== verify_effective_access (antes de reiniciar sshd)"
sshd() {
    printf '%s\n' "pubkeyauthentication yes" "allowusers intruso" "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"
}
silence verify_effective_access
check "AllowUsers sin nuestro usuario => no cierra" 1 $?
sshd() { printf '%s\n' "pubkeyauthentication yes" "allowusers root $USERNAME" "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; }
silence verify_effective_access
check "AllowUsers nos incluye => puede cerrar" 0 $?
sshd() { printf '%s\n' "pubkeyauthentication no" "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; }
silence verify_effective_access
check "pubkey apagado => no cierra" 1 $?
sshd() { printf '%s\n' "pubkeyauthentication yes" "passwordauthentication yes"; }
LOCKDOWN=1; silence verify_effective_access; check "lockdown con PassAuth=yes => no cierra" 1 $?
LOCKDOWN=0; silence verify_effective_access; check "modo suave tolera PassAuth=yes" 0 $?
LOCKDOWN=1
unset -f sshd

echo "== warn_listening_services antes de ufw enable"
# Stub de ss consciente del protocolo: -Htln devuelve TCP y -Huln UDP.
ss()    {
    case "${1:-}" in
        *t*) printf '%s\n' 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*' 'LISTEN 0 128 0.0.0.0:80 0.0.0.0:*' 'LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*' ;;
        *u*) printf '%s\n' 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:*' 'UNCONN 0 0 127.0.0.53:53 0.0.0.0:*' ;;
    esac
}
ufw()   { [[ "${1:-}" == "status" ]] && printf '%s\n' '[ 1] 2222/tcp  ALLOW IN  Anywhere' '[ 2] 80/tcp  ALLOW IN  Anywhere'; }
confirm() { return 1; }
CURRENT_PORT=2222
out="$(warn_listening_services 2>&1)"
has "avisa de 3306 sin regla" "3306" "$out"
has "da el comando exacto para abrirlo" "sudo ufw allow 3306/tcp" "$out"
hasnt "no ofrece abrir un puerto ya permitido" "sudo ufw allow 80/tcp" "$out"
hasnt "no incluye 2222 (es el puerto ssh)" "estos puertos: 2222" "$out"
has "avisa del 53/udp sin regla" "sudo ufw allow 53/udp" "$out"
hasnt "el 53/udp no entra en la lista tcp" "sudo ufw allow 53/tcp" "$out"
check "el 53 se avisa una sola vez: el 127.0.0.53 (loopback) queda fuera" "1" \
    "$(printf '%s' "$out" | grep -c 'allow 53/udp')"
unset -f ss ufw confirm
CURRENT_PORT=22

echo "== detect_admin_ips"
warn() { printf 'W: %s\n' "$*"; }
who() { printf '%s\n' \
    'tester pts/0 2026-09-24 12:00 (198.51.100.7)' \
    'root   pts/1 2026-09-24 12:05 (203.0.113.9)' \
    'allan  pts/2 2026-09-24 12:07 (localhost)'; }
ADMIN_IPS=""
detect_admin_ips > /dev/null 2>&1
check "toma las IPs de las sesiones SSH abiertas" "198.51.100.7 203.0.113.9" "$ADMIN_IPS"
who() { :; }
GUIDED_MODE=off
out="$(detect_admin_ips 2>&1)"
has "avisa si no ve ninguna sesión (ignoreip vacío)" "No detecté sesiones SSH" "$out"
hasnt "sin guía no intenta preguntar la IP" "Escribe la IP" "$out"
GUIDED_MODE=auto

echo "== other_human_users (de aquí sale el 'solo existe root')"
printf '%s\n' \
    'root:x:0:0:root:/root:/bin/bash' \
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' \
    'lxd:x:999:999::/var/snap/lxd/common/lxd:/bin/false' \
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin' \
    'ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash' > "$WORK/passwd_con_ubuntu"
check "ve al usuario del proveedor como humano" "ubuntu" "$(other_human_users "$WORK/passwd_con_ubuntu")"
printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' \
              'systemd-network:x:100:101::/run/systemd:/usr/sbin/nologin' > "$WORK/passwd_solo_root"
check "con solo root no devuelve nadie" "" "$(other_human_users "$WORK/passwd_solo_root")"
check "un archivo ilegible no aborta" "" "$(other_human_users "$WORK/no-existe")"

echo "== check_original_user con root y sin otro usuario"
# Se sustituye el detector para no depender del /etc/passwd del host, y se corre
# en subshell porque la función usa exit.
logname() { printf 'root\n'; }
SUDO_USER=""
info()  { printf 'I: %s\n' "$*"; }
success() { printf 'S: %s\n' "$*"; }
warn()    { printf 'W: %s\n' "$*"; }
error()   { printf 'E: %s\n' "$*" >&2; }
# confirm corre dentro del subshell de la captura: la pregunta se pasa por archivo.
confirm() { printf "%s" "$1" > "$WORK/confirm.txt"; return "${CONFIRM_RC:-0}"; }
other_human_users() { printf '%s\n' "$OTHERS"; }

NON_INTERACTIVE=0; USERNAME=""; OTHERS=""
out="$(check_original_user 2>&1)"; rc=$?
check "sale con 0 si el operador acepta crear el usuario" "0" "$rc"
has "dice en claro que solo existe root" "solo existe root" "$out"
has "explica que la fase 1 crea el usuario" "La fase 1 crea un usuario administrador" "$out"
has "explica que no se cierra hasta probar otra sesión" "No se cierra root ni la contraseña" "$out"
has "y pregunta si lo crea ahora" "¿Creo ahora un usuario administrador" "$(cat "$WORK/confirm.txt")"

CONFIRM_RC=1
out="$(check_original_user 2>&1)"; rc=$?
check "un 'no' detiene la corrida con 0" "0" "$rc"
has "y dice que no toca nada" "no toco nada" "$out"
CONFIRM_RC=0

OTHERS="ubuntu"
out="$(check_original_user 2>&1)"
has "si hay otro usuario, lo nombra" "otros usuarios con acceso interactivo: ubuntu" "$out"
hasnt "y no ofrece crear uno desde cero" "solo existe root" "$out"

NON_INTERACTIVE=1; OPT_SKIP_LOCKDOWN=0; OTHERS=""
out="$(check_original_user 2>&1)"; rc=$?
check "desatendido sin --skip-lockdown se niega" "1" "$rc"
has "manteniendo el motivo de siempre" "Root directo en modo no interactivo" "$out"
OPT_SKIP_LOCKDOWN=1
out="$(check_original_user 2>&1)"; check "desatendido con --skip-lockdown sigue" "0" "$?"
has "diciendo por qué es aceptable" "aceptado porque --skip-lockdown" "$out"
unset -f logname confirm other_human_users
OTHERS=""; CONFIRM_RC=0; NON_INTERACTIVE=0; OPT_SKIP_LOCKDOWN=0; USERNAME="tester"

echo "== valid_ip_or_cidr (lo que el operador teclea va a ignoreip)"
for v in "198.51.100.7" "10.0.0.1/24" "2001:db8::1" "2001:db8::/32" "::1" "::1/128"; do
    silence valid_ip_or_cidr "$v"; check "'$v' es una IP válida" 0 $?
done
for v in "" "hola" "999.1.1.1 ; rm -rf /" "1.2.3.4 && echo x" ":::1" "::::" \
         "2001:db8::1::2" "fe80::1%eth0" "1.2.3.4/999" "1.2.3.4/33" \
         "2001:db8::/129" "1.2.3.4,5.6.7.8"; do
    silence valid_ip_or_cidr "$v"; check "'$v' se rechaza" 1 $?
done

echo "== detect_session_kind"
SSH_CONNECTION="" SSH_CLIENT=""
detect_session_kind; check "sin SSH y sin sesiones => consola del proveedor" 1 $ON_CONSOLE
who() { printf '%s\n' 'u pts/0 2026-09-24 12:00 (198.51.100.7)'; }
detect_session_kind; check "una sesión SSH abierta => no es consola" 0 $ON_CONSOLE
who() { :; }
SSH_CONNECTION="198.51.100.7 55123 10.0.0.2 22"
detect_session_kind; check "SSH_CONNECTION alcanza para saber que es SSH" 0 $ON_CONSOLE
SSH_CONNECTION=""

echo "== resolve_guided_mode"
ON_CONSOLE=0; SSH_PUBKEY="ssh-ed25519 AAAA x"; PUBKEY_FILE=""
resolve_guided_mode; check "auto: la clave llegó por --pubkey => sin guía" 0 $GUIDED
SSH_PUBKEY=""; PUBKEY_FILE="/tmp/clave.pub"
resolve_guided_mode; check "auto: la clave llegó por --pubkey-file => sin guía" 0 $GUIDED
PUBKEY_FILE=""
resolve_guided_mode; check "auto: sin clave por flag => guía activa" 1 $GUIDED
SSH_PUBKEY="ssh-ed25519 AAAA x"; ON_CONSOLE=1
resolve_guided_mode; check "auto: en consola => guía activa" 1 $GUIDED
ON_CONSOLE=0; GUIDED_MODE=on
resolve_guided_mode; check "--novato fuerza la guía con clave en mano" 1 $GUIDED
GUIDED_MODE=off; ON_CONSOLE=1
resolve_guided_mode; check "--experto apaga la guía hasta en consola" 0 $GUIDED
GUIDED_MODE=auto; ON_CONSOLE=1
resolve_guided_mode
# Regresión: la fase 2 rellena SSH_PUBKEY al elegir una clave autorizada. Si la
# guía se volviera a decidir tarde, desapareceria justo para el novato.
SSH_PUBKEY="ssh-ed25519 AAAA reutilizada"
silence guided_active; check "la guía ya resuelta no se revierte al instalar la clave" 0 $?
ON_CONSOLE=0; GUIDED_MODE=auto; SSH_PUBKEY=""; PUBKEY_FILE=""
resolve_guided_mode
silence guided_active; check "guided_active coincide con lo resuelto" 0 $?

echo "== candidatos de clave reutilizable"
STATE_DIR="$WORK/state"; mkdir -p "$STATE_DIR"
CANDIDATE_KEYS_FILE="$STATE_DIR/candidate_keys.tsv"
printf '%s\n' \
    '1	ssh-ed25519 AAAAC3NzlaLb11NE5vJd vendor@hetzner	/root/.ssh/authorized_keys	256 SHA256:AAA (ED25519)' \
    '2	ssh-rsa AAAAB3NzaC1yc2E otra@laptop	/home/ubuntu/.ssh/authorized_keys	3072 SHA256:BBB (RSA)' \
    > "$CANDIDATE_KEYS_FILE"
c="$(pick_key_candidate 2)"
has "pick_key_candidate devuelve la clave elegida" "otra@laptop" "$c"
check "un número inexistente no devuelve nada" "" "$(pick_key_candidate 9)"
lst="$(print_key_candidates)"
has "la lista muestra la huella" "SHA256:AAA" "$lst"
has "y el archivo de donde salió" "/root/.ssh/authorized_keys" "$lst"
hasnt "no imprime la clave pública cruda" "AAAAC3NzlaLb11NE5vJd" "$lst"

echo "== existing_key_present / lockdown_possible"
user_home() { printf '%s\n' "$WORK/home"; }
mkdir -p "$WORK/home/.ssh"
: > "$WORK/home/.ssh/authorized_keys"
silence existing_key_present tester; check "authorized_keys vacío => no hay clave" 1 $?
if [[ -f "$WORK/id_ed25519.pub" ]]; then
    cat "$WORK/id_ed25519.pub" > "$WORK/home/.ssh/authorized_keys"
    silence existing_key_present tester; check "clave válida instalada => la reconoce" 0 $?
fi
printf 'no-es-una-clave\n' > "$WORK/home/.ssh/authorized_keys"
silence existing_key_present tester; check "authorized_keys con basura => no cuenta" 1 $?
rm -f "$WORK/home/.ssh/authorized_keys"
silence existing_key_present tester; check "sin authorized_keys => no hay clave" 1 $?

id() { if [[ "${2:-$1}" == tester ]]; then printf '1001\n'; else return 1; fi; }
silence lockdown_possible; check "con usuario existente puede cerrar" 0 $?
USERNAME="ausente"
silence lockdown_possible; check "usuario inexistente no puede cerrar" 1 $?
USERNAME=""
silence lockdown_possible; check "sin usuario se niega (AllowUsers vacío encierra a todos)" 1 $?
USERNAME="root"
silence lockdown_possible; check "root como AllowUsers se niega" 1 $?
USERNAME="tester"

echo "== fase_2b_updates: decidir sin tocar el sistema"
info()    { printf 'I: %s\n' "$*"; }
success() { printf 'S: %s\n' "$*"; }
warn()    { printf 'W: %s\n' "$*"; }
error()   { printf 'E: %s\n' "$*" >&2; }
header()  { printf '\n-- %s\n' "$*"; }
pause()   { :; }
log()     { :; }

APT_SIM='Inst libaaa [1.0] (1.1 Ubuntu/noble [amd64])
Inst libbbb [1.0] (1.1 Ubuntu/noble-security [amd64])
Inst libccc [2.0] (2.1 Ubuntu/noble [amd64])'
UPGRADED="$WORK/upgraded.flag"
APT_UPDATE_OK=1
apt-get() {
    case "$*" in
        *update*) [[ $APT_UPDATE_OK -eq 1 ]] || return 1 ;;
        *-s*upgrade*) printf '%s\n' "$APT_SIM" ;;
        *upgrade*) : > "$UPGRADED" ;;
    esac
    return 0
}
apt_pending_counts
check "cuenta los paquetes actualizables" "3" "$PENDING_COUNT"
check "separa los que vienen de security" "1" "$PENDING_SECURITY"

out="$(report_pending_updates 2>&1)"
has "el reporte dice cuántos faltan" "3 paquetes actualizables (1 de seguridad)" "$out"
APT_UPDATE_OK=0
out="$(report_pending_updates 2>&1)"
has "si apt update falla, avisa y no aborta" "No pude refrescar" "$out"
APT_UPDATE_OK=1

rm -f "$UPGRADED"
UPGRADE_MODE=no
out="$(fase_2b_updates 2>&1)"; check "--no-upgrade sale con 0" "0" "$?"
has "--no-upgrade no aplica nada" "--no-upgrade: dejo las pendientes" "$out"
check "--no-upgrade no llamó a apt upgrade" "0" "$([[ -e $UPGRADED ]] && echo 1 || echo 0)"

UPGRADE_MODE=ask; NON_INTERACTIVE=1; rm -f "$UPGRADED"
out="$(fase_2b_updates 2>&1)"; check "desatendido sale con 0" "0" "$?"
has "desatendido no actualiza por su cuenta" "Modo desatendido" "$out"
check "desatendido no llamó a apt upgrade" "0" "$([[ -e $UPGRADED ]] && echo 1 || echo 0)"
NON_INTERACTIVE=0

confirm() { return 1; }
UPGRADE_MODE=ask; rm -f "$UPGRADED"
out="$(fase_2b_updates 2>&1)"
has "un 'no' del operador deja las pendientes" "Los dejas pendientes" "$out"
check "y tampoco ejecuta el upgrade" "0" "$([[ -e $UPGRADED ]] && echo 1 || echo 0)"

confirm() { return 0; }
UPGRADE_MODE=yes; rm -f "$UPGRADED"
out="$(fase_2b_updates 2>&1)"; check "--upgrade sale con 0" "0" "$?"
has "con --upgrade informa que aplica" "Actualizaciones aplicadas" "$out"
check "y de verdad llamó a apt upgrade" "1" "$([[ -e $UPGRADED ]] && echo 1 || echo 0)"

apt-get() {
    case "$*" in
        *upgrade*) [[ "$*" == *-s* ]] && printf '%s\n' "$APT_SIM"; return 1 ;;
    esac
    return 0
}
out="$(fase_2b_updates 2>&1)"; check "un upgrade roto detiene la fase" "1" "$?"
has "y dice que para ANTES de tocar el acceso" "ANTES de tocar el acceso" "$out"
unset -f apt-get

summary
