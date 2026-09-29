#!/usr/bin/env bash
# Verificación: resultado efectivo, reporte y confirmación humana independiente.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
extract_fns ui valid_username world_or_group_writable audit_eff_val \
    audit_eff_rest audit_session_ip verification_item verification_expect \
    verification_port_contains verification_key_ok verification_ssh \
    verification_user verification_firewall verification_fail2ban \
    verification_updates verification_rollbacks verification_collect \
    verification_result ssh_test_command show_access_test_steps ask_access_result \
    verification_run offer_final_verification
info() { :; }
warn() { :; }
success() { :; }
error() { printf '%s\n' "$*" >&2; }
reset_fixture() {
    USERNAME=tester; SUDO_MODE=nopasswd; NEW_PORT=2222; SCRIPT_VERSION=test
    STATE_DIR="$WORK/state"; SNAPSHOTS_DIR="$WORK/snaps"; REBOOT_FLAG="$WORK/reboot"
    VERIFY_EXTERNAL=unconfirmed; VERIFY_FAILURES=0; VERIFY_PENDING=0
    NON_INTERACTIVE=0; ASSUME_YES=0; PUBLIC_IP=203.0.113.9
    BOLD=''; CYAN=''; NC=''
    SOCKET_ACTIVATED=0; SSH_CONNECTION='198.51.100.7 45000 203.0.113.9 2222'
    INACTIVE_SERVICE=''; DISABLED_SERVICE=''; KEY_VALID=1; KEY_MODE=600; KEY_OWNER=tester
    SUDO_RC=0; SUDO_LIST_RC=0; PASS_STATE=P; SSH_SYNTAX_RC=0; ROOT_POLICY=no
    PASSWORD_POLICY=no; ALLOW_USER=tester; DENY_USERS=''; SSH_PORTS='2222 '
    F2B_PORTS=2222; F2B_PROTOCOL=tcp; F2B_RC=0; UFW_ACTIVE=1; UFW_RULE_PORT=2222; UFW_DEFAULT=deny
    UPDATE_ENABLED=1; TIMER_PENDING=''; TIMER_QUERY_RC=0; CHANGE_AFTER_CONFIRM=0
    rm -rf "$SNAPSHOTS_DIR" "$REBOOT_FLAG"
}
id() { [[ "$*" == '-u tester' ]] && { echo 1001; return; }; [[ "$*" == tester ]]; }
user_home() { printf '%s\n' "$WORK/home"; }
existing_key_present() { [[ "$KEY_VALID" == 1 ]]; }
_file_mode() { case "$1" in *authorized_keys) echo "$KEY_MODE";; *) echo 700;; esac; }
_file_owner() { echo "$KEY_OWNER"; }
password_state() { echo "$PASS_STATE"; }
visudo() { :; }
sudo() { return "$SUDO_LIST_RC"; }
runuser() { return "$SUDO_RC"; }
detect_ssh_activation() { SOCKET_ACTIVATED=0; }
listening_ports() { printf '%s' "$SSH_PORTS"; }
current_ssh_port() { echo 2222; }
pgrep() { :; }
systemctl() {
    local unit="${@: -1}"
    case "$1" in
        is-active) [[ "$unit" != "$INACTIVE_SERVICE" ]] || return 3; [[ "$*" == *--quiet* ]] || echo active ;;
        is-enabled) [[ "$unit" != "$DISABLED_SERVICE" ]] || return 1; [[ "$*" == *--quiet* ]] || echo enabled ;;
        *) return 1 ;;
    esac
    return 0
}
sshd() {
    if [[ "$1" == -t ]]; then return "$SSH_SYNTAX_RC"; fi
    if [[ "$*" == *user=root,* ]]; then printf 'permitrootlogin %s\n' "$ROOT_POLICY"; return; fi
    printf '%s\n' "passwordauthentication $PASSWORD_POLICY" 'kbdinteractiveauthentication no' \
        'permitemptypasswords no' 'x11forwarding no' 'pubkeyauthentication yes' \
        "allowusers $ALLOW_USER" 'maxauthtries 3' 'maxsessions 2' 'logingracetime 30' \
        'clientaliveinterval 300' 'clientalivecountmax 2' 'authenticationmethods any' \
        'authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2' "denyusers $DENY_USERS"
}
has_ufw() { :; }
ufw() {
    [[ "$UFW_ACTIVE" == 1 ]] || { echo 'Status: inactive'; return; }
    if [[ "$*" == 'status verbose' ]]; then
        printf 'Status: active\nDefault: %s (incoming), allow (outgoing)\n' "$UFW_DEFAULT"
    else
        printf 'Status: active\n[ 1] %s/tcp LIMIT IN Anywhere\n' "$UFW_RULE_PORT"
    fi
}
has_fail2ban() { :; }
timeout() { shift; "$@"; }
fail2ban-client() {
    [[ "$F2B_RC" == 0 ]] || return 1
    case "$*" in
        'status sshd') echo 'Status for the jail: sshd' ;;
        'get sshd actions') printf 'The jail sshd has the following actions:\niptables-multiport\n' ;;
        'get sshd action iptables-multiport port') echo "$F2B_PORTS" ;;
        'get sshd action iptables-multiport protocol') echo "$F2B_PROTOCOL" ;;
        *) return 1 ;;
    esac
}
apt-config() {
    printf 'APT::Periodic::Update-Package-Lists "%s";\nAPT::Periodic::Unattended-Upgrade "%s";\n' "$UPDATE_ENABLED" "$UPDATE_ENABLED"
}
list_pending_rollbacks() { printf '%s' "$TIMER_PENDING"; return "$TIMER_QUERY_RC"; }
date() { if [[ "$1" == -Is ]]; then echo '2026-09-28T12:00:00-03:00'; else command date "$@"; fi; }
hostname() { echo fixture-host; }

reset_fixture
echo '== criterios de resultado'
verification_collect > "$WORK/collected"
check 'el perfil completo no tiene fallos técnicos' 0 "$VERIFY_FAILURES"
check 'el puerto 2222 cubierto por jail/reglas no tiene pendientes' 0 "$VERIFY_PENDING"
verification_result; rc=$?
check 'sin confirmación humana sigue pendiente' 2 "$rc"
VERIFY_EXTERNAL=confirmed
verification_result; rc=$?
check 'técnica y confirmación aprobadas dan éxito' 0 "$rc"
UI_LANG=en
verification_result
check 'traduce el resultado a inglés' SUCCESSFUL "$VERIFY_STATUS"
UI_LANG=es

echo '== estado efectivo y contexto SSH'
ROOT_POLICY=yes
verification_collect > "$WORK/collected"
[[ "$VERIFY_PENDING" -gt 0 ]] && ok 'Match root que permite acceso queda pendiente' || bad 'no vio root permitido'
has 'registra política efectiva de root' 'PermitRootLogin: yes' "$(cat "$WORK/collected")"
reset_fixture
PASSWORD_POLICY=yes
verification_collect > "$WORK/collected"
[[ "$VERIFY_PENDING" -gt 0 ]] && ok 'contraseña habilitada nunca da éxito' || bad 'no vio contraseña abierta'
reset_fixture
DENY_USERS=tester
verification_collect > "$WORK/collected"
has 'no ignora restricciones adicionales de acceso' 'denyusers' "$(cat "$WORK/collected")"
reset_fixture
SSH_SYNTAX_RC=1
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'configuración SSH inválida es fallo' || bad 'sshd inválido aprobado'
reset_fixture
SSH_PORTS='22 2222 '
verification_collect > "$WORK/collected"
has 'detecta puerto anterior aún abierto si se pidió uno definitivo' 'Puerto esperado' "$(cat "$WORK/collected")"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'listener extra solicitado es fallo' || bad 'no detectó listener extra'
reset_fixture
unset SSH_CONNECTION
verification_collect > "$WORK/collected"
has 'sin sesión usa un contexto explícito sin consultar internet' 'addr=127.0.0.1' "$(cat "$WORK/collected")"

echo '== claves, sudo y servicios'
reset_fixture
KEY_OWNER=other
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'propietario incorrecto de clave es fallo' || bad 'owner incorrecto aprobado'
reset_fixture
KEY_MODE=666
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'clave escribible por otros es fallo' || bad 'clave 666 aprobada'
reset_fixture
SUDO_MODE=prompt
verification_collect > "$WORK/collected"
has 'no anuncia contraseña cuando sudo sigue NOPASSWD' 'Se eligió contraseña' "$(cat "$WORK/collected")"
reset_fixture
SUDO_LIST_RC=1
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'sudo denegado es fallo' || bad 'sudo denegado aprobado'
reset_fixture
F2B_PORTS=22
verification_collect > "$WORK/collected"
has 'un jail activo en puerto equivocado no queda aprobado' 'No pude verificar que una acción activa cubra' "$(cat "$WORK/collected")"
reset_fixture
F2B_PROTOCOL=udp
verification_collect > "$WORK/collected"
[[ "$VERIFY_PENDING" -gt 0 ]] && ok 'una acción UDP no protege SSH TCP' || bad 'acción UDP aprobada para SSH'
reset_fixture
UFW_RULE_PORT=22
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'UFW sin regla del puerto definitivo es fallo' || bad 'puerto incorrecto aprobado'
reset_fixture
UFW_DEFAULT=allow
verification_collect > "$WORK/collected"
has 'entrada por defecto permisiva queda pendiente' 'no es restrictiva' "$(cat "$WORK/collected")"
reset_fixture
UPDATE_ENABLED=0
verification_collect > "$WORK/collected"
has 'consulta APT efectivo y detecta automatización deshabilitada' 'no están habilitadas' "$(cat "$WORK/collected")"
reset_fixture
DISABLED_SERVICE=apt-daily-upgrade.timer
verification_collect > "$WORK/collected"
[[ "$VERIFY_PENDING" -gt 0 ]] && ok 'timer de actualizaciones deshabilitado queda pendiente' || bad 'timer no programado aprobado'
reset_fixture
TIMER_PENDING=secure-vps-rollback-test.timer
verification_collect > "$WORK/collected"
has 'una cuenta atrás pendiente impide el éxito' 'Cuenta atrás pendiente' "$(cat "$WORK/collected")"
reset_fixture
mkdir -p "$SNAPSHOTS_DIR/failed"
touch "$SNAPSHOTS_DIR/failed/ROLLBACK_FAILED"
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'rollback fallido es fallo global' || bad 'rollback fallido aprobado'
reset_fixture
TIMER_QUERY_RC=1
verification_collect > "$WORK/collected"
[[ "$VERIFY_FAILURES" -gt 0 ]] && ok 'no confunde consulta fallida de timer con ausencia' || bad 'consulta fallida aprobada'

echo '== puertos de acciones Fail2ban'
for ports in '2222' '22,2222' '2200:2300'; do
    verification_port_contains "$ports" 2222 && ok "cubre 2222 en $ports" || bad "no cubre $ports"
done
verification_port_contains '22,2223' 2222; rc=$?
check 'un puerto cercano no sirve como coincidencia' 1 "$rc"

echo '== reporte privado sin confirmación automática'
reset_fixture
ASSUME_YES=1
verification_run > "$WORK/output"; rc=$?
check '--yes no convierte confirmación humana en éxito' 2 "$rc"
has 'guarda el resultado pendiente' 'Resultado: CON PENDIENTES' "$(cat "$VERIFY_REPORT")"
has 'declara acceso sin confirmar' 'sin confirmar' "$(cat "$VERIFY_REPORT")"
has 'guarda fecha y versión' 'Versión: test' "$(cat "$VERIFY_REPORT")"
mode=$(python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "$VERIFY_REPORT")
check 'reporte solo legible por root' 600 "$mode"
previous="$VERIFY_REPORT"
verification_run > /dev/null; rc=$?
[[ "$previous" != "$VERIFY_REPORT" ]] && ok 'dos verificaciones conservan reportes separados' || bad 'sobrescribió reporte'
check 'segunda corrida tampoco auto-confirma' 2 "$rc"

# Ejecutar las mismas funciones/fixtures en una terminal real para ejercitar
# read/token y la repetición de comprobaciones después de confirmar.
pty_fixture="$WORK/pty-fixture.sh"
{
    echo 'set -uo pipefail'
    declare -p WORK
    declare -f ui valid_username world_or_group_writable audit_eff_val audit_eff_rest audit_session_ip \
        verification_item verification_expect verification_port_contains verification_key_ok verification_ssh \
        verification_user verification_firewall verification_fail2ban verification_updates verification_rollbacks \
        verification_collect verification_result ssh_test_command show_access_test_steps ask_access_result \
        verification_run offer_final_verification \
        info warn success error reset_fixture id user_home existing_key_present _file_mode _file_owner password_state \
        visudo sudo runuser detect_ssh_activation listening_ports current_ssh_port pgrep systemctl sshd has_ufw ufw \
        has_fail2ban timeout fail2ban-client apt-config list_pending_rollbacks date hostname
    cat <<'FIXTURE'
UI_LANG=es
reset_fixture
mode="${1:-success}"
if [[ "$mode" == yes ]]; then ASSUME_YES=1; fi
if [[ "$mode" == changed ]]; then
    eval "$(declare -f verification_collect | sed 's/verification_collect/collect_original/')"
    verification_collect() {
        [[ "$VERIFY_EXTERNAL" == confirmed ]] && INACTIVE_SERVICE=ssh.service
        collect_original
    }
fi
rc=0
if [[ "$mode" == offer ]]; then offer_final_verification || rc=$?; else verification_run || rc=$?; fi
printf '%s\n' "$VERIFY_REPORT" > "$WORK/pty-report-path"
exit "$rc"
FIXTURE
} > "$pty_fixture"
run_pty() {
    python3 - "$pty_fixture" "$1" <<'PY'
import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execvp('bash', ['bash', sys.argv[1], sys.argv[2]])
out = b''; answered = False; offered = False
while True:
    try: data = os.read(fd, 65536)
    except OSError: break
    if not data: break
    out += data
    if sys.argv[2] == 'offer' and not offered and b'[S/n]' in out:
        os.write(fd, b'\n'); offered = True
    if not answered and b'\xc2\xbfLa prueba funcion' in out:
        os.write(fd, b's\n'); answered = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors='replace'))
sys.exit(os.waitstatus_to_exitcode(status))
PY
}
echo '== confirmación en terminal y estado que cambia'
run_pty success > "$WORK/pty-output"; rc=$?
check 'confirmación con todas las comprobaciones da éxito' 0 "$rc"
report=$(cat "$WORK/pty-report-path")
has 'registra que la confirmación es declaración del usuario' 'declaración del usuario): confirmados' "$(cat "$report")"
run_pty changed > "$WORK/pty-output"; rc=$?
check 'si SSH cae mientras se confirma no reutiliza un aprobado anterior' 1 "$rc"
report=$(cat "$WORK/pty-report-path")
has 'reporte guarda el fallo posterior a confirmar' 'Resultado: CON FALLOS' "$(cat "$report")"
run_pty yes > "$WORK/pty-output"; rc=$?
check '--yes tampoco confirma en una terminal real' 2 "$rc"
run_pty offer > "$WORK/pty-output"; rc=$?
check 'aceptar oferta por defecto ejecuta la verificación' 0 "$rc"
has 'se ofrece al usuario como opción' '¿Quieres verificar ahora' "$(cat "$WORK/pty-output")"
summary
