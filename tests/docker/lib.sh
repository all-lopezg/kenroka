#!/usr/bin/env bash
# Helpers compartidos por los escenarios end-to-end. Se corre en el HOST:
# cada aserto que necesita ver dos contenedores (el cliente SSH entrando o
# quedando afuera) solo se puede comprobar desde fuera de ambos.
#
# Uso: source tests/docker/lib.sh  y luego  on_server 'sshd -T'

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/compose.yml"
WORK="$HERE/.work"
SCRIPT="/opt/secure-vps.sh"

DOCKER_COMPOSE_CMD="${DOCKER_COMPOSE_CMD:-docker compose}"
SERVER_HOST="${SERVER_HOST:-server}"

cx() { $DOCKER_COMPOSE_CMD -f "$COMPOSE" exec -T "$@"; }

on_server() { cx server bash -lc "$1"; }
on_client() { cx client bash -lc "$1"; }

# on_server_in <texto-stdin> <comando>   (%b interpreta \n del texto)
on_server_in() {
    local input="$1"; shift
    printf '%b' "$input" | cx server bash -lc "$1"
}

# secure-vps.sh como root, invocado con sudo desde el usuario del proveedor:
# sudo pone SUDO_USER=ubuntu solo, que es el caso que check_original_user()
# espera ver (un lanzador no-root ya implica que hay otra vía de entrada).
RUN_LOGS=""
run_vps() {
    local log
    mkdir -p "$WORK/logs" || return
    log="$(mktemp "$WORK/logs/$(basename "$0" .sh).run-vps.XXXXXX")" || return
    RUN_LOGS="$RUN_LOGS $log"
    # --no-upgrade: el reporte de pendientes corre siempre, pero aplicar un
    # apt upgrade real en cada escena sería lento y alteraría la imagen. La
    # lógica de decisión se cubre en 18-updates-order.sh, que pasa --upgrade.
    cx server runuser -u ubuntu -- sudo -n bash "$SCRIPT" --lang es --no-upgrade "$@" 2>&1 | tee "$log"
}
run_vps_in() {
    local input="$1"; shift
    printf '%b' "$input" | run_vps "$@"
}

# --- estado observable del servidor ---
sshd_get()  { on_server "sshd -T 2>/dev/null | awk '/^$1 /{print \$2}' | head -1"; }
sshd_ports() { on_server "sshd -T 2>/dev/null | awk '/^port /{print \$2}' | paste -sd, -"; }
listening() { on_server "ss -Htln 2>/dev/null | awk '{print \$4}' | grep -oE '[0-9]+\$' | sort -un | paste -sd, -"; }
socket_listen() { on_server "systemctl show -p Listen --value ssh.socket 2>/dev/null | grep -oE ':[0-9]+' | tr -d ':' | sort -un | paste -sd, -"; }
hardening_exists() { on_server "test -f /etc/ssh/sshd_config.d/99-hardening.conf && echo si || echo no"; }
hardening_get() { on_server "awk '/^$1 /{print \$2}' /etc/ssh/sshd_config.d/99-hardening.conf 2>/dev/null | head -1"; }
ufw_rules() {
    ufw_dump | awk '/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+[^[:space:]].*[[:space:]]+(LIMIT|ALLOW)[[:space:]]+IN[[:space:]]+[^[:space:]]/ {n++} END {print n+0}'
}
ufw_dump() { on_server "ufw status numbered 2>/dev/null"; }
ufw_active() { on_server "ufw status 2>/dev/null | head -1"; }
f2b_status() { on_server "fail2ban-client status sshd 2>&1 | tr '\n' ' '"; }
f2b_jail() { on_server "cat /etc/fail2ban/jail.d/99-secure-vps.local 2>/dev/null"; }
pending_rollbacks() { on_server "systemctl list-units --all --no-legend --no-pager --type=timer --state=active 'secure-vps-rollback*' 2>/dev/null | awk '{print \$1}' | paste -sd, -"; }
# Solo listeners TCP de sshd, sin sesiones establecidas ni servicios ajenos.
ssh_ports() { on_server "set -o pipefail; ss -Htlnp | awk '/users:.*\(\"sshd\",/ {port=\$4; sub(/^.*:/, \"\", port); print port}' | sort -un | paste -sd, -"; }
# ssh.socket sólo manda el puerto cuando está enabled (24.04); en 22.04 es ssh.service.
socket_activated() { on_server '[[ "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" == enabled ]] && echo si || echo no'; }
has_generator() { on_server "[[ -d /run/systemd/generator/ssh.socket.d ]] && echo si || echo no"; }
# Reglas de UFW cuyo campo "To" empieza por ese puerto (o su alias): anclado
# para que 22 no case con 2222.
ufw_rules_for() { on_server "ufw status numbered 2>/dev/null | grep -E '^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+($1(/tcp|/udp)?|$2)([[:space:]]|\(|$)'"; }
list_snapshots() { on_server "ls -1d /var/lib/secure-vps/snapshots/*/ 2>/dev/null | wc -l | tr -d ' '"; }
# Snapshots marcados como confirmados: si uno existe, ese estado es permanente.
confirmed_snaps() { on_server "find /var/lib/secure-vps/snapshots -maxdepth 2 -name CONFIRMED 2>/dev/null | wc -l | tr -d ' '"; }
rollback_bin_present() { on_server "test -x /usr/local/bin/secure-vps-rollback && echo si || echo no"; }
auth_log() { on_server "journalctl -u ssh -u sshd --no-pager -n 40 2>/dev/null | tail -20"; }
script_log() { on_server "tail -40 /var/log/secure-vps.log 2>/dev/null"; }

# --- el cliente intentando entrar: esto es lo que decide si hay encierro ---
# ssh_login <usuario> <puerto> -> 0 si entra con clave, 1 si sshd lo rechaza
ssh_login() {
    local user="$1" port="${2:-22}"
    on_client "timeout 12 ssh -p $port -i /keys/id_ed25519 \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
        $user@$SERVER_HOST true" >/dev/null 2>&1
}
ssh_login_verbose() {
    local user="$1" port="${2:-22}"
    on_client "timeout 12 ssh -p $port -i /keys/id_ed25519 \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
        $user@$SERVER_HOST true 2>&1"
}
# ssh_login_password: entra con sshpass porque ssh lee la contraseña de
# /dev/tty, no de stdin. 0 = la contraseña fue aceptada.
ssh_login_password() {
    local user="$1" port="${2:-22}" pass="$3"
    on_client "timeout 12 sshpass -p '$pass' ssh -p $port \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 -o NumberOfPasswordPrompts=1 \
        $user@$SERVER_HOST true" >/dev/null 2>&1
}

# Sesión SSH real y sostenida desde el cliente: deja una entrada en 'who' para
# que detect_admin_ips() funcione como en un VPS de verdad.
# Hace falta -tt: con un solo -t ssh no asigna pseudo-terminal si su propio
# stdin no es un tty (aquí va detached), y sin tty sshd no escribe en utmp.
start_admin_session() {
    local port="${1:-22}"
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" exec -d client bash -lc \
        "ssh -tt -p $port -i /keys/id_ed25519 -o BatchMode=yes \
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             root@$SERVER_HOST 'sleep 900' >/dev/null 2>&1" >/dev/null 2>&1
    sleep 2
}
client_ip() {
    on_client "hostname -I 2>/dev/null | awk '{print \$1}'"
}
who_lines() { on_server "who 2>/dev/null"; }

# --- asserts ---
PASS=0
FAIL=0
FAILURES=""
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); FAILURES="$FAILURES\n    - $*"; printf '  FALLA %s\n' "$*"; }

expect_eq() { # expect_eq <desc> <esperado> <real>
    if [[ "$3" == "$2" ]]; then ok "$1"; else bad "$1 | esperado='$2' real='$3'"; fi
}
expect_match() { # expect_match <desc> <patrón-grep-E> <texto>
    if printf '%s' "$3" | grep -qE -- "$2"; then ok "$1"; else bad "$1 | no contiene /$2/ en: $(printf '%s' "$3" | head -c 200)"; fi
}
expect_nomatch() {
    if printf '%s' "$3" | grep -qE -- "$2"; then bad "$1 | contiene /$2/"; else ok "$1"; fi
}
expect_login() { # expect_login <desc> <usuario> <puerto>
    # 3 intentos: un sshd recién reiniciado puede rechazar la primera conexión.
    local attempt
    for attempt in 1 2 3; do
        if ssh_login "$2" "${3:-22}"; then ok "$1"; return 0; fi
        sleep 2
    done
    bad "$1 | ssh dijo: $(ssh_login_verbose "$2" "${3:-22}" | head -3 | tr '\n' ' ')"
}
expect_no_login() {
    if ssh_login "$2" "${3:-22}"; then bad "$1 | SÍ dejó entrar (debería rechazar)"; else ok "$1"; fi
}

# Errores de runtime de bash que el script puede no reportar: dentro de un `if`
# (como `if ! fase_0_welcome`) el errexit queda desactivado, así que un comando
# inexistante no detiene la corrida y el exit code sale 0 igual.
check_shell_errors() {
    local hits
    [[ -n "$RUN_LOGS" ]] || return 0
    hits="$(grep -hoE '(line [0-9]+: [^:]+: (command not found|unbound variable)|syntax error)' $RUN_LOGS 2>/dev/null | sort -u | head -3)"
    if [[ -n "$hits" ]]; then
        bad "bash enmascaró un error: $(printf '%s' "$hits" | tr '\n' ' ')"
    fi
}

scenario_summary() {
    check_shell_errors
    printf '\n  resultado: %d ok, %d fallas\n' "$PASS" "$FAIL"
    if [[ $FAIL -ne 0 ]]; then
        printf '  fallas:%b\n' "$FAILURES"
        printf '\n  --- log de secure-vps en el servidor ---\n'
        script_log | sed 's/^/  /'
        printf '\n  --- journalctl ssh ---\n'
        auth_log | sed 's/^/  /'
    fi
    [[ $FAIL -eq 0 ]]
}

# --- preparación / limpieza ---
reset_server() {
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" down --remove-orphans -v >/dev/null 2>&1
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" up -d server client >/dev/null 2>&1 || return 1
    wait_for_systemd || return 1
    # Copia (no mount): la corrida usa una instantánea estable del script.
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" cp "$REPO_ROOT/secure-vps.sh" server:/opt/secure-vps.sh >/dev/null 2>&1 || return 1
    on_server "chmod 755 /opt/secure-vps.sh; bash -n /opt/secure-vps.sh" || return 1
    on_server "bash /tests/seed.sh" >/dev/null 2>&1
}

wait_for_systemd() {
    local i
    for i in $(seq 1 60); do
        if on_server "systemctl is-system-running --wait --quiet" >/dev/null 2>&1 \
           || on_server "test -d /run/systemd/system && systemctl list-units --no-pager >/dev/null 2>&1"; then
            return 0
        fi
        sleep 1
    done
    echo "  systemd no arrancó en el contenedor" >&2
    return 1
}
