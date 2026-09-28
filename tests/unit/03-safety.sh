#!/usr/bin/env bash
# Regresiones de snapshot, confirmación tardía y cambio de política sudo.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
extract_fns ui snapshot_state arm_rollback rollback_snapshot_open disarm_rollback \
            revert_now confirm_port_change install_sudoers_policy \
            install_sudoers_nopasswd install_sudoers_prompt ensure_usable_sudo
error() { printf '%s\n' "$*" >&2; }
info() { :; }
warn() { :; }
success() { :; }
log() { :; }
ensure_sshd_runtime() { :; }
sshd() { :; }
systemctl() { return 1; }
ufw() { printf 'Status: inactive\n'; }
date() { printf '20260928-120000\n'; }
STATE_DIR="$WORK/state"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
HARDENING_FILE="$WORK/hardening"
CLOUD_INIT_FILE="$WORK/cloud-init"
SOCKET_DROPIN="$WORK/socket"
JAIL_LOCAL="$WORK/jail"
LOG_FILE="$WORK/log"
USERNAME=tester
CURRENT_PORT=22
SOCKET_ACTIVATED=0
ROLLBACK_ARMED=0
ROLLBACK_JOB=""
ROLLBACK_SNAP_DIR=""
SNAP_DIR=""
OPT_NO_ROLLBACK=0
ROLLBACK_MINUTES=10

# macOS no distribuye flock. fcntl usa un lock real sobre el fd heredado;
# la descripción abierta permanece en el subshell hasta salir, como con flock.
if ! command -v flock >/dev/null; then
    flock() {
        python3 - "$@" <<'PY'
import fcntl, sys
flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if '-n' in sys.argv else 0)
try:
    fcntl.flock(int(sys.argv[-1]), flags)
except BlockingIOError:
    sys.exit(1)
PY
    }
fi

list_pending_rollbacks() { printf '%s' "${PENDING_TIMER:-}"; }
systemd-run() { printf '%s\n' "$*" > "$WORK/armed"; }
kill_rollback_timer() { printf '%s\n' "$1" >> "$WORK/killed"; }
# La ejecución de restauración queda simulada; la selección de snapshot es real.
install_rollback_bin() { :; }
ROLLBACK_BIN="$WORK/rollback"
export SIM_STATE="$WORK/sim-state" SIM_RESTORED="$WORK/restored"
cat > "$ROLLBACK_BIN" <<'ROLLBACK'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$1" > "$SIM_RESTORED"
[[ ! -f "$1/REVERTED" && ! -f "$1/CONFIRMED" ]] || exit 0
cp "$1/sim-state" "$SIM_STATE"
touch "$1/REVERTED"
ROLLBACK
chmod +x "$ROLLBACK_BIN"

echo "== snapshot fijo de la cuenta atrás"
PENDING_TIMER=""
snapshot_state >/dev/null || exit 1
original="$SNAP_DIR"
printf 'firewall=inactivo\n' > "$SIM_STATE"
cp "$SIM_STATE" "$original/sim-state"
arm_rollback >/dev/null || exit 1
check "el temporizador conserva el snapshot original" "$original" "$ROLLBACK_SNAP_DIR"
has "systemd-run recibe ese mismo snapshot" "$original" "$(cat "$WORK/armed")"
PENDING_TIMER="$ROLLBACK_JOB.timer"
printf 'firewall=activo\n' > "$SIM_STATE"
snapshot_state >/dev/null || exit 1
latest="$SNAP_DIR"
cp "$SIM_STATE" "$latest/sim-state"
[[ "$latest" != "$original" ]] && ok "la fase siguiente crea otro snapshot" || bad "no creó otro snapshot"
check "el snapshot del timer no cambió" "$original" "$ROLLBACK_SNAP_DIR"
silence revert_now 'falló Fail2ban' || exit 1
check "revierte al estado anterior a activar el firewall" 'firewall=inactivo' "$(cat "$SIM_STATE")"
check "restaura el snapshot del timer, no el último" "$original" "$(cat "$SIM_RESTORED")"
check "cancela el timer solo después de restaurar" "$ROLLBACK_JOB" "$(cat "$WORK/killed")"
check "ya no considera armada la cuenta atrás" 0 "$ROLLBACK_ARMED"

reset_pending() {
    mkdir -p "$original"
    rm -f "$original/CONFIRMED" "$original/REVERTED" "$original/ROLLING_BACK" \
          "$original/ROLLBACK_FAILED" "$WORK/killed" "$WORK/finalized"
    touch "$original/READY"
    ROLLBACK_ARMED=1
    ROLLBACK_SNAP_DIR="$original"
    SNAP_DIR="$latest"
}

echo "== confirmación usa el snapshot del timer"
reset_pending
silence disarm_rollback || exit 1
[[ -f "$original/CONFIRMED" ]] && ok "confirma el snapshot original" || bad "snapshot original sin confirmar"
[[ ! -f "$latest/CONFIRMED" ]] && ok "no confirma el snapshot de otra fase" || bad "confirmó otro snapshot"

echo "== confirmación tardía no vuelve a cambiar el puerto"
finalize_old_port_removal() { printf '2222\n' > "$WORK/finalized"; }
for marker in ROLLING_BACK REVERTED ROLLBACK_FAILED; do
    reset_pending
    touch "$original/$marker"
    silence confirm_port_change; rc=$?
    check "rechaza confirmación con $marker" 1 "$rc"
    [[ ! -f "$WORK/finalized" ]] && ok "no modifica puertos con $marker" || bad "modificó puertos con $marker"
    [[ ! -f "$original/CONFIRMED" ]] && ok "no confirma estado con $marker" || bad "confirmó estado con $marker"
done

echo "== finalización protegida por el lock del rollback"
reset_pending
finalize_old_port_removal() {
    # Un proceso competidor abre por separado el mismo lock, como el rollback.
    if ( exec 7>"$ROLLBACK_SNAP_DIR/lock"; flock -n 7 ); then
        return 1
    fi
    [[ ! -f "$ROLLBACK_SNAP_DIR/CONFIRMED" ]] || return 1
    printf '2222\n' > "$WORK/finalized"
}
silence confirm_port_change; rc=$?
check "finaliza manteniendo el lock exclusivo" 0 "$rc"
check "aplica el puerto antes de confirmar" 2222 "$(cat "$WORK/finalized" 2>/dev/null)"
[[ -f "$original/CONFIRMED" ]] && ok "confirma al terminar la operación" || bad "no confirmó"
check "desarma después de finalizar" 0 "$ROLLBACK_ARMED"

reset_pending
finalize_old_port_removal() { return 1; }
silence confirm_port_change; rc=$?
check "un fallo al finalizar no se anuncia como éxito" 1 "$rc"
[[ ! -f "$original/CONFIRMED" ]] && ok "un fallo no confirma el snapshot" || bad "confirmó tras fallo"
check "el fallo restaura el snapshot protegido" "$original" "$(cat "$SIM_RESTORED")"

echo "== no iniciar otra fase tras vencer la cuenta atrás"
reset_pending
touch "$original/REVERTED"
PENDING_TIMER=""
silence snapshot_state; rc=$?
check "rechaza nueva fase aunque el timer ya no esté activo" 1 "$rc"
check "no reemplaza el snapshot de la fase" "$latest" "$SNAP_DIR"

echo "== sudo con contraseña reemplaza NOPASSWD"
# Solo se redirige la ruta del drop-in al directorio temporal de pruebas.
eval "$(declare -f install_sudoers_policy | sed 's|/etc/sudoers.d/|$WORK/sudoers/|g')"
mkdir -p "$WORK/sudoers"
visudo() { return "${VISUDO_RC:-0}"; }
sudo() { return "${SUDO_LIST_RC:-0}"; }
runuser() { printf '%s\n' "$*" > "$WORK/sudo-check"; return "${SUDO_RC:-1}"; }
password_state() { printf '%s\n' "${PASSWORD_STATE:-P}"; }
ask_sudo_mode() { :; }
NON_INTERACTIVE=0
VISUDO_RC=0
SUDO_RC=1
PASSWORD_STATE=P
SUDO_MODE=prompt
install_sudoers_nopasswd tester >/dev/null || exit 1
has "precondición: regla sin contraseña" NOPASSWD "$(cat "$WORK/sudoers/90-tester")"
silence ensure_usable_sudo tester; rc=$?
check "permite pasar a contraseña" 0 "$rc"
check "reemplaza el permiso administrado" 'tester ALL=(ALL) PASSWD:ALL' "$(cat "$WORK/sudoers/90-tester")"
has "comprueba sin credenciales cacheadas" 'sudo -k -n true' "$(cat "$WORK/sudo-check")"
SUDO_RC=0
silence ensure_usable_sudo tester; rc=$?
check "otra regla NOPASSWD impide anunciar éxito" 1 "$rc"
has "explica el conflicto efectivo" 'Otra regla sudoers' "$(cat "$WORK/silence.out")"
SUDO_RC=1
SUDO_LIST_RC=1
silence ensure_usable_sudo tester; rc=$?
check "sudo denegado no se confunde con exigir contraseña" 1 "$rc"
has "explica la denegación de la política efectiva" 'no permite administrar' "$(cat "$WORK/silence.out")"
SUDO_LIST_RC=0
install_sudoers_nopasswd tester >/dev/null || exit 1
PASSWORD_STATE=L
silence ensure_usable_sudo tester; rc=$?
check "sin contraseña usable se detiene" 1 "$rc"
has "conserva NOPASSWD hasta tener contraseña usable" NOPASSWD "$(cat "$WORK/sudoers/90-tester")"
VISUDO_RC=1
silence install_sudoers_prompt tester; rc=$?
check "rechaza sudoers inválido" 1 "$rc"
has "validación fallida preserva la regla previa" NOPASSWD "$(cat "$WORK/sudoers/90-tester")"

summary
