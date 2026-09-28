#!/usr/bin/env bash
# Se ejecuta únicamente dentro del contenedor de pruebas Ubuntu como root.
set -euo pipefail
[[ ${container:-} == docker && $EUID -eq 0 ]] || exit 2
# Cargar las funciones y rutas reales, sin ejecutar main.
source <(sed '$d' /opt/secure-vps.sh)
export LC_ALL=C
umask 077
UI_LANG=es
NON_INTERACTIVE=1
USERNAME=tester
SUDO_MODE=nopasswd
OPT_SKIP_LOCKDOWN=1
LOG_FILE_TEST=/tmp/safety-regressions.log
PASS=0
expect() {
    if "$@"; then
        PASS=$((PASS + 1))
    else
        printf 'FALLO: %s\n' "$*" >&2
        exit 1
    fi
}
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"
detect_ssh_activation
CURRENT_PORT=$(current_ssh_port)
fase_1_user
install_authorized_key tester "$(cat /keys/id_ed25519.pub)"

printf '\n== firewall pendiente y fallo en la fase siguiente\n'
ufw --force disable
snapshot_state
original="$SNAP_DIR"
arm_rollback
ufw limit 22/tcp
ufw --force enable
saved_jail_fn=$(declare -f write_fail2ban_jail)
write_fail2ban_jail() { printf 'configuracion sin seccion\n' > "$JAIL_LOCAL"; }
if fase_5_fail2ban > "$LOG_FILE_TEST" 2>&1; then
    echo 'Fail2ban debía rechazar la configuración' >&2
    exit 1
fi
expect test "$SNAP_DIR" != "$original"
expect test "$ROLLBACK_SNAP_DIR" = "$original"
expect test -f "$original/REVERTED"
expect test "$ROLLBACK_ARMED" = 0
expect test "$(ufw status | head -1)" = 'Status: inactive'
expect test -z "$(list_pending_rollbacks)"
eval "$saved_jail_fn"
printf 'snapshot-pendiente: OK\n'

printf '\n== confirmación recibida después del rollback real\n'
snapshot_state
original="$SNAP_DIR"
arm_rollback
hardening_set_ports 22 2222
ufw limit 2222/tcp
restart_ssh
expect test "$(listening_ports)" = '22 2222 '
# Disparar el mismo servicio que lanzaría el timer, sin esperar diez minutos.
systemctl start "$ROLLBACK_JOB.service"
for _ in $(seq 1 30); do
    [[ -f "$original/REVERTED" ]] && break
    sleep 1
done
expect test -f "$original/REVERTED"
expect test "$(listening_ports)" = '22 '
NEW_PORT=2222
if confirm_port_change > "$LOG_FILE_TEST" 2>&1; then
    echo 'La confirmación tardía debía rechazarse' >&2
    exit 1
fi
expect test ! -f "$original/CONFIRMED"
expect test "$(listening_ports)" = '22 '
expect test -z "$(list_pending_rollbacks)"
printf 'confirmacion-tardia: OK\n'

printf '\n== confirmación y finalización reales bajo el lock\n'
snapshot_state
original="$SNAP_DIR"
arm_rollback
hardening_set_ports 22 2222
ufw limit 2222/tcp
restart_ssh
saved_finalize_fn=$(declare -f finalize_old_port_removal)
# Guardar una copia con otro nombre permite comprobar el lock y luego ejecutar
# la finalización real de SSH/UFW/Fail2ban.
eval "${saved_finalize_fn/finalize_old_port_removal/finalize_real}"
finalize_old_port_removal() {
    if ( exec 7>"$ROLLBACK_SNAP_DIR/lock"; flock -n 7 ); then
        echo 'El lock quedó libre durante la finalización' >&2
        return 1
    fi
    finalize_real
}
confirm_port_change
expect test -f "$original/CONFIRMED"
expect test "$ROLLBACK_ARMED" = 0
expect test "$(listening_ports)" = '2222 '
expect test -z "$(list_pending_rollbacks)"
printf 'finalizacion-protegida: OK\n'

printf '\n== NOPASSWD pasa a contraseña con sudo real\n'
printf 'tester:kenroka-prueba-sudo\n' | chpasswd
SUDO_MODE=prompt
ensure_usable_sudo tester
expect grep -qx 'tester ALL=(ALL) PASSWD:ALL' /etc/sudoers.d/90-tester
if runuser -u tester -- sudo -k -n true; then
    echo 'sudo no debe funcionar sin contraseña' >&2
    exit 1
fi
printf 'kenroka-prueba-sudo\n' | runuser -u tester -- sudo -k -S -p '' true
printf 'tester ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/99-safety-conflict
chmod 0440 /etc/sudoers.d/99-safety-conflict
if ensure_usable_sudo tester > "$LOG_FILE_TEST" 2>&1; then
    echo 'Otra regla NOPASSWD debía impedir declarar éxito' >&2
    exit 1
fi
expect grep -q 'Otra regla sudoers' "$LOG_FILE_TEST"
printf 'tester ALL=(ALL) !ALL\n' > /etc/sudoers.d/99-safety-conflict
if ensure_usable_sudo tester > "$LOG_FILE_TEST" 2>&1; then
    echo 'Una denegación de sudo no debe confundirse con exigir contraseña' >&2
    exit 1
fi
expect grep -q 'no permite administrar' "$LOG_FILE_TEST"
rm -f /etc/sudoers.d/99-safety-conflict
printf 'sudo-contrasena: OK\n'
printf '\nRegresiones verificadas con systemd/SSH/sudo reales: %s asertos\n' "$PASS"
