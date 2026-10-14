#!/usr/bin/env bash
# Servicios reales: precedencia, migración y restauración del orden de Includes.
set -euo pipefail
[[ ${container:-} == docker && $EUID -eq 0 ]] || exit 2
source <(sed '$d' /opt/secure-vps.sh)
export LC_ALL=C
UI_LANG=es
NON_INTERACTIVE=1
ASSUME_YES=1
USERNAME=tester
SUDO_MODE=nopasswd
LOCKDOWN=1
PASS=0
expect() {
    if "$@"; then PASS=$((PASS + 1)); else
        printf 'FALLO: %s\n' "$*" >&2
        exit 1
    fi
}
detect_ssh_activation
CURRENT_PORT=$(current_ssh_port)
fase_1_user
install_authorized_key tester "$(cat /keys/id_ed25519.pub)"
# Simular un endurecimiento legado y directivas del proveedor anteriores.
printf 'Port 22\nPermitRootLogin no\nPasswordAuthentication no\nAllowUsers tester\n' > "$LEGACY_HARDENING_FILE"
printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > /etc/ssh/sshd_config.d/00-provider.conf
sed -i '1i PasswordAuthentication yes' "$SSHD_CONFIG"
sshd -t
sha_main=$(sha256sum "$SSHD_CONFIG")
sha_legacy=$(sha256sum "$LEGACY_HARDENING_FILE")
snapshot_state
original="$SNAP_DIR"
arm_rollback
write_hardening_file
install_hardening_include
sshd -t
expect verify_effective_access
expect test ! -e "$LEGACY_HARDENING_FILE"
expect test "$(sshd -T | awk '/^port /{print $2}')" = 22
expect test "$(sshd -T | awk '/^allowusers /{print $2}')" = tester
expect test "$(sshd -T | awk '/^passwordauthentication /{print $2}')" = no
restart_ssh
printf 'precedencia-y-migracion: OK\n'
cp "$SSHD_CONFIG" /tmp/sshd-after-include
cp "$HARDENING_FILE" /tmp/kenroka-after-migration
write_hardening_file
install_hardening_include
expect cmp -s "$SSHD_CONFIG" /tmp/sshd-after-include
expect cmp -s "$HARDENING_FILE" /tmp/kenroka-after-migration
printf '\nMatch User root\n    PermitRootLogin yes\n' >> "$SSHD_CONFIG"
if verify_effective_access; then echo 'Match root debía detener el cierre' >&2; exit 1; fi
PASS=$((PASS + 1))
cp /tmp/sshd-after-include "$SSHD_CONFIG"
printf '\nMatch User tester\n    PasswordAuthentication yes\n' >> "$SSHD_CONFIG"
if verify_effective_access; then echo 'Match tester debía detener el cierre' >&2; exit 1; fi
PASS=$((PASS + 1))
printf 'match-incompatible: OK\n'
revert_now 'Prueba de restauración tras migrar configuración SSH'
expect test -f "$original/REVERTED"
expect test "$(sha256sum "$SSHD_CONFIG")" = "$sha_main"
expect test "$(sha256sum "$LEGACY_HARDENING_FILE")" = "$sha_legacy"
expect test ! -e "$HARDENING_FILE"
expect test -z "$(list_pending_rollbacks)"
expect test "$(sshd -T | awk '/^passwordauthentication /{print $2}')" = yes
printf 'restauracion-de-migracion: OK\n'
printf 'comprobaciones internas: %s\n' "$PASS"
