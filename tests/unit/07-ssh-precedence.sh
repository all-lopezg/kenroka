#!/usr/bin/env bash
# Precedencia real de OpenSSH y migración sin tocar la configuración del host.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
extract_fns ui write_hardening_file hardening_set_ports install_hardening_include verify_effective_access
HARDENING_FILE="$WORK/secure-vps.conf"
LEGACY_HARDENING_FILE="$WORK/dropins/99-hardening.conf"
SSHD_CONFIG="$WORK/sshd_config"
USERNAME="$(id -un)"
LOCKDOWN=1
SSH_CONNECTION='198.51.100.7 55555 203.0.113.9 22'
error() { printf '%s\n' "$*" >&2; }
success() { :; }
ensure_sshd_runtime() { :; }
mkdir -p "$WORK/dropins"
printf 'Port 2222\nPasswordAuthentication no\nPermitRootLogin no\nAllowUsers %s\n' "$USERNAME" > "$LEGACY_HARDENING_FILE"
printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > "$WORK/dropins/00-provider.conf"
printf 'PasswordAuthentication yes\nInclude %s/*.conf\n' "$WORK/dropins" > "$SSHD_CONFIG"
cp "$SSHD_CONFIG" "$WORK/original"
write_hardening_file
install_hardening_include
check 'include de Kenroka precede a opciones e includes del proveedor' "Include $HARDENING_FILE" "$(head -n 1 "$SSHD_CONFIG")"
check 'el resto de sshd_config se conserva byte a byte' "$(cat "$WORK/original")" "$(tail -n +2 "$SSHD_CONFIG")"
[[ ! -e "$LEGACY_HARDENING_FILE" ]] && ok 'retira el drop-in legado tras migrar' || bad 'no retiró el drop-in legado'
has 'migra el puerto previo' 'Port 2222' "$(cat "$HARDENING_FILE")"
cp "$SSHD_CONFIG" "$WORK/once"
cp "$HARDENING_FILE" "$WORK/hardening-once"
write_hardening_file
install_hardening_include
cmp -s "$SSHD_CONFIG" "$WORK/once" && ok 'include idempotente byte a byte' || bad 'include no idempotente'
cmp -s "$HARDENING_FILE" "$WORK/hardening-once" && ok 'hardening idempotente byte a byte' || bad 'hardening no idempotente'
# También debe migrar una instalación ya cerrada en modo suave.
cp "$HARDENING_FILE" "$LEGACY_HARDENING_FILE"
rm "$HARDENING_FILE"
LOCKDOWN=0
write_hardening_file
install_hardening_include
has 'modo suave conserva cierre previo' 'PasswordAuthentication no' "$(cat "$HARDENING_FILE")"
LOCKDOWN=1
cp "$HARDENING_FILE" "$LEGACY_HARDENING_FILE"
rm "$HARDENING_FILE"
hardening_set_ports 2222 2223
install_hardening_include
has 'cambio de puerto directo migra políticas previas' 'PasswordAuthentication no' "$(cat "$HARDENING_FILE")"
check 'cambio de puerto directo conserva transición' '2222 2223' "$(awk '/^Port /{print $2}' "$HARDENING_FILE" | paste -sd' ' -)"
hardening_set_ports 2222
SSHD_BIN="$(command -v sshd || true)"
if [[ -z "$SSHD_BIN" ]]; then
    echo '  SKIP configuración efectiva real: sshd no disponible'
    summary
    exit $?
fi
ssh-keygen -q -t ed25519 -N '' -f "$WORK/host-key" || exit 1
printf '\nHostKey %s\n' "$WORK/host-key" >> "$SSHD_CONFIG"
# En Linux sshd exige el directorio runtime incluso en -T; no se crea aquí.
if ! "$SSHD_BIN" -T -f "$SSHD_CONFIG" > "$WORK/effective" 2> "$WORK/sshd-error"; then
    echo "  SKIP configuración efectiva real: $(cat "$WORK/sshd-error")"
    summary
    exit $?
fi
sshd() { "$SSHD_BIN" "$@" -f "$SSHD_CONFIG"; }
silence verify_effective_access
check 'configuración real cierra contraseña y root pese al proveedor' 0 "$?"
check 'puerto migrado se incluye una sola vez' '2222' "$(awk '/^port /{print $2}' "$WORK/effective")"
check 'AllowUsers se incluye una sola vez' "$USERNAME" "$(awk '/^allowusers /{$1="";sub(/^ /, "");print}' "$WORK/effective")"
printf '\nMatch User %s\n    PasswordAuthentication yes\n' "$USERNAME" >> "$SSHD_CONFIG"
silence verify_effective_access
check 'Match del administrador incompatible sigue abortando' 1 "$?"
cp "$WORK/once" "$SSHD_CONFIG"
printf '\nHostKey %s\nMatch User root\n    PermitRootLogin yes\n' "$WORK/host-key" >> "$SSHD_CONFIG"
silence verify_effective_access
check 'Match de root incompatible también aborta' 1 "$?"
summary
