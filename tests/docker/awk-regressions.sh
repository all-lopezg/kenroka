#!/usr/bin/env bash
# Ejecuta el helper real con GNU awk y mawk en archivos de laboratorio.
set -euo pipefail
[[ ${container:-} == docker && $EUID -eq 0 ]] || exit 2
source <(sed -n '/^install_hardening_include()/,/^}/p' /opt/secure-vps.sh)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
PASS=0
expect() {
    if "$@"; then PASS=$((PASS + 1)); else
        printf 'FALLO: %s\n' "$*" >&2
        exit 1
    fi
}
# La expresión publicada antes debe reproducir exactamente el fallo del VPS.
if gawk -v include=x '$0 != include' /dev/null > "$work_dir/old.out" 2> "$work_dir/old.err"; then
    echo 'GNU awk debía rechazar el nombre reservado include' >&2
    exit 1
fi
expect grep -q 'builtin.*include' "$work_dir/old.err"
printf 'fallo-anterior-reproducido: OK\n'
for awk_impl in gawk mawk; do
    HARDENING_FILE="$work_dir/$awk_impl.conf"
    LEGACY_HARDENING_FILE="$work_dir/$awk_impl.legacy"
    SSHD_CONFIG="$work_dir/$awk_impl.sshd_config"
    printf 'PasswordAuthentication no\n' > "$HARDENING_FILE"
    printf 'Port 22\n' > "$LEGACY_HARDENING_FILE"
    printf '# proveedor\nPasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n' > "$work_dir/original"
    # Incluir una línea gestionada fuera del principio obliga a filtrarla.
    { cat "$work_dir/original"; printf 'Include %s\n' "$HARDENING_FILE"; } > "$SSHD_CONFIG"
    chmod 600 "$SSHD_CONFIG"
    awk() { "$awk_impl" "$@"; }
    expect install_hardening_include
    expect test "$(head -n 1 "$SSHD_CONFIG")" = "Include $HARDENING_FILE"
    tail -n +2 "$SSHD_CONFIG" > "$work_dir/preserved"
    expect cmp -s "$work_dir/original" "$work_dir/preserved"
    expect test "$(stat -c %a "$SSHD_CONFIG")" = 600
    expect test ! -e "$LEGACY_HARDENING_FILE"
    cp "$SSHD_CONFIG" "$work_dir/once"
    expect install_hardening_include
    expect cmp -s "$SSHD_CONFIG" "$work_dir/once"
    printf '%s-compatible: OK\n' "$awk_impl"
done
printf 'comprobaciones internas awk: %s\n' "$PASS"
