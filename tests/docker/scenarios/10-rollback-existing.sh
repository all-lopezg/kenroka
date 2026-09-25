#!/usr/bin/env bash
# 10 · Negar un cambio de puerto debe restaurar exactamente un hardening previo.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

CMD_ARGS=(--run-all --yes --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd)
SNAPSHOT_FILES=(
    /etc/ssh/sshd_config.d/99-hardening.conf
    /etc/ssh/sshd_config.d/50-cloud-init.conf
    /etc/ufw/user.rules
    /etc/ufw/user6.rules
)

echo "  primera pasada: endurecer y confirmar SSH en 2222"
start_admin_session
out1="$(run_vps_in 'acceso-ok\nacceso-ok\nacceso-ok\n' "${CMD_ARGS[@]}" --port 2222 2>&1)"
rc1=$?
expect_eq "el hardening inicial termina bien" 0 "$rc1"
expect_eq "existe el hardening que se deberá restaurar" si "$(hardening_exists)"
expect_eq "la configuración inicial usa 2222" 2222 "$(sshd_ports)"
expect_eq "sshd escucha inicialmente solo en 2222" 2222 "$(ssh_ports)"
expect_login "tester entra por 2222 antes del segundo cambio" tester 2222
ufw_before="$(ufw_active)"
expect_eq "UFW ya está activo antes del segundo cambio" "Status: active" "$ufw_before"
expect_eq "la primera pasada no deja rollback pendiente" "" "$(pending_rollbacks)"

before_checksums=()
for file in "${SNAPSHOT_FILES[@]}"; do
    checksum="$(on_server "sha256sum '$file'")"
    expect_eq "se puede leer el checksum inicial de $file" 0 "$?"
    expect_match "el checksum inicial de $file es válido" '^[[:xdigit:]]{64}[[:space:]]' "$checksum"
    before_checksums+=("$checksum")
done

if [[ $FAIL -ne 0 ]]; then
    scenario_summary
    exit 1
fi

echo "  segunda pasada: confirmar fase 3 y negar el cambio a 2223"
# UFW ya está activo: solo se confirma fase 3 y se niega el token del puerto.
out2="$(run_vps_in 'acceso-ok\nacceso-no-dado\n' "${CMD_ARGS[@]}" --port 2223 2>&1)"
rc2=$?
expect_eq "negar el último token devuelve error" 1 "$rc2"
expect_match "alcanzó la transición a 2223 antes de revertir" "SSH escuchando en:.*2222.*2223" "$out2"
expect_match "revierte por negar el cambio de puerto, no por otro error" "Sin confirmación, vuelvo al puerto 2222" "$out2"

for ((i=0; i<${#SNAPSHOT_FILES[@]}; i++)); do
    file="${SNAPSHOT_FILES[$i]}"
    checksum="$(on_server "sha256sum '$file'")"
    expect_eq "se puede leer el checksum restaurado de $file" 0 "$?"
    expect_eq "restauró exactamente $file" "${before_checksums[$i]}" "$checksum"
done

expect_eq "UFW conserva su estado activo" "$ufw_before" "$(ufw_active)"
expect_eq "la configuración efectiva vuelve a 2222" 2222 "$(sshd_ports)"
if [[ "$(socket_activated)" == si ]]; then
    expect_eq "ssh.socket vuelve solo a 2222" 2222 "$(socket_listen)"
fi
expect_eq "sshd escucha realmente solo en 2222" 2222 "$(ssh_ports)"
expect_login "el acceso por 2222 sobrevive al rollback" tester 2222
expect_no_login "2223 no acepta acceso tras el rollback" tester 2223
expect_eq "no queda una cuenta atrás pendiente" "" "$(pending_rollbacks)"

scenario_summary
