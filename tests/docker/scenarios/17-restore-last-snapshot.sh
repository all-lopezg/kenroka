#!/usr/bin/env bash
# 17 · El rescate del menú: la opción 11 revierte al ÚLTIMO snapshot, o sea
# deshace el último cambio (el del puerto), no todo el endurecimiento. Es la
# vía que la tarjeta final le indica a un novato, así que se prueba de verdad:
# vía menú, con confirmación, y verificando que el 22 vuelve a funcionar.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  primera pasada: endurecer y mover a 2222"
start_admin_session
sha0="$(on_server "sha256sum /etc/ssh/sshd_config | awk '{print \$1}'")"

out="$(run_vps_in 'acceso-ok\nacceso-ok\nacceso-ok\n' --run-all --yes --port 2222 \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
expect_eq "primera pasada ok" 0 "$rc"
expect_eq "SSH en 2222" "2222" "$(ssh_ports)"
expect_match "UFW activo" "Status: active" "$(ufw_active)"
expect_eq "sin cuenta atrás pendiente" "" "$(pending_rollbacks)"

echo "  opción 11 del menú: revertir al último snapshot"
out2="$(run_vps_in '11\ns\n0\n' --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc2=$?
printf '%s\n' "$out2" | grep -E 'restaurado|Destino' | head -4 | sed 's/^/    > /'

expect_eq "el menú termina limpio" 0 "$rc2"
expect_match "confirma la restauración" "Estado restaurado" "$out2"
expect_eq "el puerto volvió al 22" "22" "$(ssh_ports)"
expect_eq "sshd también" "22" "$(sshd_ports)"
expect_eq "la config quedó sin Port 2222" "" "$(hardening_get Port)"
expect_eq "sshd_config intacto byte a byte" "$sha0" \
    "$(on_server "sha256sum /etc/ssh/sshd_config | awk '{print \$1}'")"
expect_match "UFW sigue activo (el snapshot es posterior a la fase 4)" "Status: active" "$(ufw_active)"
expect_nomatch "sin la regla del 2222" "2222" "$(ufw_dump)"
expect_match "jail de fail2ban de vuelta al 22" "^port     = 22" "$(f2b_jail)"
expect_eq "sin cuenta atrás pendiente" "" "$(pending_rollbacks)"

expect_login "se entra por el 22" tester 22
expect_no_login "el 2222 ya no responde" tester 2222

scenario_summary
