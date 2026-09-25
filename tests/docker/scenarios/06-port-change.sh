#!/usr/bin/env bash
# 06 · Cambio de puerto en Ubuntu 24.04. Aquí es donde el script original fallaba
# por escribir Port en sshd_config cuando quien manda el listen es ssh.socket.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: 'pasa SSH al 2222 y cierra el 22'"
start_admin_session

out="$(run_vps_in 'acceso-ok\nacceso-ok\nacceso-ok\n' --run-all --yes --port 2222 \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -iE 'ssh.socket|drop-in|escucha|puerto' | head -8 | sed 's/^/    > /'

expect_eq "termina bien" 0 "$rc"
expect_match "explica cómo se manda el puerto en esta versión" "ssh.socket|ssh.service" "$out"
SOCKED="$(socket_activated)"; GENER="$(has_generator)"
echo "    ssh.socket enabled: $SOCKED · generador 24.04: $GENER"
if [[ "$SOCKED" == si ]]; then
    expect_eq "el socket escucha solo en 2222" "2222" "$(socket_listen)"
fi
expect_eq "y eso es lo que se ve en la red" "2222" "$(ssh_ports)"
expect_eq "el puerto se manda con Port en sshd_config.d" "2222" \
    "$(on_server "awk '/^Port /{print \$2}' /etc/ssh/sshd_config.d/99-hardening.conf | paste -sd, -")"
# En 24.04 el generador de systemd traduce 'Port' a ListenStream y escribe su
# propio drop-in; un ListenStream manual quedaría aplastado por el suyo.
if [[ "$GENER" == si ]]; then
    expect_eq "sin drop-in manual, que estorbaría al generador" "no" \
        "$(on_server "test -f /etc/systemd/system/ssh.socket.d/99-secure-vps.conf && echo si || echo no")"
    gen="$(on_server "cat /run/systemd/generator/ssh.socket.d/addresses.conf 2>/dev/null")"
    expect_match "el generador reprodujo el puerto nuevo" "ListenStream=0\.0\.0\.0:2222" "$gen"
    expect_nomatch "y ya no lista el 22" ":22$" "$gen"
elif [[ "$SOCKED" == si ]]; then
    expect_eq "sin generador, el drop-in de ListenStream sí es necesario" "si" \
        "$(on_server "test -f /etc/systemd/system/ssh.socket.d/99-secure-vps.conf && echo si || echo no")"
fi

expect_login "se entra por 2222" tester 2222
expect_no_login "el 22 ya no acepta conexiones" tester 22

echo "    ufw: $(ufw_dump | grep -E 'ALLOW|LIMIT' | tr '\n' '|')"
expect_match "UFW permite 2222" "2222" "$(ufw_dump)"
expect_eq "UFW ya no tiene la regla del 22 (el bug del delete por alias)" "" "$(ufw_rules_for 22 ssh)"
expect_match "jail de fail2ban en el puerto nuevo" "^port     = 2222" "$(f2b_jail)"
expect_eq "sin cuenta atrás pendiente" "" "$(pending_rollbacks)"

scenario_summary
