#!/usr/bin/env bash
# 07 · El puerto nuevo ya está ocupado por otra cosa: la fase 7 debe negarse y
# no dejar SSH partido por la mitad.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: una app ya escucha en 2222"
on_server "nohup socat TCP-LISTEN:2222,reuseaddr,fork EXEC:/bin/true >/dev/null 2>&1 & sleep 1; echo ok" >/dev/null
expect_eq "el 2222 está ocupado antes de correr" "si" \
    "$(on_server "ss -Htln | grep -qE ':2222\b' && echo si || echo no")"

before="$(listening)"
# La fase 7 se salta si ve consola de proveedor: hace falta la sesión SSH.
start_admin_session
out="$(run_vps_in 'acceso-ok\n' --run-all --yes --port 2222 --skip-lockdown \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?

expect_match "avisa que otro servicio lo usa" "otro servicio" "$out"
expect_eq "sale con error" 1 "$rc"
expect_eq "no tocó los puertos en escucha" "$before" "$(listening)"
expect_eq "no dejó un drop-in a medias" "no" \
    "$(on_server "test -f /etc/systemd/system/ssh.socket.d/99-secure-vps.conf && echo si || echo no")"
expect_login "sigue habiendo acceso por 22" root 22

on_server "pkill -f 'TCP-LISTEN:2222' 2>/dev/null; true" >/dev/null
scenario_summary
