#!/usr/bin/env bash
# 18 · El orden de las actualizaciones: se reportan al arrancar, se aplican
# DESPUÉS de tener la clave verificada y ANTES de cerrar el acceso, y el aviso
# de reinicio llega al final. El arnés corre con --no-upgrade (aplicar un apt
# upgrade real en cada escena sería lento y alteraría la imagen); aquí se
# comprueban las tres decisiones que no dependen de la red.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  corrida guiada con --no-upgrade y aviso de reinicio pendiente"
start_admin_session
on_server "touch /var/run/reboot-required" >/dev/null

out="$(run_vps_in 's\nacceso-ok\nn\ns\nacceso-ok\nn\n' --run-all \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina bien" 0 "$rc"
expect_match "reporta el estado de los paquetes al empezar" \
    "paquetes actualizables|está al día|No pude refrescar" "$out"
expect_match "la fase 2.5 existe y va entre la 2 y la 3" "FASE 2.5" "$out"
expect_match "con --no-upgrade no aplica nada" "--no-upgrade: dejo las pendientes" "$out"
secuencia="$(printf '%s\n' "$out" | grep -oE 'FASE 2:|FASE 2\.5|FASE 3:' | tr '\n' ' ')"
expect_eq "el orden es fase 2, 2.5 y luego 3" "FASE 2: FASE 2.5 FASE 3: " "$secuencia"
expect_match "y avisa de que hace falta reiniciar" "Hace falta reiniciar" "$out"
expect_match "dando el comando exacto" "sudo reboot" "$out"
expect_eq "el cierre de acceso se aplicó igual" "no" "$(sshd_get passwordauthentication)"

echo "  modo desatendido sin --upgrade: reporta y no actualiza"
out2="$(on_server_in '' "bash $SCRIPT --lang es --non-interactive --skip-lockdown --yes \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1")"
rc2=$?
expect_match "dice que no actualiza por su cuenta" "Modo desatendido: no actualizo" "$out2"
expect_match "y propone el flag explícito" "con --upgrade" "$out2"

scenario_summary
