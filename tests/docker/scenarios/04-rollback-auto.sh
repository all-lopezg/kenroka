#!/usr/bin/env bash
# 04 · Nadie confirma y nadie cancela: la cuenta atrás tiene que revertir sola.
# Se deja el script bloqueado en la pregunta del token (stdin abierto pero sin
# datos), que es exactamente "me fui del terminal a mitad".
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: cierre aplicado y el operador desaparece sin confirmar"
echo "  (tarda ~90s: es el temporizador de verdad, no un mock)"

on_server_in '' "systemctl is-system-running >/dev/null 2>&1; echo listo" >/dev/null
prl0="$(sshd_get permitrootlogin)"

# `sleep | script` deja el stdin abierto sin enviar nada: el gate se queda
# esperando y el script sigue vivo con la cuenta atrás armada.
# La sesión SSH del operador es lo que permite al script cerrar el acceso.
start_admin_session
$DOCKER_COMPOSE_CMD -f "$COMPOSE" exec -d server bash -lc \
    "sleep 600 | runuser -u ubuntu -- sudo -n bash $SCRIPT --run-all --yes \
        --rollback-minutes 1 --user tester \
        --pubkey-file /keys/id_ed25519.pub --sudo nopasswd > /tmp/run04.log 2>&1"

armed=0
for _ in $(seq 1 20); do
    if [[ -n "$(pending_rollbacks)" ]]; then armed=1; break; fi
    sleep 2
done
expect_eq "la cuenta atrás quedó armada" 1 "$armed"
expect_eq "y el cierre ya está aplicado" "no" "$(sshd_get permitrootlogin)"
expect_no_login "root está afuera en este momento" root 22

echo "    esperando a que venza el minuto..."
reverted=0
for _ in $(seq 1 45); do
    if [[ "$(sshd_get permitrootlogin)" != "no" ]]; then reverted=1; break; fi
    sleep 2
done
expect_eq "el servidor se revierte solo al vencer" 1 "$reverted"
expect_eq "PermitRootLogin vuelve a su valor por defecto" "$prl0" "$(sshd_get permitrootlogin)"
expect_eq "PasswordAuthentication vuelve a yes" "yes" "$(sshd_get passwordauthentication)"
expect_login "root recupera el acceso sin ayuda externa" root 22
# El timer sigue cargado mientras su servicio hermano está corriendo el rollback;
# se descarga al terminar, así que hay que dejarlo aterrizar antes de mirar.
sleep 6
expect_eq "la cuenta atrás ya no está pendiente" "" "$(pending_rollbacks)"

on_server "pkill -f 'sleep 600' 2>/dev/null; pkill -f secure-vps.sh 2>/dev/null; true" >/dev/null
printf '    (salida del run bloqueado)\n'
on_server "tail -6 /tmp/run04.log 2>/dev/null" | sed 's/^/      /'

scenario_summary
