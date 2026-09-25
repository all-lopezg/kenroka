#!/usr/bin/env bash
# 13 · El operador acepta el consejo de salir del 22 en la corrida guiada, sin
# haber pasado --port. Es la ruta que sigue una persona real: 's' y Enter (2222
# por defecto). 06 fuerza el puerto por flag y 12 rechaza el consejo.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: operador guiado que acepta el 2222 propuesto"
start_admin_session

# fase 0 's' | fase 3 acceso-ok | fase 4 no abrir puertos, activar UFW, acceso-ok
# | fase 7 's', puerto por defecto (Enter) y acceso-ok
out="$(run_vps_in 's\nacceso-ok\nn\ns\nacceso-ok\ns\n\nacceso-ok\n' --run-all \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -iE 'Recomendado|omite|puerto' | head -6 | sed 's/^/    > /'

expect_eq "termina bien" 0 "$rc"
# `read -p` solo imprime el prompt si la entrada es una terminal, así que la
# pregunta nunca aparece con la entrada alimentada por tubería: se comprueba la
# consecuencia visible (abrir 2222 y luego retirar el 22), que es lo contrario
# de la ruta 12, donde el operador rechaza el consejo.
expect_match "abrió 2222 junto al 22 antes de decidir" "SSH escuchando en:22 2222" "$out"
expect_match "el operador confirmó y se retiró el puerto viejo" "Quitando el puerto 22" "$out"
expect_eq "SSH quedó solo en 2222" "2222" "$(ssh_ports)"
expect_eq "sshd ya no ofrece el 22" "2222" "$(sshd_ports)"
expect_eq "el puerto vive en sshd_config.d" "2222" \
    "$(on_server "awk '/^Port /{print \$2}' /etc/ssh/sshd_config.d/99-hardening.conf | paste -sd, -")"
if [[ "$(socket_activated)" == si ]]; then
    expect_eq "y el socket escucha en el puerto nuevo" "2222" "$(socket_listen)"
fi

expect_login "se entra por 2222" tester 2222
expect_no_login "el 22 quedó cerrado" tester 22

expect_match "UFW permite 2222" "2222" "$(ufw_dump)"
expect_eq "UFW retiró la regla del 22" "" "$(ufw_rules_for 22 ssh)"
expect_match "fail2ban jailed en 2222" "^port     = 2222" "$(f2b_jail)"
expect_eq "sin cuenta atrás pendiente" "" "$(pending_rollbacks)"

scenario_summary
