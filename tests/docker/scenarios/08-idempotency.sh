#!/usr/bin/env bash
# 08 · Idempotencia: volver a correr el endurecimiento completo no puede romper
# el acceso ni dejar reglas duplicadas. Es lo que pasa cuando alguien lo ejecuta
# dos veces o Ansible lo re-aplica.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

CMD_ARGS=(--run-all --yes --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd --port 2222)
# Sesión SSH viva durante las dos pasadas: sin ella el script cree estar en la
# consola del proveedor y omite cierre y cambio de puerto.
start_admin_session

echo "  primera pasada"
out1="$(run_vps_in 'acceso-ok\nacceso-ok\nacceso-ok\n' "${CMD_ARGS[@]}" 2>&1)"; rc1=$?
expect_eq "primera pasada ok" 0 "$rc1"
state1="$(on_server "sshd -T | grep -E '^(permitrootlogin|passwordauthentication|allowusers|maxauthtries)' | sort")"
ports1="$(ssh_ports)"
rules1="$(ufw_rules)"
expect_eq "se pudo consultar las reglas iniciales de UFW" 0 "$?"
expect_match "el conteo inicial incluye reglas de acceso" "^[1-9][0-9]*$" "$rules1"

echo "  segunda pasada sobre el mismo servidor"
out2="$(run_vps_in 'acceso-ok\nacceso-ok\nacceso-ok\n' "${CMD_ARGS[@]}" 2>&1)"; rc2=$?
expect_eq "segunda pasada también termina bien" 0 "$rc2"
expect_match "reconoce que el usuario ya existe" "ya existe" "$out2"
expect_match "reconoce que la clave ya estaba" "ya estaba" "$out2"
expect_match "reconoce que UFW ya está activo" "ya está activo" "$out2"

state2="$(on_server "sshd -T | grep -E '^(permitrootlogin|passwordauthentication|allowusers|maxauthtries)' | sort")"
expect_eq "la config efectiva no cambió" "$state1" "$state2"
expect_eq "los puertos ssh en escucha no cambiaron" "$ports1" "$(ssh_ports)"
expect_eq "ssh sigue escuchando en 2222" "2222" "$(ssh_ports)"
rules2="$(ufw_rules)"
expect_eq "se pudo consultar las reglas finales de UFW" 0 "$?"
expect_eq "UFW no acumuló reglas de más" "$rules1" "$rules2"
expect_login "el acceso sobrevive a la repetición" tester 2222
expect_no_login "root sigue afuera" root 2222

scenario_summary
