#!/usr/bin/env bash
# 12 · Ruta interactiva de "no, gracias" en el consejo de cambiar el puerto:
# se recomienda salir del 22, y si el operador rechaza, el resto se aplica igual.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: operador sin flags de automatización que rechaza el 2222"
start_admin_session

# fase 0 's' | fase 3 acceso-ok | fase 4 no abrir puertos, activar UFW, acceso-ok | fase 7 'n'
out="$(run_vps_in 's\nacceso-ok\nn\ns\nacceso-ok\nn\n' --run-all \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina bien pese a rechazar el consejo" 0 "$rc"
expect_match "había recomendado salir del 22" "22|2222" "$out"
expect_match "registra que se omite el cambio" "Omitiendo|Skipping" "$out"
expect_eq "SSH sigue en el puerto original" "22" "$(ssh_ports)"
expect_eq "sshd sigue configurado en 22" "22" "$(sshd_ports)"
expect_eq "el cierre de acceso sí se aplicó" "no" "$(sshd_get permitrootlogin)"
expect_eq "y la contraseña quedó desactivada" "no" "$(sshd_get passwordauthentication)"
expect_login "el usuario indicado entra por 22" tester 22
expect_no_login "root sigue afuera" root 22
expect_eq "UFW quedó activo igual" "Status: active" "$(ufw_active)"
expect_match "UFW permite el 22" "(^|[[:space:]])22(/tcp)?([[:space:]]|\(|$)" "$(ufw_dump)"
expect_eq "no quedó cuenta atrás pendiente" "" "$(pending_rollbacks)"
expect_nomatch "no se creó el drop-in del 2222" "2222" "$(ufw_dump)"

scenario_summary
