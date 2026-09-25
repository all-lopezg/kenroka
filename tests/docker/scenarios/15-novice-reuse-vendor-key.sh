#!/usr/bin/env bash
# 15 · Novato conectado por SSH (el caso normal) que no pasó --pubkey: el script
# le ofrece la clave con la que ya entró al crear el VPS, la reutiliza y sí puede
# cerrar el acceso, porque la prueba de la conexión nueva sí es posible.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: sin clave por flag, sesión SSH real, elige la clave 1"
start_admin_session

# fase 0 's' | fase 2 número de clave | fase 3 acceso-ok | fase 4 no abrir
# puertos, activar UFW, acceso-ok | fase 7 rechaza el consejo
out="$(run_vps_in 's\n1\nacceso-ok\nn\ns\nacceso-ok\nn\n' --run-all \
        --user tester --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina bien" 0 "$rc"
expect_nomatch "no avisa de consola del proveedor" "Esta sesión viene de la consola" "$out"
expect_match "reutiliza la clave ya autorizada" "Reutilizando la clave número 1" "$out"
expect_eq "cerró root" "no" "$(sshd_get permitrootlogin)"
expect_eq "desactivó la contraseña" "no" "$(sshd_get passwordauthentication)"
expect_eq "y AllowUsers quedó en el usuario nuevo" "tester" "$(sshd_get allowusers)"
expect_login "la clave reutilizada entra" tester 22
expect_no_login "root ya no entra" root 22
expect_match "UFW activo" "Status: active" "$(ufw_active)"
expect_match "jail en el puerto en uso" "^port     = 22" "$(f2b_jail)"
expect_eq "sin cuenta atrás pendiente" "" "$(pending_rollbacks)"
expect_match "la tarjeta final dice cómo entrar" "Cómo entrar mañana" "$out"
expect_match "y manda respaldar la clave privada" "Respalda la clave privada" "$out"
# Con --sudo nopasswd el usuario no queda con contraseña de sistema: la guía
# tiene que decirle que se la ponga, porque es su única salida por consola.
expect_match "y le manda poner contraseña de sistema" "sudo passwd tester" "$out"

scenario_summary
