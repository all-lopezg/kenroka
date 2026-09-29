#!/usr/bin/env bash
# 22 · La guía no debe aceptar una palabra pregrabada como evidencia: este
# escenario abre una conexión real desde client antes de responder cada uno de
# los tres checkpoints (preprueba, SSH endurecido y UFW activo).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo '  guiando cada checkpoint tras una conexión SSH real desde client'
start_admin_session

out="$(python3 "$HERE/helpers/guided-access-pty.py" "$COMPOSE" 2>&1)"; rc=$?
printf '%s\n' "$out" | grep -E 'PRUEBA (PREVIA|DE ACCESO)|segunda prueba|HARDENING DEL ACCESO' | head -8 | sed 's/^/    > /'

expect_eq 'el flujo guiado termina tras tres pruebas reales' 0 "$rc"
expect_match 'explica la preprueba antes del cierre' 'prueba PREVIA' "$out"
expect_match 'explica la prueba posterior al firewall' 'segunda prueba|UFW ya está activo' "$out"
expect_match 'muestra el comando con autenticación por clave' 'PasswordAuthentication=no' "$out"
expect_match 'declara el hardening completado solo al final' 'HARDENING DEL ACCESO COMPLETADO' "$out"
expect_eq 'root queda cerrado' no "$(sshd_get permitrootlogin)"
expect_eq 'la contraseña SSH queda cerrada' no "$(sshd_get passwordauthentication)"
expect_login 'la conexión real sigue entrando tras UFW' tester 22
expect_eq 'no queda protección temporal pendiente' '' "$(pending_rollbacks)"

scenario_summary
