#!/usr/bin/env bash
# 24 · Release estable pública: comando exacto del usuario y guía completa.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/lib.sh"
start_admin_session
out="$(python3 "$HERE/helpers/public-installer-pty.py" "$COMPOSE" menu 2>&1)"; rc=$?
expect_eq 'el comando exacto abre el menú y permite salir' 0 "$rc"
expect_match 'descarga la release estable corregida' 'Resolved version: 1.5.1|Versión resuelta: 1.5.1' "$out"
expect_match 'verifica firma pública real' 'Signature valid|Firma válida' "$out"
expect_match 'verifica checksum público real' 'secure-vps.sh: OK' "$out"
expect_eq 'abrir el menú no endurece el servidor' no "$(hardening_exists)"
# Probar el mismo instalador con el conflicto del proveedor y guía automatizada.
on_server "printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > /etc/ssh/sshd_config.d/00-provider.conf; sed -i '1i PasswordAuthentication yes' /etc/ssh/sshd_config"
out="$(python3 "$HERE/helpers/public-installer-pty.py" "$COMPOSE" guided 2>&1)"; rc=$?
printf '%s\n' "$out" | grep -E 'resuelta:|Firma válida|secure-vps.sh: OK|Escribiendo /etc/ssh|HARDENING DEL ACCESO' | sed 's/^/    /'
expect_eq 'la guía desde la release pública pasa tres pruebas SSH y sudo reales' 0 "$rc"
expect_match 'usa el archivo de políticas corregido' 'Escribiendo /etc/ssh/secure-vps.conf' "$out"
expect_match 'termina el cierre confirmado' 'HARDENING DEL ACCESO COMPLETADO' "$out"
expect_eq 'root queda cerrado' no "$(sshd_get permitrootlogin)"
expect_eq 'contraseñas SSH quedan cerradas' no "$(sshd_get passwordauthentication)"
expect_login 'administrador sigue entrando tras UFW' tester 22
expect_match 'UFW activo' 'Status: active' "$(ufw_active)"
expect_match 'Fail2ban activo' 'Status for the jail: sshd' "$(f2b_status)"
expect_eq 'ninguna protección temporal pendiente' '' "$(pending_rollbacks)"
scenario_summary
