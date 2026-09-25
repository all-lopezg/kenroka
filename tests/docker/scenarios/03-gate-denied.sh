#!/usr/bin/env bash
# 03 · La puerta de acceso: el operador NO confirma poder entrar con la clave
# nueva. El script debe cerrar, detectar que no hay confirmación y REVERTIR.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: 'no, todavía no puedo entrar con esa clave'"
# Sesión SSH real del "operador": sin ella el script asume consola del
# proveedor y ni siquiera llega al cierre que esta escena quiere probar.
start_admin_session

before_ports="$(sshd_ports)"
prl0="$(sshd_get permitrootlogin)"
n_before="$(list_snapshots)"

out="$(run_vps_in 'acceso-no-dado\n' --run-all --yes \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -iE 'revierto|revierte|rollback' | head -5 | sed 's/^/    > /'

expect_match "anuncia la cuenta atrás antes de cerrar" "Cuenta atrás armada" "$out"
expect_match "revertirá al no recibir el token" "No confirmaste el acceso" "$out"
expect_eq "sale con código de error (un revert no es un éxito)" 1 "$rc"
expect_eq "el acceso queda como estaba: root sigue entrando" 0 "$(ssh_login root 22 >/dev/null 2>&1; echo $?)"
expect_eq "PasswordAuthentication vuelve a yes" "yes" "$(sshd_get passwordauthentication)"
expect_eq "PermitRootLogin vuelve a su valor por defecto" "$prl0" "$(sshd_get permitrootlogin)"
expect_eq "el puerto de escucha no cambió" "$before_ports" "$(sshd_ports)"
expect_eq "dejó un snapshot para el historial" "$((n_before + 1))" "$(list_snapshots)"
expect_eq "ningún snapshot quedó confirmado" "0" "$(confirmed_snaps)"
expect_eq "instaló el binario de rollback" "si" "$(rollback_bin_present)"
expect_eq "canceló la cuenta atrás al revertir" "" "$(pending_rollbacks)"

scenario_summary
