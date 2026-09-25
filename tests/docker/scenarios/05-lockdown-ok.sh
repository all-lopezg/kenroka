#!/usr/bin/env bash
# 05 · Camino feliz completo: clave válida, operador que confirma desde otra
# ventana, y el cierre queda permanente. Es el estado final de un VPS sano.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: 'ya tengo otra sesión abierta y funciona'"
start_admin_session
ADMIN_IP="$(client_ip)"

out="$(run_vps_in 'acceso-ok\nacceso-ok\n' --run-all --yes \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina bien" 0 "$rc"
# Sin --port la fase 7 ni se llama (run_all_fases la salta), así que se comprueba
# la consecuencia: el puerto no se movió.
expect_eq "el puerto sigue siendo el 22" "22" "$(ssh_ports)"
expect_eq "cancela la cuenta atrás al confirmar" "" "$(pending_rollbacks)"
expect_eq "confirma los snapshots de SSH y de activación UFW" "2" "$(confirmed_snaps)"

expect_eq "PermitRootLogin=no"            "no"  "$(sshd_get permitrootlogin)"
expect_eq "PasswordAuthentication=no"     "no"  "$(sshd_get passwordauthentication)"
expect_eq "AllowUsers=tester"             "tester" "$(sshd_get allowusers)"
expect_eq "MaxAuthTries=3"                "3"   "$(sshd_get maxauthtries)"
expect_eq "el cloud-init deja de reabrir la contraseña" "no" \
    "$(on_server "awk '/^PasswordAuthentication/{print \$2}' /etc/ssh/sshd_config.d/50-cloud-init.conf")"

expect_login "tester entra con clave" tester 22
expect_no_login "root ya no entra" root 22
if ssh_login_password ubuntu 22 'semilla-test'; then
    bad "aceptó contraseña del usuario del proveedor, y eso era lo que había que cerrar"
else
    ok "la contraseña ya no abre SSH (sudo usa la suya propia, por otro canal)"
fi

echo "    ufw: $(ufw_active)"
expect_match "UFW activo" "Status: active" "$(ufw_active)"
expect_match "regla para el 22" "22" "$(ufw_dump)"
expect_eq "--yes no abrió el 80 por detrás" "" "$(ufw_rules_for 80 http)"

echo "    fail2ban: $(f2b_status)"
expect_match "jail sshd corriendo" "Status for the jail: sshd" "$(f2b_status)"
expect_match "el jail apunta al 22" "^port     = 22$" "$(f2b_jail)"
expect_match "excluye la IP del administrador conectado ($ADMIN_IP)" "$ADMIN_IP" "$(f2b_jail)"
expect_match "backend coherente con los logs disponibles" "^backend  = (systemd|auto)$" "$(f2b_jail)"

scenario_summary
