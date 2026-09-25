#!/usr/bin/env bash
# 01 · --skip-lockdown: prepara usuario, clave, UFW y fail2ban SIN cerrar el
# acceso. Es lo que se corre en un VPS que aún no probaste con otra ventana.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: VPS recién entregado, root con clave y contraseña activas"

start_admin_session
# El valor por defecto cambia entre versiones de OpenSSH (prohibit-password /
# without-password): se captura antes, no se hardcodea.
prl0="$(sshd_get permitrootlogin)"

out="$(run_vps --non-interactive --skip-lockdown --yes \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina sin errores" 0 "$rc"
expect_eq "escribe el archivo de endurecimiento" "si" "$(hardening_exists)"
expect_eq "aplica MaxAuthTries" "3" "$(hardening_get MaxAuthTries)"
expect_eq "aplica ClientAliveInterval" "300" "$(hardening_get ClientAliveInterval)"

# Lo que NO puede haber tocado:
expect_eq "no deshabilita el login de root" "$prl0" "$(sshd_get permitrootlogin)"
expect_eq "no toca la nube: cloud-init sigue en yes" "yes" "$(sshd_get passwordauthentication)"
expect_eq "no escribe AllowUsers" "" "$(hardening_get AllowUsers)"
expect_login "root sigue entrando con clave" root 22
# La contraseña se prueba con el usuario del proveedor: PermitRootLogin
# without-password ya bloquea la de root en un Ubuntu sin tocar.
if ssh_login_password ubuntu 22 'semilla-test'; then
    ok "la contraseña del usuario del proveedor sigue abriendo SSH"
else
    bad "en modo suave no debería cerrarse la autenticación por contraseña"
fi

# El bug original: usuario en grupo sudo pero con adduser --disabled-password.
expect_match "tester existe" "^[0-9]+$" "$(on_server "id -u tester 2>/dev/null")"
expect_match "tester está en sudo" "sudo" "$(on_server "groups tester 2>/dev/null")"
expect_eq "tester puede hacer sudo real (NOPASSWD)" "0" \
    "$(on_server "su - tester -c 'sudo -n id -u' 2>/dev/null")"
expect_match "su clave quedó instalada" "ssh-ed25519" \
    "$(on_server "cat /home/tester/.ssh/authorized_keys 2>/dev/null")"

scenario_summary
