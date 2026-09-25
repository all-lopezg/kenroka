#!/usr/bin/env bash
# 14 · Novato en la consola web del proveedor: llegó sin clave, no tiene como
# probar una conexión SSH nueva desde ahí. El script debe aplicar TODO menos el
# cierre del acceso, y decirle qué hacer después.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: sesión de consola (docker exec, sin SSH) y sin --pubkey"
# Sin start_admin_session a propósito: así detect_session_kind ve consola.
prl0="$(sshd_get permitrootlogin)"

# fase 0 's' | fase 2 elige la clave autorizada número 1 | fase 4 no abrir
# puertos, activar UFW. Nada más: en consola no se pide acceso-ok ni puerto.
out="$(run_vps_in 's\n1\nn\ns\n' --run-all --user tester --sudo nopasswd 2>&1)"
rc=$?

expect_eq "termina bien" 0 "$rc"
expect_match "avisa de que está en la consola" "consola del proveedor" "$out"
expect_match "reutiliza una clave ya autorizada" "Reutilizando la clave número" "$out"
expect_match "fase 3 en modo suave" "MODO SUAVE" "$out"
expect_eq "no cerró root" "$prl0" "$(sshd_get permitrootlogin)"
expect_eq "y dejó la contraseña activa" "yes" "$(sshd_get passwordauthentication)"
expect_eq "SSH sigue en el 22" "22" "$(ssh_ports)"
expect_match "no ofrece cambiar el puerto desde la consola" "no puedo probar el puerto nuevo" "$out"
expect_match "UFW sí se activó" "Status: active" "$(ufw_active)"
expect_match "fail2ban sí quedó configurado" "^port     = 22" "$(f2b_jail)"
expect_match "avisa que no podrá excluir su IP" "Añádela a mano" "$out"

# La tarjeta final: cómo entrar y qué hacer si se queda fuera.
expect_match "le dice cómo entrar mañana" "Cómo entrar mañana" "$out"
expect_match "y que se pone contraseña de sistema" "sudo passwd tester" "$out"

# La cuenta atrás de la fase 4 queda armada a propósito (nadie pudo probar).
expect_eq "queda una cuenta atrás pendiente" "1" "$( [[ -n "$(pending_rollbacks)" ]] && echo 1 || echo 0)"

# Volver a ejecutar con esa cuenta viva no puede ser un callejón sin salida:
# en desatendido se niega y explica; con terminal ofrece cancelarla y seguir.
out2="$(run_vps_in 's\n' --run-all --yes --user tester --sudo nopasswd 2>&1)"; rc2=$?
expect_eq "con --yes no la cancela por su cuenta" 1 "$rc2"
expect_match "y dice por qué" "Modo desatendido" "$out2"
expect_match "nombra la cuenta pendiente" "secure-vps-rollback-" "$out2"
expect_eq "sigue pendiente tras negarse" "1" "$( [[ -n "$(pending_rollbacks)" ]] && echo 1 || echo 0)"

out3="$(run_vps_in 's\ns\n1\nn\n' --run-all --user tester --sudo nopasswd 2>&1)"; rc3=$?
expect_eq "con terminal cancela y continúa" 0 "$rc3"
expect_match "explica que era de una ejecución anterior" "cuenta atrás pendiente de una ejecución anterior" "$out3"
expect_eq "ya no queda cuenta atrás" "" "$(pending_rollbacks)"

expect_login "la clave reutilizada sirve para entrar" tester 22

scenario_summary
