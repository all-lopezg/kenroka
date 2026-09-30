#!/usr/bin/env bash
# 21 · Verificador final: consulta servicios reales, guarda reporte y exige
# confirmación independiente; no reconfigura el VPS ni cancela sus timers.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/lib.sh"

echo '  aplicar el perfil completo en el contenedor de pruebas'
start_admin_session
out="$(run_vps --non-interactive --allow-lockdown --no-rollback --yes \
    --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd --port 2222 2>&1)"; rc=$?
expect_eq 'preparación completa' 0 "$rc"
expect_login 'el cliente realmente entra por el puerto definitivo' tester 2222

# El paquete preinstalado no siempre viene habilitado al arrancar (22.04).
# Forzar ambos estados prueba que runtime activo no basta para aprobarlo.
on_server 'systemctl disable fail2ban' >/dev/null 2>&1
out="$(run_vps --verify --user tester --port 2222 --yes 2>&1)"; rc=$?
expect_eq 'Fail2ban activo pero sin arranque automático queda pendiente' 2 "$rc"
expect_match 'explica persistencia pendiente de Fail2ban' '\[PENDIENTE\].*Fail2ban \(al arrancar\)' "$out"
expect_eq 'el verificador no habilita Fail2ban por su cuenta' disabled "$(on_server 'systemctl is-enabled fail2ban || true')"
# Corrección del operador dentro de la fixture; verificar solo observa.
on_server 'systemctl enable fail2ban' >/dev/null 2>&1

MANIFEST='find /etc/ssh /etc/ufw /etc/fail2ban /etc/apt/apt.conf.d /etc/sudoers.d /etc/systemd/system /home /root/.ssh -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum'
before="$(on_server "$MANIFEST")"
out="$(run_vps --verify --user tester --port 2222 --sudo nopasswd --yes 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -7 | sed 's/^/    /'
expect_eq 'sin declaración humana el resultado es pendiente' 2 "$rc"
expect_match 'las comprobaciones técnicas están aprobadas' '\[OK\].*Puerto protegido por Fail2ban' "$out"
expect_nomatch 'no hay fallos ni pendientes técnicos inesperados' '\[FALLO\]|\[PENDIENTE\]' "$out"
expect_eq 'no modifica configuración ni claves' "$before" "$(on_server "$MANIFEST")"
report="$(on_server 'ls -1t /var/lib/secure-vps/reports/*.txt | head -1')"
expect_eq 'el reporte es privado' 600 "$(on_server "stat -c %a '$report'")"
expect_match 'explica qué falta' 'sin confirmar' "$(on_server "cat '$report'")"
expect_match 'guarda contexto y versión' 'Versión:|Contexto SSH' "$(on_server "cat '$report'")"
expect_eq 'verificar no instala otra cuenta atrás' '' "$(pending_rollbacks)"

# --yes tampoco puede aprobar automáticamente desde una terminal real.
out="$(on_server "script -q -e -c 'bash $SCRIPT --lang es --verify --user tester --port 2222 --yes' /dev/null" 2>&1)"; rc=$?
expect_eq '--yes con terminal sigue pendiente' 2 "$rc"
expect_nomatch 'no pide una confirmación externa con --yes' '¿La prueba funcionó' "$out"

# La conexión y sudo se comprueban de verdad en el cliente antes del token.
on_client 'ssh -p 2222 -i /keys/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null tester@server "sudo -n true"' >/dev/null 2>&1
expect_eq 'sudo funciona desde la nueva conexión del cliente' 0 "$?"
out="$(on_server 'python3 /tests/helpers/verify-pty.py' 2>&1)"; rc=$?
expect_eq 'comprobaciones y declaración final dan éxito' 0 "$rc"
expect_match 'informa resultado exitoso' 'Resultado: EXITOSO' "$out"
report="$(on_server 'ls -1t /var/lib/secure-vps/reports/*.txt | head -1')"
expect_match 'reporte distingue declaración humana' 'declaración del usuario\): confirmados' "$(on_server "cat '$report'")"
expect_eq 'confirmar verificación tampoco cambia la configuración' "$before" "$(on_server "$MANIFEST")"

# El menú sigue disponible después de guardar el reporte. Entrada no-tty no
# intenta atribuir una confirmación externa al Enter ni a --yes.
out="$(run_vps_in '2.3\n\n0\n' --user tester --sudo nopasswd --port 2222 --experto 2>&1)"; rc=$?
expect_eq 'se puede verificar y volver al menú' 0 "$rc"
expect_match 'opción 2.3 visible' '2\.3\).*Verificar el hardening' "$out"
expect_match 'el menú ejecuta el verificador' 'VERIFICACIÓN DEL HARDENING' "$out"
expect_match 'no-tty informa pendientes desde menú' 'Resultado: CON PENDIENTES' "$out"

# Una cuenta atrás real se conserva; no se puede aprobar el estado todavía.
on_server 'systemd-run --unit=secure-vps-rollback-verification-fixture --on-active=1h /bin/true' >/dev/null 2>&1
out="$(on_server 'python3 /tests/helpers/verify-pty.py' 2>&1)"; rc=$?
expect_eq 'cuenta atrás activa impide resultado exitoso' 2 "$rc"
expect_match 'detecta temporizador real pendiente' 'Cuenta atrás pendiente' "$out"
expect_nomatch 'con cuenta atrás no pide aprobación final' '¿La prueba funcionó' "$out"
expect_match 'verificar conserva el temporizador' 'secure-vps-rollback-verification-fixture.timer' "$(pending_rollbacks)"
on_server 'systemctl stop secure-vps-rollback-verification-fixture.timer' >/dev/null

# Alterar solo runtime comprueba que el verificador no se limita a los archivos.
on_server 'systemctl stop fail2ban' >/dev/null
out="$(run_vps --verify --non-interactive --user tester 2>&1)"; rc=$?
expect_eq 'jail/servicio caído produce código de fallo' 1 "$rc"
expect_match 'describe el fallo efectivo' 'Servicio o jail sshd inactivo' "$out"
expect_match 'resultado de fallo no se oculta' 'Resultado: CON FALLOS' "$out"
expect_eq 'verificar no reinicia el servicio caído' inactive "$(on_server 'systemctl is-active fail2ban || true')"

out="$(run_vps --verify --audit --user tester 2>&1)"; rc=$?
expect_eq 'audit y verify no se mezclan' 1 "$rc"
expect_match 'explica modos excluyentes' 'por separado' "$out"
out="$(run_vps --lang en --verify --non-interactive --user tester 2>&1)"
expect_match 'resultado y encabezado en inglés' 'HARDENING VERIFICATION|Result: FAILED' "$out"
expect_nomatch 'no filtra mensajes nuevos en español' 'VERIFICACIÓN|Resultado:|Reporte guardado:' "$out"

scenario_summary
