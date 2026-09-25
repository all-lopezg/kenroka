#!/usr/bin/env bash
# 19 · --audit: el reporte promete no tocar nada, y esa promesa es lo que se
# prueba aquí. Se toma una huella sha256 de todo lo que el endurecido escribe
# (sshd, UFW, fail2ban, systemd, homes, snapshots, log), se corre la auditoría
# y la huella tiene que salir idéntica. Lo que dice el reporte se prueba en las
# unitarias; aquí se comprueba además que no pregunta nada y que sale 0.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

# Todo lo que secure-vps.sh puede llegar a modificar, en una sola huella.
# Una sola linea: 'bash -lc' ejecutaria cada renglon como comando aparte.
MANIFEST='find /etc/ssh /root/.ssh /home /etc/ufw /etc/fail2ban /etc/default/ufw'
MANIFEST="$MANIFEST /etc/systemd/system /etc/apt/apt.conf.d /etc/sudoers.d"
MANIFEST="$MANIFEST /var/lib/secure-vps /var/log/secure-vps.log"
MANIFEST="$MANIFEST /usr/local/bin/secure-vps-rollback"
MANIFEST="$MANIFEST -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum"
if [[ -z "$(on_server "$MANIFEST")" ]]; then
    bad "la huella no lista archivos: el escenario no probaria nada"
    scenario_summary; exit 1
fi
# El primer 'sudo' de un usuario crea ~/.sudo_as_admin_successful (es de Ubuntu,
# no del script). Se provoca antes de la huella base para que la comparacion sea
# estricta: si aparece algo nuevo despues de auditar, es del script.
on_server "runuser -u ubuntu -- sudo -n true" >/dev/null 2>&1
manifest() { on_server "$MANIFEST"; }
exists()   { on_server "test -e $1 && echo si || echo no"; }

echo "  sobre un VPS recién sembrado"
before="$(manifest)"
if [[ -z "$before" ]]; then
    bad "no se pudo tomar la huella inicial; el escenario pierde su sentido"
    scenario_summary; exit 1
fi
ok "huella inicial tomada ($(printf '%s\n' "$before" | grep -c .) archivos)"

out="$(run_vps --audit 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -E '^\s*\[[0-9]/8\]|hallazgo|Hallazgos' | sed 's/^/    > /'

expect_eq "sale 0" 0 "$rc"
expect_eq "la huella del sistema es idéntica" "$before" "$(manifest)"
expect_eq "no creó el arbol de snapshots" "no" "$(exists /var/lib/secure-vps/snapshots)"
expect_eq "no instaló el binario de rollback" "no" "$(exists /usr/local/bin/secure-vps-rollback)"
expect_eq "no dejó ningún sshd_config.bak" "no" \
    "$(on_server "ls /etc/ssh/sshd_config.bak.* >/dev/null 2>&1 && echo si || echo no")"
expect_eq "no escribió el log de la herramienta" "no" \
    "$(on_server "test -s /var/log/secure-vps.log && echo si || echo no")"
expect_eq "no armó cuenta atrás" "" "$(pending_rollbacks)"
expect_eq "no cambió el estado de UFW" "no" \
    "$(on_server "ufw status 2>/dev/null | grep -q 'Status: active' && echo si || echo no")"

echo "  qué se ve en el reporte"
expect_match "abre con el banner" "secure-vps v" "$out"
expect_match "dice que es de solo lectura" "AUDITORÍA DE SOLO LECTURA" "$out"
expect_match "enumera las ocho secciones" "\[8/8\]" "$out"
expect_match "reporta la versión de Ubuntu" "\[1/8\]" "$out"
expect_match "nombra al usuario del proveedor" "ubuntu" "$out"
expect_match "avisa del puerto 22" "SSH sigue en el 22" "$out"
expect_match "marca UFW inactivo" "UFW inactivo" "$out"
expect_match "lista el 80 expuesto por la semilla" "sudo ufw allow 80/tcp" "$out"
expect_match "no sale a internet a buscar la IP publica" "no hace peticiones salientes" "$out"
expect_match "reporta el jail sshd servido" "jail sshd" "$out"
expect_match "y que nadie esta excluido del ban" "sin excluir" "$out"
expect_match "cierra con los hallazgos numerados" "  1\) " "$out"
expect_match "propone el comando con el usuario detectado" \
    "sudo bash /opt/secure-vps.sh --port 2222 --user ubuntu" "$out"
expect_match "y recuerda que no escribió nada" "--audit solo lee" "$out"
expect_nomatch "no corre ninguna fase" "FASE 1:|Snapshot guardado|Backup creado|UFW activado" "$out"
expect_nomatch "no hace ninguna pregunta" "Presiona Enter|¿Continuar|acceso-ok" "$out"
expect_nomatch "no deja el menú en pantalla" "Elige una opción" "$out"

echo "  en inglés, y dos corridas seguidas"
out2="$(run_vps --lang en --audit 2>&1)"
expect_eq "sale 0" 0 "$?"
expect_match "el titulo cambia de idioma" "READ-ONLY AUDIT" "$out2"
expect_match "la seccion final tambié" "Findings" "$out2"
expect_nomatch "no queda español en las cabeceras" "Hallazgos|AUDITORÍA" "$out2"
expect_eq "la segunda corrida tampoco tocó nada" "$before" "$(manifest)"

echo "  sin root se niega antes de leer nada"
out3="$(on_server "runuser -u ubuntu -- bash $SCRIPT --audit 2>&1"; echo "rc=$?")"
expect_match "pide sudo" "must run as root|debe ejecutarse como root" "$out3"
expect_match "y sale con error" "rc=1" "$out3"
expect_eq "aun asi no dejo archivos nuevos" "$before" "$(manifest)"

echo "  la auditoría también está dentro del menú (opción 12)"
out5="$(run_vps_in '12\n\n0\n' --skip-lockdown --user tester \
        --pubkey-file /keys/id_ed25519.pub --sudo nopasswd --experto 2>&1)"
expect_eq "el menú la ofrece" 0 "$?"
expect_match "se ve el reporte desde el menú" "AUDITORÍA DE SOLO LECTURA" "$out5"
expect_match "y el menu sigue disponible despues" "Revertir al último snapshot" "$out5"

echo "  sobre un VPS ya endurecido (misma auditoría, otro diagnóstico)"
start_admin_session
hard="$(run_vps_in 'acceso-ok\n' --run-all --yes --skip-lockdown \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
expect_eq "el endurecido terminó bien" 0 "$?"
expect_match "UFW quedó activo" "Status: active" "$(ufw_active)"
mid="$(manifest)"
out4="$(run_vps --audit 2>&1)"
expect_eq "la auditoría no deshizo nada" "$mid" "$(manifest)"
expect_nomatch "ya no avisa de UFW inactivo" "UFW inactivo" "$out4"
expect_match "reconoce el snapshot guardado" "snapshots" "$out4"
expect_match "y el archivo de endurecido" "99-hardening.conf" "$out4"
expect_match "menciona al usuario creado" "tester" "$out4"
expect_match "sigue avisando del 22 mientras ese sea el puerto" "SSH sigue en el 22" "$out4"
expect_nomatch "tras endurecer, ignoreip ya no esta vacio" "sin excluir" "$out4"

echo "  la ayuda documenta el modo"
h="$(on_server "bash $SCRIPT --lang es --help 2>&1")"
expect_match "--audit aparece en español" -- "--audit" "$h"
expect_match "explica que no escribe" "No escribe nada" "$h"
h="$(on_server "bash $SCRIPT --lang en --help 2>&1")"
expect_match "--audit aparece en inglés" -- "--audit" "$h"
expect_match "y su contrato en inglés" "Writes nothing" "$h"

scenario_summary
