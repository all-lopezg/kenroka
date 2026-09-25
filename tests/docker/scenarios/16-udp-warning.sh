#!/usr/bin/env bash
# 16 · La fase 4 avisa por TCP y por UDP: un servicio UDP sin regla (WireGuard,
# DNS, VoIP) quedaría filtrado por deny incoming igual que uno TCP. También
# comprueba que lo que escucha solo en loopback no se marca como riesgo.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: un DNS local en 5353/udp además del HTTP de pruebas"
start_admin_session
on_server "nohup socat -u UDP4-LISTEN:5353,fork,reuseaddr /dev/null >/dev/null 2>&1 & sleep 1; echo ok" >/dev/null
expect_eq "el 5353/udp está a la escucha" "si" \
    "$(on_server "ss -Huln | grep -qE ':5353\b' && echo si || echo no")"

echo "  primera pasada (--yes): avisa de ambos, no abre nada"
out="$(run_vps_in 'acceso-ok\n' --run-all --yes --skip-lockdown \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -E 'escucha|puertos:' | head -4 | sed 's/^/    > /'

expect_eq "termina bien" 0 "$rc"
expect_match "lista el riesgo del TCP 80" "sudo ufw allow 80/tcp" "$out"
expect_match "lista el riesgo del UDP 5353" "sudo ufw allow 5353/udp" "$out"
expect_match "el aviso agrupa ambos protocolos" "estos puertos: 80 5353" "$out"
expect_match "UFW quedó activo" "Status: active" "$(ufw_active)"
expect_nomatch "con --yes el 5353/udp sigue filtrado" "5353/udp" "$(ufw_dump)"
expect_nomatch "y el 80/tcp también" "80/tcp" "$(ufw_dump)"

echo "  segunda pasada (interactiva): acepta abrirlos"
out2="$(run_vps_in 's\ns\nn\n' --run-all --skip-lockdown \
        --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd 2>&1)"
rc2=$?
expect_eq "termina bien" 0 "$rc2"
expect_match "abre el puerto TCP preguntado" "Puerto 80 permitido" "$out2"
expect_match "abre el puerto UDP preguntado" "Puerto 5353 permitido" "$out2"
expect_match "y el 5353/udp queda con regla" "5353/udp" "$(ufw_dump)"
expect_match "junto al 80/tcp" "80/tcp" "$(ufw_dump)"

scenario_summary
