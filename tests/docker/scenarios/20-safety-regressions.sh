#!/usr/bin/env bash
# 20 · Snapshots entre fases, confirmación tardía y transición real de sudo.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/lib.sh"
out="$(on_server 'bash /tests/safety-regressions.sh' 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -12 | sed 's/^/    /'
expect_eq "las regresiones pasan con servicios reales" 0 "$rc"
expect_match "el fallo posterior revierte UFW" 'snapshot-pendiente: OK' "$out"
expect_match "se rechaza la confirmación tardía" 'confirmacion-tardia: OK' "$out"
expect_match "la finalización mantiene el bloqueo" 'finalizacion-protegida: OK' "$out"
expect_match "sudo vuelve a pedir contraseña" 'sudo-contrasena: OK' "$out"
expect_login "el puerto confirmado permite entrar" tester 2222
scenario_summary
