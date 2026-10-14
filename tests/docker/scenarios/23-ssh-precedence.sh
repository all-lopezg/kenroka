#!/usr/bin/env bash
# 23 · Precedencia, migración del drop-in legado, Match y rollback reales.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/lib.sh"
out="$(on_server 'bash /tests/ssh-precedence-regressions.sh' 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -12 | sed 's/^/    /'
expect_eq 'las regresiones SSH pasan con servicios reales' 0 "$rc"
expect_match 'aplica políticas antes del proveedor y migra puertos' 'precedencia-y-migracion: OK' "$out"
expect_match 'bloques Match incompatibles detienen el cierre' 'match-incompatible: OK' "$out"
expect_match 'rollback recupera configuración y archivo legado exactos' 'restauracion-de-migracion: OK' "$out"
expect_eq 'archivo nuevo retirado tras restauración' no "$(hardening_exists)"
expect_eq 'el puerto original sigue escuchando' 22 "$(ssh_ports)"
expect_eq 'vuelve la política anterior de contraseñas' yes "$(sshd_get passwordauthentication)"
expect_login 'administrador conserva entrada tras restaurar la migración' tester 22
scenario_summary
