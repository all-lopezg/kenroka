#!/usr/bin/env bash
# 09 · Root directo sin usuario alternativo: check_original_user() rechaza
# cerrar el acceso, porque no queda nadie con quien entrar si algo falla.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: ssh a la consola del proveedor y 'bash secure-vps.sh' como root"
FLAGS="--lang es --non-interactive --yes --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd --allow-lockdown --no-rollback"
prl0="$(sshd_get permitrootlogin)"

out="$(on_server "bash $SCRIPT $FLAGS" 2>&1)"; rc=$?
expect_eq "se niega a cerrar el acceso" 1 "$rc"
expect_match "explica por qué" "Root directo en modo no interactivo" "$out"
expect_eq "y no tocó sshd" "$prl0" "$(sshd_get permitrootlogin)"
expect_login "root conserva su sesión" root 22

echo "  con --skip-lockdown el mismo origen root sí es aceptable (no cierra nada)"
out="$(on_server "bash $SCRIPT $FLAGS --skip-lockdown" 2>&1)"; rc=$?
expect_eq "pasa la comprobación del lanzador" 0 "$rc"
expect_nomatch "no queja de root directo" "no hay garantía" "$out"
expect_eq "aun así deja el acceso abierto" "$prl0" "$(sshd_get permitrootlogin)"
expect_login "root sigue entrando" root 22

echo "  y con sudo desde un usuario, el cierre sí procede"
out="$(run_vps $FLAGS </dev/null 2>&1)"; rc=$?
expect_eq "SUDO_USER=ubuntu desbloquea el cierre" 0 "$rc"
expect_match "el opt-out advierte que cierra sin prueba humana" "allow-lockdown:.*sin prueba humana" "$out"
expect_eq "ahora sí cerró root" "no" "$(sshd_get permitrootlogin)"
expect_no_login "root ya no entra" root 22
expect_login "tester sí" tester 22

echo "  y si el equipo se queda solo con root, lo dice claro y pregunta"
# El VPS recién creado no tiene otro usuario: se imita quitándole el shell a
# todos los que quedan (ubuntu del proveedor y tester, creado arriba). Si se
# deja uno con shell, la rama correcta es la de "ya hay otros usuarios".
sha_h="$(on_server "sha256sum /etc/ssh/sshd_config.d/99-hardening.conf | awk '{print \$1}'")"
on_server "usermod -s /usr/sbin/nologin ubuntu; usermod -s /usr/sbin/nologin tester" >/dev/null
out4="$(on_server_in 'n\n' "bash $SCRIPT --lang es --run-all --user testigo \
        --pubkey-file /keys/id_ed25519.pub --sudo nopasswd" 2>&1)"; rc4=$?
on_server "usermod -s /bin/bash ubuntu; usermod -s /bin/bash tester" >/dev/null

expect_eq "un 'no' detiene la corrida sin error" 0 "$rc4"
expect_match "dice que solo existe root" "solo existe root" "$out4"
expect_match "explica que la fase 1 crea el usuario" "La fase 1 crea un usuario administrador" "$out4"
# La pregunta en sí no se puede ver aquí: `read -p` solo imprime el prompt si la
# entrada es terminal. Su texto está cubierto en el unitario.
expect_match "al negarse, no toca nada" "no toco nada" "$out4"
expect_eq "el usuario testigo no fue creado" "" "$(on_server "id -u testigo 2>/dev/null || true")"
expect_eq "y la config de endurecido quedó intacta" "$sha_h" \
    "$(on_server "sha256sum /etc/ssh/sshd_config.d/99-hardening.conf | awk '{print \$1}'")"

scenario_summary
