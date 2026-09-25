#!/usr/bin/env bash
# 02 · Clave malformada: debe abortar ANTES de tocar sshd. Un typo al pegar la
# clave pública es la forma más fácil de quedarse fuera.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

echo "  simulando: el operador pegó una clave truncada"

# La clave con espacios debe llegar como un único argumento, sin comillas literales.
prl0="$(sshd_get permitrootlogin)"
out="$(run_vps --non-interactive --allow-lockdown --no-rollback --yes \
        --user tester --pubkey "ssh-ed25519 AAAAC0RRUPTA" --sudo nopasswd 2>&1)"
rc=$?

expect_eq "el script sale con error" 1 "$rc"
expect_match "explica que ssh-keygen la rechaza" "no es válida|rechaza" "$out"
expect_eq "no escribe configuración de endurecimiento" "no" "$(hardening_exists)"
expect_eq "sshd sigue igual que al empezar" "$prl0" "$(sshd_get permitrootlogin)"
expect_login "root conserva su acceso" root 22
expect_eq "no creó la cuenta de rollback" "" "$(pending_rollbacks)"

echo "  variante: clave con CRLF (archivo .pub copiado desde Windows)"
on_server "printf 'ssh-ed25519 AAAA\r\n' > /tmp/crlf.pub"
out="$(run_vps --non-interactive --allow-lockdown --no-rollback --yes \
        --user tester --pubkey-file /tmp/crlf.pub --sudo nopasswd 2>&1)"
expect_eq "también la rechaza en vez de instalarla" 1 $?
expect_eq "y no deja medio configurar" "no" "$(hardening_exists)"

scenario_summary
