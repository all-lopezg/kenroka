#!/usr/bin/env bash
# Unit 01: argumentos, validación de clave pública y borrado de reglas UFW.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

error() { printf '    [error] %s\n' "$*" >&2; }
info()  { :; }
warn()  { :; }
success() { :; }
usage() { :; }
LOG_FILE="$WORK/out.log"

extract_fns is_port require_val validate_pubkey _pubkey_normalize resolve_pubkey ufw_purge_port ui

echo "== is_port"
for p in 1 22 2222 65535; do
    if is_port "$p"; then ok "acepta $p"; else bad "rechaza $p indebidamente"; fi
done
for p in 0 65536 22a "" "-1" "80 443"; do
    if is_port "$p"; then bad "debería rechazar '$p'"; else ok "rechaza '$p'"; fi
done

echo "== require_val"
if (require_val --port 2222) 2>/dev/null; then ok "con valor pasa"; else bad "con valor falla"; fi
for args in "--port" "--port "; do
    # shellcheck disable=SC2086
    if (require_val $args) 2>/dev/null; then bad "debería fallar con '$args'"; else ok "falla con '$args'"; fi
done

echo "== resolve_pubkey"
KEYFILE="$WORK/id_ed25519.pub"
if ! ssh-keygen -t ed25519 -N "" -C test@kenroka -f "$WORK/id_ed25519" -q 2>/dev/null; then
    echo "  ssh-keygen no disponible: salto este bloque"
else
    KEY="$(cat "$KEYFILE")"

    SSH_PUBKEY="  $KEY  "; PUBKEY_FILE=""
    resolve_pubkey
    check "recorta espacios sobrantes" "$KEY" "$SSH_PUBKEY"

    printf '# comentario\n\n%s\n' "$KEY" > "$WORK/pk.pub"
    SSH_PUBKEY=""; PUBKEY_FILE="$WORK/pk.pub"
    resolve_pubkey
    check "lee archivo y salta comentarios" "$KEY" "$SSH_PUBKEY"

    printf '%s\r\n' "$KEY" > "$WORK/crlf.pub"
    SSH_PUBKEY=""; PUBKEY_FILE="$WORK/crlf.pub"
    resolve_pubkey
    check "tolera CRLF de archivo copiado desde Windows" "$KEY" "$SSH_PUBKEY"

    printf '%s\n' "$KEY" | { SSH_PUBKEY=""; PUBKEY_FILE="-"; resolve_pubkey; check "acepta clave por stdin" "$KEY" "$SSH_PUBKEY"; }
fi

echo "== validate_pubkey"
if [[ -n "${KEY:-}" ]]; then
    validate_pubkey "$KEY" && ok "clave real aceptada" || bad "clave real rechazada"
    [[ -n "${VALID_FINGERPRINT:-}" ]] && ok "devuelve huella ($VALID_FINGERPRINT)" || bad "sin huella"
fi
for garbage in "ssh-ed25519 AAAAC0RRUPTA" "no-es-clave" "ssh-rsa" "echo hola"; do
    if validate_pubkey "$garbage" 2>/dev/null; then bad "acepta basura: '$garbage'"; else ok "rechaza '$garbage'"; fi
done

echo "== ufw_purge_port (ufw allow ssh != ufw delete allow 22/tcp)"
SAMPLE='Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] ssh                        ALLOW IN    Anywhere
[ 3] 2222/tcp                   ALLOW IN    Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 2222/tcp (v6)              ALLOW IN    Anywhere (v6)
[ 6] 443                        ALLOW IN    Anywhere
[10] 80/tcp                     ALLOW IN    Anywhere'
DELETED=""
ufw() {
    case "${1:-}" in
        status) printf '%s\n' "$SAMPLE" ;;
        --force) [[ "${2:-}" == "delete" ]] && DELETED="$DELETED $3" ;;
    esac
}

DELETED=""
ufw_purge_port 22 ssh > /dev/null 2>&1
check "purga 22 y su alias, de mayor a menor" " 4 2 1" "$DELETED"

DELETED=""
ufw_purge_port 2222 "" > /dev/null 2>&1
check "2222 no arrastra a 22" " 5 3" "$DELETED"

DELETED=""
ufw_purge_port 443 "" > /dev/null 2>&1
check "regla sin /tcp también cuenta" " 6" "$DELETED"

DELETED=""
ufw_purge_port 80 "" > /dev/null 2>&1
check "números de dos dígitos ([10]) se leen bien" " 10" "$DELETED"

DELETED=""
ufw_purge_port 3306 "" > /dev/null 2>&1
check "puerto inexistente no borra nada" "" "$DELETED"

summary
