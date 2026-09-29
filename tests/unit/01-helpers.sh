#!/usr/bin/env bash
# Unit 01: argumentos, validación de clave pública y borrado de reglas UFW.
# --audit promete no escribir nada: exige que la carga de funciones falle ruidosa
# (set -u) en vez de tragar un 'readonly: readonly variable' como hacía antes.
set -euo pipefail

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

# ============================================================
# IDIOMA DE LAS PREGUNTAS
# ============================================================
echo "== confirm_labels"
extract_fns confirm_labels
UI_LANG=es
check "en español se pide [s/n]" "[s/n]: " "$(confirm_labels)"
UI_LANG=en
check "en inglés se pide [y/n]" "[y/n]: " "$(confirm_labels)"
check "la interfaz ya no exige un token literal" "0" \
    "$(grep -c 'type acceso-ok' "$SRC" || true)"

# ============================================================
# INVARIANTES DE PANTALLA (colores reales, ancho del arte y de la tarjeta)
# ============================================================
echo "== colores y banner"
# Con '\033[1m' (comilla simple) el valor guarda texto literal: printf '%s' y
# los heredoc lo imprimen tal cual, que es como el banner salio cubierto de
# "\033[1m" en un VPS real. Las definiciones tienen que ir con $'...'.
bad_quotes="$(grep -cE "readonly (RED|GREEN|YELLOW|BLUE|CYAN|BOLD|DIM|NC)='\\\\033" "$SRC" || true)"
check "ningun color definido con comilla simple" "0" "$bad_quotes"
for v in RED GREEN YELLOW BLUE CYAN BOLD DIM NC; do
    n="$(grep -oE "\b${v}=" "$SRC" | grep -c . || true)"
    check "$v definido en las dos ramas (con y sin TTY)" "2" "$n"
done
# El arte se mide en codepoints, no en bytes: cada caja son 3 bytes y awk del
# sistema cuenta bytes, asi que una fila con una tilde menos "cuadraria" mal.
banner_check="$(python3 - "$SRC" <<'PYEOF'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"cat <<'BANNER'\n(.*?)\nBANNER", s, re.S)
rows = m.group(1).split("\n") if m else []
w = {len(r) for r in rows}
print("ok" if len(rows) == 6 and len(w) == 1 else "mal %d filas %s" % (len(rows), sorted(w)))
PYEOF
)"
check "el banner tiene 6 filas del mismo ancho" "ok" "$banner_check"

# La tarjeta de bienvenida se renderiza de verdad: se saca el heredoc del fuente
# y se expande con las variables del script, y despues se mide lo que veria una
# terminal de 80 columnas (en codepoints, por las tildes).
render_card() {   # render_card <1|2>  -> 1 = espanol, 2 = ingles
    local body
    body="$(python3 - "$SRC" "$1" <<'PYEOF'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
want = int(sys.argv[2])
cards = [b for b in re.findall(r"cat <<EOF\n(.*?)\nEOF", s, re.S) if "\u25b8" in b]
sys.stdout.write(cards[want - 1])
PYEOF
)"
    (
        PRETTY_NAME="Ubuntu 24.04.5 LTS"; PUBLIC_IP="185.147.157.139"
        ORIGINAL_USER="root"; CURRENT_PORT=22; ROLLBACK_MINUTES=10
        SNAPSHOTS_DIR="/var/lib/secure-vps/snapshots"
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
        eval "cat <<XEOF
$body
XEOF"
    )
}
card="$(render_card 1)"
card_w="$(printf '%s\n' "$card" | python3 -c 'import sys;print(max(len(l.rstrip("\n")) for l in sys.stdin))')"
check "la tarjeta cabe en 80 columnas" "yes" "$([[ "$card_w" -le 80 ]] && echo yes || echo "no ($card_w)")"
has "anuncia el sistema y el puerto" "Ubuntu 24.04.5 LTS" "$card"
has "enumera las fases"              "Usuario administrador con sudo" "$card"
has "explica la cuenta atras"        "cuenta atrás de 10 min" "$card"
has "y lo que el rollback NO deshace" "No deshace usuarios, sudo" "$card"
hasnt "no vuelve a la lista larga de antes" "8. Cambiar el puerto" "$card"
card_en="$(render_card 2)"
has "la version inglesa existe" "An admin user whose sudo actually works" "$card_en"
has "y explica la decisión clara en inglés" "choose keep/restore" "$card_en"
hasnt "pero no el espanol en la pantalla inglesa" "acceso-ok" "$card_en"

summary
