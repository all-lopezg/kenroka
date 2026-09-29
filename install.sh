#!/usr/bin/env bash
#
# install.sh - puerta de entrada de kenroka/secure-vps
#
# Uso pensado para el usuario final (una sola línea, sin versión: siempre la
# última release publicada y firmada):
#   curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
#
# Para quedarse en una versión concreta (una flota, un entorno que no cambia):
#   curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | KENROKA_VERSION=vX.Y.Z bash
#
# Los flags se reenvían al script tal cual. El que no escribe nada:
#   curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | sudo bash -s -- --audit
#
# Por qué existe este archivo en vez de apuntar el curl directamente al script:
# con `curl | bash` el stdin del proceso es la tubería, así que cualquier `read`
# del script se come las siguientes líneas de sí mismo. secure-vps.sh necesita
# preguntar varias veces (la confirmación de acceso, el puerto, la clave), así que se
# descarga, se verifica y se arranca con la terminal conectada (< /dev/tty).
#
# Este archivo NO lee del teclado: solo baja, comprueba y entrega el control.

set -euo pipefail

REPO="all-lopezg/kenroka"
# Sin KENROKA_VERSION, 'releases/latest' resuelve la última release estable
# (GitHub excluye drafts y pre-releases) y la URL del instalador no cambia nunca.
if [[ -n "${KENROKA_VERSION:-}" ]]; then
    BASE="${KENROKA_BASE:-https://github.com/${REPO}/releases/download/${KENROKA_VERSION}}"
else
    BASE="${KENROKA_BASE:-https://github.com/${REPO}/releases/latest/download}"
fi
# Principal que se le pasa a ssh-keygen -Y verify. Es una etiqueta, no parte de
# la firma (comprobado: la firma solo cubre el namespace "file", la clave y los
# datos), así que renombrarla no invalida las releases ya publicadas. Se puso el
# nombre del producto en vez del usuario de GitHub para que la herramienta no
# dependa de una persona.
IDENTITY="kenroka"

# Clave pública con la que se firma SHA256SUMS.txt de cada release. Contrasta
# su huella por un canal distinto al de la descarga antes de fiarte:
#   SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
TRUSTED_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICr4W9Fle/TgTmrKBKpRh5SVXYu19VlrGv99bFpWRYPb kenroka-release"

# Mismo idioma que va a hablar secure-vps.sh: la detección es la suya (locale del
# sistema, es* => español) y un --lang reenviado manda sobre las dos cosas. Si no,
# el instalador saluda en un idioma y el asistente continúa en otro, y eso parece
# un fallo aunque esté funcionando.
UI_LANG="en"
case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in es*) UI_LANG="es" ;; esac
_prev=""
for _a in "$@"; do
    if [[ "$_prev" == "--lang" ]]; then
        case "$_a" in es|en) UI_LANG="$_a" ;; esac
    fi
    _prev="$_a"
done

if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; DIM=$'\033[2m'; NC=$'\033[0m'
else
    GREEN=''; RED=''; DIM=''; NC=''
fi

say()  { printf '%s\n' "$*"; }
dim()  { printf '%s\n' "${DIM}$*${NC}"; }
ok()   { printf '%s\n' "${GREEN}✔${NC}  $*"; }
fail() { printf '%s\n' "${RED}✘  $1${NC}" >&2; exit 1; }

# msg <español> <inglés>
msg() {
    if [[ $UI_LANG == es ]]; then
        printf '%s\n' "$1"
    else
        printf '%s\n' "$2"
    fi
}
# msg_fail <español> <inglés>
msg_fail() {
    if [[ $UI_LANG == es ]]; then
        fail "$1"
    else
        fail "$2"
    fi
}

command -v curl       >/dev/null 2>&1 || msg_fail "falta curl (apt-get install curl)" "curl is missing (apt-get install curl)"
command -v ssh-keygen >/dev/null 2>&1 || msg_fail "falta ssh-keygen (apt-get install openssh-client)" "ssh-keygen is missing (apt-get install openssh-client)"
[[ -t 1 ]] || dim "$(msg "sin terminal: los avisos se verán solo en el log" "no terminal: the notices will only show in the log")"
# Ojo: con `curl | bash` el stdin ES la tubería, así que `-t 0` mentiría justo
# en el caso que queremos soportar. Lo que importa es si existe una terminal de
# control a la que conectar al script; sin ella no podría preguntar nada (cron,
# ansible sin tty) y preferimos parar antes de descargar.
if ! ( exec </dev/tty ) >/dev/null 2>&1; then
    msg_fail "no hay terminal de control: el asistente necesita preguntarte cosas. Descarga el script y córrelo en una terminal." \
             "there is no controlling terminal: the assistant needs to ask you things. Download the script and run it in a terminal."
fi

WORK="$(mktemp -d)" || msg_fail "no pude crear un directorio temporal" "could not create a temporary directory"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

dim "$(msg "Descargando secure-vps desde" "Downloading secure-vps from") ${DIM}${BASE}${NC}"
# Fuera de https solo si es el servidor de pruebas del instalador.
CURL_EXTRA=(--proto '=https' --tlsv1.2)
[[ "$BASE" == http://* ]] && CURL_EXTRA=(--proto '=http')
for f in secure-vps.sh SHA256SUMS.txt SHA256SUMS.txt.sig; do
    curl -fsSL "${CURL_EXTRA[@]}" "${BASE}/${f}" -o "${WORK}/${f}" \
        || msg_fail "no pude descargar ${f} desde ${BASE}" "could not download ${f} from ${BASE}"
done
# La versión real es la que dice el archivo descargado, no la que creíamos
# pedir: con 'releases/latest' la URL no la lleva.
RESOLVED="$(awk -F'"' '/^readonly SCRIPT_VERSION=/{print $2; exit}' "${WORK}/secure-vps.sh")"
RESOLVED="${RESOLVED:-desconocida}"

printf '%s namespaces="file" %s\n' "$IDENTITY" "$TRUSTED_KEY" > "${WORK}/allowed_signers"
chmod 600 "${WORK}/allowed_signers"

if ! ssh-keygen -Y verify -f "${WORK}/allowed_signers" -I "$IDENTITY" -n file \
        -s "${WORK}/SHA256SUMS.txt.sig" < "${WORK}/SHA256SUMS.txt" >/dev/null 2>&1; then
    msg_fail "la firma de SHA256SUMS.txt NO valida con la clave publicada. No ejecuto nada: puede que la release esté cortada o que alguien esté sirviendo otro archivo." \
             "the SHA256SUMS.txt signature does NOT verify against the published key. Running nothing: the release may be broken or someone is serving a different file."
fi
ok "$(msg "Firma válida de" "Signature valid, signed by") ${IDENTITY}"

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$WORK" && sha256sum -c SHA256SUMS.txt ) || msg_fail "el checksum no cuadra" "the checksum does not match"
else
    ( cd "$WORK" && shasum -a 256 -c SHA256SUMS.txt ) || msg_fail "el checksum no cuadra" "the checksum does not match"
fi

say ""
msg "Versión resuelta: ${RESOLVED}." "Resolved version: ${RESOLVED}."

# Sin argumentos, quien llega por el one-liner va directo al asistente guiado.
# El menú por fases sigue disponible corriendo el script a mano:
#   sudo bash secure-vps.sh
if [[ $# -eq 0 ]]; then
    set -- --run-all
fi

say ""
bash "${WORK}/secure-vps.sh" "$@" < /dev/tty
rc=$?
exit $rc
