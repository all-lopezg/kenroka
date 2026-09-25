#!/usr/bin/env bash
#
# install.sh - puerta de entrada de kenroka/secure-vps
#
# Uso pensado para el usuario final (una sola línea, sin versión: siempre la
# última release publicada y firmada):
#   curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
#
# Para quedarse en una versión concreta (una flota, un entorno que no cambia):
#   KENROKA_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
#
# Los flags se le pasan al script tal cual. El que no escribe nada:
#   curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | sudo bash -s -- --audit
#
# Por qué existe este archivo en vez de apuntar el curl directamente al script:
# con `curl | bash` el stdin del proceso es la tubería, así que cualquier `read`
# del script se come las siguientes líneas de sí mismo. secure-vps.sh necesita
# preguntar varias veces (el acceso-ok, el puerto, la clave), así que se
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
IDENTITY="all-lopezg"

# Clave pública con la que se firma SHA256SUMS.txt de cada release. Contrasta
# su huella por un canal distinto al de la descarga antes de fiarte:
#   SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
TRUSTED_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICr4W9Fle/TgTmrKBKpRh5SVXYu19VlrGv99bFpWRYPb kenroka-release"

say()  { printf '%s\n' "$*"; }
fail() { printf '✘  %s\n' "$*" >&2; exit 1; }

command -v curl       >/dev/null 2>&1 || fail "falta curl (apt-get install curl)"
command -v ssh-keygen >/dev/null 2>&1 || fail "falta ssh-keygen (apt-get install openssh-client)"
[[ -t 1 ]] || say "sin terminal: los avisos se verán solo en el log"
# Ojo: con `curl | bash` el stdin ES la tubería, así que `-t 0` mentiría justo
# en el caso que queremos soportar. Lo que importa es si existe una terminal de
# control a la que conectar al script; sin ella no podría preguntar nada (cron,
# ansible sin tty) y preferimos parar antes de descargar.
if ! ( exec </dev/tty ) >/dev/null 2>&1; then
    fail "no hay terminal de control: el asistente necesita preguntarte cosas. Descarga el script y córrelo en una terminal."
fi

WORK="$(mktemp -d)" || fail "no pude crear un directorio temporal"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

say "Descargando secure-vps desde ${BASE}..."
# Fuera de https solo si es el servidor de pruebas del instalador.
CURL_EXTRA=(--proto '=https' --tlsv1.2)
[[ "$BASE" == http://* ]] && CURL_EXTRA=(--proto '=http')
for f in secure-vps.sh SHA256SUMS.txt SHA256SUMS.txt.sig; do
    curl -fsSL "${CURL_EXTRA[@]}" "${BASE}/${f}" -o "${WORK}/${f}" \
        || fail "no pude descargar ${f} desde ${BASE}"
done
# La versión real es la que dice el archivo descargado, no la que creíamos
# pedir: con 'releases/latest' la URL no la lleva.
RESOLVED="$(awk -F'"' '/^readonly SCRIPT_VERSION=/{print $2; exit}' "${WORK}/secure-vps.sh")"
RESOLVED="${RESOLVED:-desconocida}"

printf '%s namespaces="file" %s\n' "$IDENTITY" "$TRUSTED_KEY" > "${WORK}/allowed_signers"
chmod 600 "${WORK}/allowed_signers"

if ! ssh-keygen -Y verify -f "${WORK}/allowed_signers" -I "$IDENTITY" -n file \
        -s "${WORK}/SHA256SUMS.txt.sig" < "${WORK}/SHA256SUMS.txt" >/dev/null 2>&1; then
    fail "la firma de SHA256SUMS.txt NO valida con la clave publicada. No ejecuto nada: puede que la release esté cortada o que alguien esté sirviendo otro archivo."
fi
say "✔  Firma válida de ${IDENTITY}."

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$WORK" && sha256sum -c SHA256SUMS.txt ) || fail "el checksum no cuadra"
else
    ( cd "$WORK" && shasum -a 256 -c SHA256SUMS.txt ) || fail "el checksum no cuadra"
fi

say ""
say "Versión resuelta: ${RESOLVED}. Para congelarla en una flota, repite con KENROKA_VERSION=v${RESOLVED}."
say "Contenido verificado. Arranco el asistente; sigue las instrucciones en pantalla."
say ""

# Sin argumentos, quien llega por el one-liner va directo al asistente guiado.
# El menú por fases sigue disponible corriendo el script a mano:
#   sudo bash secure-vps.sh
if [[ $# -eq 0 ]]; then
    set -- --run-all
fi

bash "${WORK}/secure-vps.sh" "$@" < /dev/tty
rc=$?
exit $rc
