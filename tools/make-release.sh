#!/usr/bin/env bash
#
# Herramienta del mantenedor: deja lista la release firmada.
#
#   tools/make-release.sh v1.0.0
#
# Calcula el checksum del script, firma ese checksum con tu clave de firma (la
# privada NUNCA entra en el repo) y te da el comando gh para subir los assets.
# Instalar la clave una vez:
#   ssh-keygen -t ed25519 -C "kenroka-release" -f ~/.ssh/kenroka_sign
#   ssh-add ~/.ssh/kenroka_sign
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${1:-}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "uso: tools/make-release.sh vX.Y.Z" >&2; exit 2; }

KEY="${KENROKA_SIGN_KEY:-$HOME/.ssh/kenroka_sign}"
[[ -f "$KEY" ]] || { echo "no encuentro la clave de firma en $KEY" >&2; exit 1; }

grep -q "SCRIPT_VERSION=\"${VERSION#v}\"" secure-vps.sh \
    || echo "aviso: la versión del script no parece ser ${VERSION}; revisa SCRIPT_VERSION" >&2

# sha256sum es de coreutils; en macOS el mantenedor tiene shasum.
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum secure-vps.sh > SHA256SUMS.txt
else
    ( cd . && shasum -a 256 secure-vps.sh ) > SHA256SUMS.txt
fi
# ssh-keygen pregunta "Overwrite (y/n)?" si la firma ya existe, y sin terminal
# sale con código 0 SIN sobrescribir: quedaría publicada la firma anterior.
rm -f SHA256SUMS.txt.sig
ssh-keygen -Y sign -f "$KEY" -n file SHA256SUMS.txt
[[ -s SHA256SUMS.txt.sig ]] || { echo "no se escribió la firma" >&2; exit 1; }

echo
echo "Listo. Assets de la release:"
sed 's/^/    /' SHA256SUMS.txt
echo "    SHA256SUMS.txt.sig"
echo
echo "Publícalos con:"
echo "  gh release create $VERSION secure-vps.sh SHA256SUMS.txt SHA256SUMS.txt.sig \\ "
echo "      --title \"secure-vps $VERSION\" --notes-file NOTAS.md"
echo
echo "Y actualiza en install.sh la línea VERSION=\"...\" a $VERSION antes de subir el tag."
