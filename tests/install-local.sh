#!/usr/bin/env bash
# Arnés local de install.sh: sirve los archivos por http en localhost, con una
# clave de firma de usar y tirar, y comprueba que el instalador acepta lo bueno
# y rechaza lo manipulado. No toca la clave real ni publica nada.
set -uo pipefail

SRC=/Users/allan/Documents/Proyectos/kenroka
D="$(mktemp -d /tmp/kenroka-inst.XXXXXX)"
PUB="$D/pub"
PORT=$(( 8700 + RANDOM % 300 ))
mkdir -p "$PUB"
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; rm -rf "$D"' EXIT

PASS=0; FAILN=0
ok()  { PASS=$((PASS+1)); printf '  ok    %s\n' "$*"; }
bad() { FAILN=$((FAILN+1)); printf '  FALLA %s\n' "$*"; }
has()  { case "$3" in *"$2"*) ok "$1";; *) bad "$1 | falta '$2' en: $(printf '%s' "$3" | tr '\n' ' ' | head -c 300)";; esac; }
hasnt() { case "$3" in *"$2"*) bad "$1 | sobra '$2'";; *) ok "$1";; esac; }

# --- material de pruebas ---
ssh-keygen -t ed25519 -N "" -C "prueba-local" -f "$D/testkey" -q
cp "$SRC/secure-vps.sh" "$PUB/secure-vps.sh"
PUBKEY_LINE="$(cut -d' ' -f1,2 "$D/testkey.pub")"
sed "s|^TRUSTED_KEY=.*|TRUSTED_KEY=\"$PUBKEY_LINE\"|" "$SRC/install.sh" > "$PUB/install.sh"
( cd "$PUB" && shasum -a 256 secure-vps.sh > SHA256SUMS.txt \
    && ssh-keygen -Y sign -f "$D/testkey" -n file SHA256SUMS.txt >/dev/null )

(cd "$PUB" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SRV=$!
# Si el puerto estaba ocupado, el servidor nuevo no arrancó y cada curl daría
# 404 contra un directorio ajeno: mejor decirlo aquí que parecer un fallo de firma.
up=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --proto '=http' "http://127.0.0.1:$PORT/secure-vps.sh" -o /dev/null 2>/dev/null; then
        up=1; break
    fi
    sleep 0.5
done
if [[ $up -ne 1 ]]; then
    echo "no hay servidor en el puerto $PORT (¿estará ocupado por una corrida anterior?)" >&2
    exit 3
fi

# install.sh exige terminal de control: se la damos con un pty. Ojo: pty.spawn
# se queda esperando entrada de un stdin que aquí no es terminal; con pty.fork
# el padre lee hasta el EIO de que el hijo murió y devuelve el estado real.
run_inst() {
    KENROKA_BASE="http://127.0.0.1:$PORT" python3 -c '
import os, pty, sys
cmd = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
out = b""
while True:
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(st))
' bash "$PUB/install.sh" "$@" 2>&1
}

echo "== caso feliz (el script se ejecuta con --help y sale solo)"
out="$(run_inst --help)"
has "verifica la firma"              "Firma válida" "$out"
has "verifica el checksum"           "Contenido verificado" "$out"
has "el script heredó la terminal"   "Usage: sudo bash" "$out"
hasnt "no hubo error de checksum"    "no cuadra" "$out"

echo "== archivo servido manipulado (un byte)"
printf '\n' >> "$PUB/secure-vps.sh"
out="$(run_inst --help)"
has "rechaza el checksum"            "no cuadra" "$out"
hasnt "no llega a ejecutar el script" "Contenido verificado" "$out"
cp "$SRC/secure-vps.sh" "$PUB/secure-vps.sh"

echo "== lista de checksums firmada por otra mano"
ssh-keygen -t ed25519 -N "" -C "ajena" -f "$D/otherkey" -q
( cd "$PUB" && rm -f SHA256SUMS.txt.sig \
    && ssh-keygen -Y sign -f "$D/otherkey" -n file SHA256SUMS.txt >/dev/null )
out="$(run_inst --help)"
has "rechaza una firma que no valida" "NO valida" "$out"
hasnt "no ejecuta nada"                "Contenido verificado" "$out"

echo "== sin terminal de control"
out="$(KENROKA_BASE="http://127.0.0.1:$PORT" bash "$PUB/install.sh" --help < /dev/null 2>&1)"
has "para antes de descargar" "no hay terminal de control" "$out"

printf '\n  resultado: %d ok, %d fallas\n' "$PASS" "$FAILN"
[[ $FAILN -eq 0 ]]
