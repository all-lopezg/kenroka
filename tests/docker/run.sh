#!/usr/bin/env bash
# Maneja los escenarios end-to-end de secure-vps.sh sobre contenedores
# Ubuntu 24.04 con systemd real.
#
#   tests/docker/run.sh                 todas las escenas (Ubuntu 24.04)
#   tests/docker/run.sh --distro 22.04  misma suite contra Ubuntu 22.04
#   tests/docker/run.sh --only 05       una sola escena
#   tests/docker/run.sh --keep          deja los contenedores arriba al final
#   tests/docker/run.sh --rebuild       fuerza docker compose build
#
# Requiere Docker Desktop corriendo: el servidor necesita systemd como PID 1
# (ssh.socket, systemd-run y journald no existen sin él).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

WORK_DIR="$HERE/.work"
LOG_DIR="$WORK_DIR/logs"
KEEP=0
REBUILD=0
ONLY=""
# El compose lee ${UBUNTU} para el FROM y el tag de imagen.
UBUNTU="${UBUNTU:-24.04}"
export UBUNTU

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only)    ONLY="${2:-}"; shift 2 ;;
        --distro)  UBUNTU="${2:-}"; export UBUNTU; shift 2 ;;
        --keep)    KEEP=1; shift ;;
        --rebuild) REBUILD=1; shift ;;
        --list)    ls -1 "$HERE/scenarios"/*.sh 2>/dev/null | xargs -n1 basename; exit 0 ;;
        -h|--help) grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "opción desconocida: $1 (usa --only|--keep|--rebuild|--list)" >&2; exit 2 ;;
    esac
done

die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# --- prerequisites ---
docker info >/dev/null 2>&1 || die "El daemon de Docker no responde.
Arráncalo primero (abre Docker Desktop o: open -a Docker) y vuelve a probar.
No lo lancé por ti porque es una app de tu máquina."

[[ -d "$HERE/scenarios" ]] || die "falta $HERE/scenarios"

# --- claves del par administrador (se generan en el host, una sola vez) ---
mkdir -p "$WORK_DIR/keys" "$LOG_DIR"
if [[ ! -f "$WORK_DIR/keys/id_ed25519" ]]; then
    echo "generando par de claves SSH de prueba en tests/docker/.work/keys/"
    ssh-keygen -t ed25519 -N "" -C kenroka-admin@tests -f "$WORK_DIR/keys/id_ed25519" -q \
        || die "ssh-keygen falló"
    # Una clave válida pero ajena: se usa para simular "instalé la clave equivocada".
    ssh-keygen -t ed25519 -N "" -C kenroka-ajena@tests -f "$WORK_DIR/keys/stray_ed25519" -q \
        || die "ssh-keygen falló"
    chmod 600 "$WORK_DIR/keys"/*
fi

case "$UBUNTU" in
    22.04|24.04) ;;
    *) die "--distro solo acepta 22.04 o 24.04 (matriz probada); llegó '$UBUNTU'" ;;
esac

# --- build ---
if [[ $REBUILD -eq 1 ]] || ! docker image inspect "kenroka/server-systemd:$UBUNTU" >/dev/null 2>&1; then
    echo "construyendo imágenes de Ubuntu $UBUNTU (systemd + openssh + ufw + fail2ban)..."
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" build \
        || die "docker compose build falló"
fi

# --- corrida ---
shopt -s nullglob
SCENARIOS=("$HERE"/scenarios/*.sh)
[[ -n "$ONLY" ]] && SCENARIOS=("$HERE/scenarios/$ONLY"*.sh)
[[ ${#SCENARIOS[@]} -gt 0 ]] || die "no hay escenarios que concuerden con '$ONLY'"

PASSED=()
FAILED=()
for sc in "${SCENARIOS[@]}"; do
    name="$(basename "$sc" .sh)"
    log="$LOG_DIR/$name.log"
    printf '\n\033[1m▶ %s\033[0m\n' "$name"
    echo "  reiniciando servidor..."
    if ! reset_server; then
        printf '\033[31m  no pude dejar el servidor en estado limpio\033[0m\n'
        FAILED+=("$name (setup)")
        continue
    fi
    if bash "$sc" > "$log" 2>&1; then
        PASSED+=("$name")
        grep -vE '^  ok ' "$log" | sed 's/^/  /'
        printf '  \033[32mPASS\033[0m  %s asertos\n' "$(grep -c '^  ok ' "$log")"
    else
        FAILED+=("$name")
        sed 's/^/  /' "$log"
        printf '  \033[31mFAIL\033[0m  (log completo: %s)\n' "$log"
    fi
done

# --- limpieza ---
if [[ $KEEP -eq 1 ]]; then
    echo
    echo "contenedores dejados arriba; entra con:"
    echo "  $DOCKER_COMPOSE_CMD -f $COMPOSE exec server bash"
    echo "  $DOCKER_COMPOSE_CMD -f $COMPOSE exec client bash"
    echo "y abajo con: $DOCKER_COMPOSE_CMD -f $COMPOSE down -v"
else
    $DOCKER_COMPOSE_CMD -f "$COMPOSE" down --remove-orphans -v >/dev/null 2>&1 || true
fi

echo
printf '\033[1mresultador\033[0m\n'
printf '  %d pasaron: %s\n' "${#PASSED[@]}" "${PASSED[*]:-—}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '  \033[31m%d fallaron: %s\033[0m\n' "${#FAILED[@]}" "${FAILED[*]}"
    exit 1
fi
exit 0
