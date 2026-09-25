#!/usr/bin/env bash
# Deja el contenedor en el estado de un VPS Ubuntu 24.04 recién entregado por
# un proveedor cloud: usuario por defecto con sudo, root accesible por clave,
# PasswordAuthentication yes vía cloud-init, ssh.socket activo y un servicio
# extra escuchando en 80 (para probar el aviso antes de activar UFW).
set -uo pipefail

KEYPUB=/keys/id_ed25519.pub
if [[ ! -f "$KEYPUB" ]]; then
    echo "seed: falta $KEYPUB; genera el par con tests/docker/run.sh --prepare-keys" >&2
    exit 1
fi

fail() { echo "seed: $*" >&2; exit 1; }

# 1) Usuario del proveedor: si el script se corre con sudo desde aquí,
#    SUDO_USER=ubuntu, que es el caso que check_original_user() espera.
if ! id ubuntu >/dev/null 2>&1; then
    adduser --gecos "" --disabled-password ubuntu >/dev/null 2>&1 || fail "no pude crear ubuntu"
    usermod -aG sudo ubuntu
fi
# En la imagen de test sí hay NOPASSWD: es el andamio, no la config que se valida.
printf 'ubuntu ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-test-ubuntu
chmod 0440 /etc/sudoers.d/90-test-ubuntu
visudo -cf /etc/sudoers.d/90-test-ubuntu >/dev/null || fail "sudoers de test inválido"

# 2) Root con tu clave: la única vía de entrada antes del endurecimiento.
#    Ojo: con PermitRootLogin=without-password (default de Ubuntu) la
#    contraseña de root NO abre SSH; para probar autenticación por contraseña
#    se usa el usuario del proveedor.
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp "$KEYPUB" /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 3) Usuario del proveedor, con contraseña y clave: el que representa al
#    operador legítimo antes y después del cierre.
mkdir -p /home/ubuntu/.ssh
cp "$KEYPUB" /home/ubuntu/.ssh/authorized_keys
chmod 700 /home/ubuntu/.ssh
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh
printf 'ubuntu:semilla-test\n' | chpasswd || fail "no pude fijar la contraseña de ubuntu"

# 4) Como en cualquier imagen cloud: un drop-in que reabre la contraseña.
#    Si fase_3 no lo corrige, PasswordAuthentication seguiría en yes.
mkdir -p /etc/ssh/sshd_config.d
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/50-cloud-init.conf
chmod 644 /etc/ssh/sshd_config.d/50-cloud-init.conf

# 5) Claves de host, y el esquema de arranque de ssh que trae cada versión:
#    24.04 usa ssh.socket (activación por socket); 22.04, ssh.service clásico.
ssh-keygen -A >/dev/null 2>&1
. /etc/os-release
if [[ "${VERSION_ID:-}" == "24.04" ]]; then
    systemctl enable ssh.socket ssh.service >/dev/null 2>&1
    systemctl restart ssh.socket ssh.service 2>/dev/null || systemctl restart ssh 2>/dev/null || true
else
    systemctl disable --now ssh.socket >/dev/null 2>&1 || true
    systemctl enable ssh.service >/dev/null 2>&1
    systemctl restart ssh.service 2>/dev/null || systemctl restart ssh 2>/dev/null || true
fi

# 6) Un listener que UFW debería dejar fuera: simula una web ya desplegada.
if [[ ! -f /etc/systemd/system/dummy-http.service ]]; then
    cat > /etc/systemd/system/dummy-http.service <<'EOF'
[Unit]
Description=Listener falso en 80 para probar el aviso de UFW
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:80,reuseaddr,fork EXEC:/bin/true
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now dummy-http.service >/dev/null 2>&1
fi

# 7) Esperar a que el 22 esté escuchando antes de dar por buena la semilla.
for _ in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -qE '(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]):22([[:space:]]|$)'; then
        echo "seed: ssh escuchando en 22, root con clave instalada, usuario ubuntu listo"
        exit 0
    fi
    sleep 1
done
fail "sshd nunca quedó escuchando en 22 (revisa 'systemctl status ssh.socket')"
