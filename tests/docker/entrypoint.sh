#!/usr/bin/env bash
# Arranca systemd como PID 1. Sin esto no existe ssh.socket, ni systemd-run,
# ni journald, y el script perdería justo lo que queremos comprobar.
set -euo pipefail

mkdir -p /run/sshd /run/lock /var/lib/secure-vps /var/log/secure-vps
: > /run/utmp

# systemd se queja si /etc/hostname no existe dentro del contenedor.
[[ -s /etc/hostname ]] || echo kenroka-test > /etc/hostname

exec /lib/systemd/systemd "$@"
