#!/usr/bin/env python3
"""Drive the guided checkpoints only after a real client SSH + sudo test."""
import os
import pty
import signal
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: guided-access-pty.py <compose-file>")

compose = sys.argv[1]
base = ["docker", "compose", "-f", compose]
command = base + [
    "exec", "-T", "server", "runuser", "-u", "ubuntu", "--", "sudo", "-n",
    "bash", "/opt/secure-vps.sh", "--lang", "es", "--run-all", "--yes",
    "--no-upgrade", "--user", "tester", "--pubkey-file", "/keys/id_ed25519.pub",
    "--sudo", "nopasswd",
]
client_test = base + [
    "exec", "-T", "client", "bash", "-lc",
    "ssh -p 22 -i /keys/id_ed25519 -o BatchMode=yes "
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-o PreferredAuthentications=publickey -o PasswordAuthentication=no "
    "tester@server 'whoami && sudo -n true'",
]

# Un cuelgue debe fallar en minutos, no en horas: si ningún checkpoint llega en
# 10 minutos, el driver muere y el escenario falla en vez de esperar sin fin.
signal.alarm(600)
pid, fd = pty.fork()
if pid == 0:
    os.execvp(command[0], command)

# El prompt de `read -p` no se imprime cuando el stdin del contenedor es una
# tubería (docker compose exec -T), así que sincronizar con la pregunta cuelga
# al driver. Cada checkpoint imprime esta advertencia justo antes de preguntar.
marker = "NO valida esta prueba SSH externa.".encode()
output = b""
answered = 0
failed = False

while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
    output += data
    while output.count(marker) > answered:
        probe = subprocess.run(client_test, capture_output=True, text=True)
        if probe.returncode:
            failed = True
            sys.stderr.write("real SSH + sudo probe failed:\n" + probe.stderr + probe.stdout)
            os.write(fd, b"n\n")
        else:
            os.write(fd, b"s\n")
        answered += 1

_, status = os.waitpid(pid, 0)
sys.stdout.write(output.decode(errors="replace"))
if failed:
    raise SystemExit(1)
if answered != 3:
    sys.stderr.write(f"expected 3 guided access checkpoints, saw {answered}\n")
    raise SystemExit(1)
raise SystemExit(os.waitstatus_to_exitcode(status))
