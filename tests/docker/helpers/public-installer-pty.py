#!/usr/bin/env python3
"""Test the public installer with a real controlling terminal in Ubuntu."""
import os
import pty
import signal
import subprocess
import sys

compose, mode = sys.argv[1:]
if mode not in ('menu', 'guided'):
    raise SystemExit('mode must be menu or guided')
base = ['docker', 'compose', '-f', compose]
launch = 'curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash'
if mode == 'guided':
    launch += (' -s -- --lang es --run-all --yes --no-upgrade'
               ' --user tester --pubkey-file /keys/id_ed25519.pub --sudo nopasswd')
command = base + ['exec', '-it', '-e', 'TERM=dumb', 'server', 'runuser', '-u', 'ubuntu',
                  '--', 'bash', '-lc', launch]
probe_command = base + ['exec', '-T', 'client', 'bash', '-lc',
    "ssh -p 22 -i /keys/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no "
    "-o UserKnownHostsFile=/dev/null -o PreferredAuthentications=publickey "
    "-o PasswordAuthentication=no tester@server 'whoami && sudo -n true'"]
signal.alarm(600)
pid, fd = pty.fork()
if pid == 0:
    os.execvp(command[0], command)
output = b''
answered = pauses = 0
menu_exited = failed = False
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
    output += data
    if mode == 'menu':
        if not menu_exited and (b'Type an option:' in output or b'Escribe una opci' in output):
            os.write(fd, b'0\n')
            menu_exited = True
        continue
    marker = 'NO valida esta prueba SSH externa.'.encode()
    while output.count(marker) > answered:
        probe = subprocess.run(probe_command, capture_output=True, text=True)
        if probe.returncode:
            failed = True
            sys.stderr.write('real SSH + sudo probe failed:\n' + probe.stderr + probe.stdout)
            os.write(fd, b'n\n')
        else:
            os.write(fd, b's\n')
        answered += 1
    marker = 'Presiona Enter para continuar...'.encode()
    while output.count(marker) > pauses:
        os.write(fd, b'\n')
        pauses += 1
_, status = os.waitpid(pid, 0)
sys.stdout.write(output.decode(errors='replace'))
if failed or (mode == 'menu' and not menu_exited) or (mode == 'guided' and answered != 3):
    raise SystemExit(1)
raise SystemExit(os.waitstatus_to_exitcode(status))
