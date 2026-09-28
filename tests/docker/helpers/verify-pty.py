#!/usr/bin/env python3
"""Drive verification from a real terminal, replying only after its prompt."""
import os
import pty
import signal
import sys

signal.alarm(90)
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "/opt/secure-vps.sh", "--lang", "es",
                      "--verify", "--user", "tester", "--port", "2222"])
output = b""
answered = False
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
    output += data
    if not answered and b"escribe acceso-ok" in output:
        os.write(fd, b"acceso-ok\n")
        answered = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(output.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
