#!/usr/bin/env python3
"""Exercise presentation functions in a real PTY; never run VPS operations."""
import fcntl
import os
import pty
import re
import selectors
import signal
import struct
import sys
import termios
import time

fixture, scenario, width, output_file = sys.argv[1:]
responses = {
    'access': ['h', '', '1'],
    'restore': ['2'],
    'result': ['h', ''],
    'failed': [''],
    'plain': [],
    'dumb': [],
    'menu': ['2', 'b', '3', 'b', '0'],
    'decision': ['h', '1', ''],
    'resize': [''],
    'username': ['', 'root', 'miadmin'],
    'menu_actions': ['1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '2.1', '2.2', '2.3', '3.1', '1', '3.2', '0'],
}[scenario]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 40, int(width), 0, 0))
    os.environ['TERM'] = 'xterm-256color'
    os.execvp('bash', ['bash', fixture, scenario])
selector = selectors.DefaultSelector()
selector.register(fd, selectors.EVENT_READ)
out = b''
answered = 0
deadline = time.monotonic() + 15
try:
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError(f'UI timed out in {scenario}: {out[-1000:]!r}')
        if not selector.select(0.2):
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        while out.count(b'> ') > answered and answered < len(responses):
            os.write(fd, (responses[answered] + '\n').encode())
            answered += 1
    _, status = os.waitpid(pid, 0)
except BaseException:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise
finally:
    os.close(fd)
# Retain raw escape sequences for checking transitions, plus readable frames.
with open(output_file + '.raw', 'wb') as file:
    file.write(out)
text = out.decode(errors='replace').replace('\r', '')
text = text.replace('\x1b[2J\x1b[H', '\n[SCREEN]\n')
text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
with open(output_file, 'w') as file:
    file.write(text)
if answered != len(responses):
    raise RuntimeError(f'{scenario}: expected {len(responses)} responses, sent {answered}')
sys.exit(os.waitstatus_to_exitcode(status))
