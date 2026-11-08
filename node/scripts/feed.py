#!/usr/bin/env python3
# feed.py — type a script into a program's console, a line at a time, each
# only once the program is ready for it: what it prints since the last line
# ends with a prompt ("$ ", "login: ", "password: ").  Its output goes to
# stdout as it comes.  Used by scripts/oscheck.sh, so the tests don't depend
# on the machine's speed (typed ahead, a line is echoed among the output).
#
# Usage: feed.py SECS FILE CMD...
#   SECS  the whole run's limit (the program killed after it; exit 124)
#   FILE  the lines; besides plain lines (sent with a newline):
#     #wait TEXT   wait (without sending) until TEXT has appeared since the
#                  last line sent
#     #raw TEXT    send TEXT with Python's escapes meant (\r, \n, \t, \\,
#                  \x1b for Esc), no newline, without waiting for a prompt
#                  first (keys for a program in raw mode)
#     #sleep SECS  wait that long
#   After the last line: until a prompt again (or the program's end), half a
#   second more, then it is stopped (exit 124) if it has not ended.
import os, select, subprocess, sys, time

PROMPTS = (b"$ ", b"login: ", b"password: ")
LINE_LIMIT = 60.0                       # seconds to wait for a prompt or text


def unescape(s):
    return s.encode("latin-1").decode("unicode_escape").encode("latin-1")


def main():
    secs, path, cmd = float(sys.argv[1]), sys.argv[2], sys.argv[3:]
    lines = open(path).read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    end = time.time() + secs
    since = b""                          # output since the last line sent
    out = sys.stdout.buffer

    def pump(wait):
        nonlocal since
        r, _, _ = select.select([p.stdout], [], [], wait)
        if not r:
            return True
        d = os.read(p.stdout.fileno(), 65536)
        if not d:
            return False
        out.write(d); out.flush()
        since += d
        return True

    def until(done):
        limit = min(end, time.time() + LINE_LIMIT)
        while not done() and time.time() < limit:
            if not pump(0.05):
                return False
        return time.time() < end

    def send(b):
        nonlocal since
        since = b""
        try:
            p.stdin.write(b); p.stdin.flush()
        except BrokenPipeError:
            pass

    alive = True
    for l in lines:
        if not alive or time.time() >= end:
            break
        if l.startswith("#wait "):
            want = l[6:].encode()
            alive = until(lambda: want in since)
        elif l.startswith("#sleep "):
            t = time.time() + float(l[7:])
            while time.time() < t and alive:
                alive = pump(0.05)
        elif l.startswith("#raw "):
            send(unescape(l[5:]))
        else:
            alive = until(lambda: since.endswith(PROMPTS))
            send(l.encode() + b"\n")
    if alive:
        alive = until(lambda: since.endswith(PROMPTS))
    t = min(end, time.time() + 0.5)
    while alive and time.time() < t:
        alive = pump(0.05)
    if p.poll() is None:
        p.kill(); p.wait()
        while select.select([p.stdout], [], [], 0)[0]:
            d = os.read(p.stdout.fileno(), 65536)
            if not d:
                break
            out.write(d); out.flush()
        sys.exit(124)
    sys.exit(p.returncode)


main()
