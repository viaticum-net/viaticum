#!/usr/bin/env python3
"""Drive `viaticum setup` through a real pty (no expect on this machine).

The phrase is parsed from the grid and used to answer the check. The transcript
is printed to stdout and nowhere else — the caller keeps it in a shell variable,
never in a file (install-i2: no phrase in logs or captures).

Modes:
  --stop-at-check   answer quota/Enter, wait for the first `Word #N?`, send Ctrl-C
  (default)         answer the check correctly
  --wrong-once      give one wrong word first, then the right words (the same
                    three positions are asked again; retries are part of setup)

Usage:
  setup_pty.py --binary ./target/release/viaticum --data-dir DIR [--watch DIR ...]
               [--stop-at-check|--wrong-once] [--timeout SECS] [-- extra setup args]
"""

import argparse
import errno
import os
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import struct
import time
import fcntl

GRID_WORD = re.compile(rb"(\d{1,2})\.\s+([a-z]+)")
CHECK_PROMPT = re.compile(rb"Word #(\d+)\?")
QUOTA = re.compile(rb"in GB \[[^\]]*\]: ")
MODE = re.compile(rb"Choose 1 or 2 \[1\]: ")
PHRASE_ENTER = re.compile(rb"Press Enter when you have written them down: ")


class Driver:
    def __init__(self, argv, timeout):
        self.argv = argv
        self.timeout = timeout
        self.buf = bytearray()
        self.transcript = bytearray()
        self.words = {}
        self.answered = 0
        self.wrong_left = 0
        self.stop_at_check = False
        self.quit = False
        self.exit_code = None
        self.debug = False
        self.stderr_file = None
        self.child_pid = None

    def log(self, msg):
        if self.debug:
            print(f"[pty] {msg}", file=sys.stderr, flush=True)

    def read_available(self, fd, master):
        data = os.read(master, 65536)
        if not data:
            return False
        self.buf.extend(data)
        self.transcript.extend(data)
        for m in GRID_WORD.finditer(bytes(self.buf)):
            idx, word = int(m.group(1)), m.group(2).decode()
            if 1 <= idx <= 24:
                self.words[idx] = word
        return True

    def send(self, master, data: bytes):
        os.write(master, data)

    def run(self):
        master, slave = pty.openpty()
        # A wide-enough terminal for the 6-column grid; the default 80x24 would
        # wrap a 6x12-column grid and break the parser.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))

        def reset_signals():
            # A non-interactive parent shell starts background jobs with SIGINT
            # ignored, and exec keeps ignored dispositions. The friend's
            # terminal has the default; restore it before exec.
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGQUIT, signal.SIG_DFL)
            # Keep stderr (tracing and prompts that are not the phrase grid)
            # in a file the leak scan reads. The grid stays on the pty stdout.
            if self.stderr_file:
                fd = os.open(self.stderr_file, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                os.dup2(fd, 2)
                os.close(fd)

        proc = subprocess.Popen(
            self.argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            start_new_session=True,
            preexec_fn=reset_signals,
        )
        self.child_pid = proc.pid
        self.log(f"child pid {proc.pid}")
        os.close(slave)
        os.set_blocking(master, False)
        deadline = time.time() + self.timeout
        sent_ctrl_c = False
        while True:
            if proc.poll() is not None:
                # Drain what is left.
                try:
                    while self.read_available(master, master):
                        pass
                except OSError:
                    pass
                break
            if time.time() > deadline:
                proc.kill()
                self.exit_code = 124
                break
            try:
                r, _, _ = select.select([master], [], [], 0.05)
            except InterruptedError:
                continue
            if r:
                try:
                    if not self.read_available(master, master):
                        break
                except OSError as e:
                    if e.errno == errno.EIO:
                        break
                    raise
            text = bytes(self.buf)

            # Quota prompt: accept the default with Enter.
            if MODE.search(text[-200:]):
                self.log("mode prompt: 1 (new)")
                self.send(master, b"1\n")
                self.buf.clear()
                continue

            if text.endswith(b"]: ") and b"in GB [" in text[-200:]:
                self.log("quota prompt: Enter")
                self.send(master, b"\n")
                self.buf.clear()
                continue

            # After the grid: Enter to acknowledge the paper.
            if PHRASE_ENTER.search(text[-200:]):
                self.log("paper prompt: Enter")
                self.send(master, b"\n")
                self.buf.clear()
                continue

            # A check prompt (never look before the grid: "Word #7?" only comes
            # after the paper prompt).
            m = CHECK_PROMPT.search(text)
            if m:
                self.log(f"check prompt #{m.group(1).decode()}")
                if self.stop_at_check:
                    if not sent_ctrl_c:
                        self.log("sending Ctrl-C (SIGINT)")
                        proc.send_signal(signal.SIGINT)
                        sent_ctrl_c = True
                        self.buf.clear()
                    continue
                pos = int(m.group(1))
                word = self.words.get(pos)
                if word is None:
                    self.send(master, b"\n")
                elif self.wrong_left > 0:
                    self.wrong_left -= 1
                    self.answered += 1
                    self.send(master, b"definitelywrong\n")
                else:
                    self.answered += 1
                    self.send(master, (word + "\n").encode())
                self.buf.clear()
                continue

        try:
            os.close(master)
        except OSError:
            pass
        code = proc.wait()
        if self.exit_code is not None:
            return self.exit_code
        if code < 0:
            return 128 - code
        return code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="viaticum")
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--watch", action="append", default=[])
    ap.add_argument("--stop-at-check", action="store_true")
    ap.add_argument("--wrong-once", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--stderr-file", help="copy the child's stderr here (leak scan; no phrase grid)")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("extra", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    extra = list(args.extra)
    if extra and extra[0] == "--":
        extra = extra[1:]
    argv = [args.binary, "--data-dir", args.data_dir, "setup"]
    for w in args.watch:
        argv += ["--watch", w]
    argv += extra

    d = Driver(argv, args.timeout)
    d.stop_at_check = args.stop_at_check
    d.wrong_left = 1 if args.wrong_once else 0
    d.debug = args.debug
    d.stderr_file = args.stderr_file
    code = d.run()
    # The transcript goes to stdout only. It contains the phrase: the caller
    # must keep it in memory, never `tee` it to a file.
    sys.stdout.write(d.transcript.decode(errors="replace"))
    sys.stdout.flush()
    sys.exit(code)


if __name__ == "__main__":
    main()
