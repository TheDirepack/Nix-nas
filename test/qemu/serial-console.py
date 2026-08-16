#!/usr/bin/env python3
"""
Drive a QEMU serial console over a unix socket with a tiny expect-style DSL.

There is no `expect` on the host, so this script implements just enough of one
to drive an unattended NixOS install over the virtual serial port.

DSL (one directive per line, '#' starts a comment):

  loginroot                     wait for a login prompt OR a root shell; log in
                                as root with an empty password if prompted
  wait:<regex>                  wait until <regex> matches the accumulated
                                output (required; timeout = --wait-timeout)
  waitopt:<regex>,<secs>        wait up to <secs> for <regex>; continue either way
  any:<r1>|<r2>|...             wait until one regex matches; store its index
  if:<index> ... endif          skip block unless the last `any` matched <index>
  send:<text>                   send <text> (\\n becomes newline) + trailing LF
  sendraw:<text>                send <text> verbatim (no trailing newline)
  ctrlc                         send ^C
  sleep:<secs>                  wait

`loginroot` timeout is controlled by --boot-timeout (the kernel takes a while).
"""

import argparse
import re
import socket
import time


def parse_script(path):
    commands = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "\t" in line and not stripped.startswith(
                ("#", "wait", "any", "send", "sleep", "loginroot", "ctrlc", "if", "endif")
            ):
                # Indented block bodies inside if/endif are allowed and skipped
                # by the parser via dedicated handling; ignore stray tabs.
                stripped = line.strip()
            commands.append(stripped)
    return commands


class Console:
    def __init__(self, sock_path, log_path, connect_timeout=90):
        self.sock_path = sock_path
        self.log_fh = open(log_path, "ab") if log_path else None
        self.buf = ""
        deadline = time.time() + connect_timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(sock_path)
                self.sock.settimeout(0.2)
                break
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                self.sock.close()
                if time.time() > deadline:
                    raise SystemExit(f"ERROR: could not connect to serial socket {sock_path}")
                time.sleep(0.5)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        if self.log_fh:
            self.log_fh.close()

    def _pump(self, timeout):
        """Read available serial data for up to `timeout` seconds."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                data = self.sock.recv(4096)
                if not data:
                    time.sleep(0.1)
                    continue
                self.buf += data.decode("utf-8", errors="replace")
                if self.log_fh:
                    self.log_fh.write(data)
                    self.log_fh.flush()
            except socket.timeout:
                return
            except (BlockingIOError, ConnectionResetError):
                return

    def wait(self, patterns, timeout, what="output"):
        """patterns: list of compiled regexes. Returns matched index or None."""
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        end = time.time() + timeout
        while time.time() < end:
            for idx, rx in enumerate(compiled):
                if rx.search(self.buf):
                    return idx
            self._pump(min(0.2, max(0.05, end - time.time())))
        return None

    def send(self, text, newline=True):
        data = text.replace("\\n", "\n").encode("utf-8")
        if newline and not data.endswith(b"\n"):
            data += b"\n"
        self.sock.sendall(data)


def main():
    ap = argparse.ArgumentParser(description="Expect-style serial console driver")
    ap.add_argument("--socket", required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--log", default=None)
    ap.add_argument("--connect-timeout", type=int, default=90)
    ap.add_argument("--wait-timeout", type=int, default=300)
    ap.add_argument("--boot-timeout", type=int, default=300)
    args = ap.parse_args()

    cmds = parse_script(args.script)
    con = Console(args.socket, args.log, args.connect_timeout)

    def fail(msg):
        con.close()
        raise SystemExit(f"ERROR: {msg}")

    i = 0
    last_any = None
    n = len(cmds)
    while i < n:
        cmd = cmds[i]
        if cmd == "loginroot":
            # NixOS 26.05 live ISOs auto-login as `nixos`; older ones show a
            # `login:` prompt. Reach a shell either way, then escalate to root
            # via passwordless `sudo -i` (the live `nixos` user is in wheel).
            con.send("")  # newline: harmless at a prompt, elicits output if idle
            idx = con.wait(["login:", r"(?:nixos|root)@nixos[^$]*[#$]"], args.boot_timeout, "login prompt / shell")
            if idx is None:
                fail("timed out waiting for the login prompt or shell after boot")
            if idx == 0:
                # `login:` was shown; give auto-login a moment, else type it.
                if con.wait([r"(?:nixos|root)@nixos[^$]*[#$]"], 20) is None:
                    con.send("nixos")
                    if con.wait([r"[Pp]assword:", r"(?:nixos|root)@nixos[^$]*[#$]"], args.wait_timeout) == 0:
                        con.send("")
                        con.wait([r"(?:nixos|root)@nixos[^$]*[#$]"], args.wait_timeout)
            if re.search(r"root@nixos[^$]*#", con.buf):
                return  # already root
            con.send("sudo -i")
            if con.wait([r"root@nixos[^$]*#"], args.wait_timeout) is None:
                fail("could not escalate to a root shell (sudo -i failed)")
        elif cmd.startswith("wait:"):
            rx = cmd[len("wait:") :]
            if con.wait([rx], args.wait_timeout) is None:
                fail(f"timeout waiting for: {rx!r}  (last output: ...{con.buf[-400:]!r})")
        elif cmd.startswith("waitopt:"):
            rest = cmd[len("waitopt:") :]
            rx, _, secs = rest.rpartition(",")
            try:
                secs = float(secs)
            except ValueError:
                secs = 15.0
            con.wait([rx], secs)
        elif cmd.startswith("any:"):
            rxs = cmd[len("any:") :].split("|")
            idx = con.wait(rxs, args.wait_timeout)
            last_any = idx
            if idx is None:
                fail(f"timeout waiting for any of: {rxs!r}")
        elif cmd.startswith("if:"):
            target = int(cmd[len("if:") :])
            if last_any != target:
                depth = 1
                while i < n and depth:
                    i += 1
                    if i >= n:
                        break
                    sub = cmds[i]
                    if sub.startswith("if:"):
                        depth += 1
                    elif sub == "endif":
                        depth -= 1
                if i >= n:
                    fail("unbalanced if/endif")
        elif cmd == "endif":
            pass
        elif cmd.startswith("send:"):
            con.send(cmd[len("send:") :])
        elif cmd.startswith("sendraw:"):
            con.send(cmd[len("sendraw:") :], newline=False)
        elif cmd == "ctrlc":
            con.sock.sendall(b"\x03")
        elif cmd.startswith("sleep:"):
            time.sleep(float(cmd[len("sleep:") :]))
        else:
            fail(f"unknown directive: {cmd!r}")
        i += 1

    con.close()
    print("OK: script completed")


if __name__ == "__main__":
    main()
