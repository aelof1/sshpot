"""A fake shell. NOTHING is ever executed: every answer is hard-coded text."""

from __future__ import annotations

import random
import shlex

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"""

FAKE_FILES = {
    "/root": ["backup.sh", "notes.txt", ".bash_history", ".ssh"],
    "/home/ubuntu": ["app", "deploy.sh"],
    "/tmp": [],
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "srv", "tmp", "usr", "var"],
}

MOTD = (
    "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n\r\n"
    "Last login: Mon Nov 16 09:12:44 2026 from 10.0.0.12\r\n"
)


class FakeShell:
    def __init__(self, username: str = "root", hostname: str = "srv-prod-01"):
        self.user = username
        self.host = hostname
        self.cwd = "/root" if username == "root" else f"/home/{username}"

    @property
    def prompt(self) -> str:
        sign = "#" if self.user == "root" else "$"
        here = "~" if self.cwd in ("/root", f"/home/{self.user}") else self.cwd
        return f"{self.user}@{self.host}:{here}{sign} "

    def handle(self, line: str) -> tuple[str, bool]:
        """Return (output, should_close). Commands chained with ; or && are split."""
        outputs = []
        for part in line.replace("&&", ";").split(";"):
            part = part.strip()
            if not part:
                continue
            out, close = self._one(part)
            if out:
                outputs.append(out)
            if close:
                return "\r\n".join(outputs), True
        return "\r\n".join(outputs), False

    def _one(self, command: str) -> tuple[str, bool]:
        try:
            args = shlex.split(command)
        except ValueError:
            args = command.split()
        if not args:
            return "", False
        cmd = args[0].split("/")[-1]

        if cmd in ("exit", "logout", "quit"):
            return "logout", True
        if cmd == "whoami":
            return self.user, False
        if cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)" if self.user == "root" \
                else f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)", False
        if cmd == "hostname":
            return self.host, False
        if cmd == "pwd":
            return self.cwd, False
        if cmd == "uname":
            if "-a" in args:
                return (f"Linux {self.host} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 "
                        "x86_64 x86_64 x86_64 GNU/Linux"), False
            return "Linux", False
        if cmd == "cd":
            target = args[1] if len(args) > 1 else "~"
            if target in ("~", ""):
                self.cwd = "/root" if self.user == "root" else f"/home/{self.user}"
            elif target.startswith("/"):
                self.cwd = target.rstrip("/") or "/"
            elif target == "..":
                self.cwd = self.cwd.rsplit("/", 1)[0] or "/"
            else:
                self.cwd = f"{self.cwd.rstrip('/')}/{target}"
            return "", False
        if cmd == "ls":
            path = next((a for a in args[1:] if not a.startswith("-")), self.cwd)
            files = FAKE_FILES.get(path, [])
            if "-a" not in " ".join(args):
                files = [f for f in files if not f.startswith(".")]
            return "  ".join(files), False
        if cmd == "cat":
            if any("passwd" in a for a in args):
                return FAKE_PASSWD.replace("\n", "\r\n"), False
            if any("cpuinfo" in a for a in args):
                return "processor\t: 0\r\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", False
            return f"cat: {args[-1]}: Permission denied" if len(args) > 1 else "", False
        if cmd == "nproc":
            return "4", False
        if cmd == "free":
            return ("               total        used        free      shared  buff/cache   available\r\n"
                    "Mem:         8141616     1702384     4263212       10588     2176020     6150524"), False
        if cmd == "uptime":
            return f" 10:{random.randint(10, 59)}:02 up 42 days,  3:17,  1 user,  load average: 0.08, 0.03, 0.01", False
        if cmd in ("w", "who"):
            return f"{self.user}    pts/0        2026-11-17 10:02 (10.0.0.12)", False
        if cmd == "echo":
            return " ".join(args[1:]), False
        if cmd in ("wget", "curl"):
            # attackers often download malware here: we log the URL but download nothing
            return f"{cmd}: unable to resolve host address", False
        if cmd in ("sudo", "su"):
            return "", False
        if cmd in ("history", "clear", "export", "unset", "chmod", "rm", "mkdir", "touch", "kill", "pkill"):
            return "", False
        return f"-bash: {cmd}: command not found", False
