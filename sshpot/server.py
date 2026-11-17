"""The SSH honeypot server (needs the 'paramiko' library)."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import paramiko

from .logger import EventLogger
from .shell import MOTD, FakeShell

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

# Logins that "work", so we can see what attackers do once inside.
# Everything else is refused, which looks like a normal server.
WEAK_CREDENTIALS = {
    ("root", "root"), ("root", "123456"), ("root", "password"), ("root", "admin"), ("root", "toor"),
    ("admin", "admin"), ("admin", "123456"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("test", "test"),
}


def load_host_key(path: str) -> paramiko.PKey:
    p = Path(path)
    if p.exists():
        return paramiko.RSAKey(filename=str(p))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(p))
    p.chmod(0o600)
    return key


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip: str, logger: EventLogger, accept_all: bool, max_attempts: int):
        self.ip = ip
        self.logger = logger
        self.accept_all = accept_all
        self.max_attempts = max_attempts
        self.attempts = 0
        self.username = ""
        self.exec_command: str | None = None
        self.ready = threading.Event()

    # --- authentication ---
    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.attempts += 1
        accepted = self.accept_all or (username, password) in WEAK_CREDENTIALS
        self.logger.log("login_success" if accepted else "login_failed", self.ip,
                        username=username, password=password)
        if accepted:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.logger.log("pubkey_attempt", self.ip, username=username,
                        key_type=key.get_name(), fingerprint=key.get_fingerprint().hex())
        return paramiko.AUTH_FAILED

    # --- channels ---
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else command
        self.ready.set()
        return True


def interactive(chan: paramiko.Channel, shell: FakeShell, logger: EventLogger, ip: str) -> None:
    chan.send(MOTD + "\r\n" + shell.prompt)
    buffer = ""
    while True:
        data = chan.recv(1024)
        if not data:
            return
        for ch in data.decode("utf-8", errors="replace"):
            if ch in ("\r", "\n"):
                chan.send("\r\n")
                line = buffer.strip()
                buffer = ""
                if line:
                    logger.log("command", ip, username=shell.user, command=line)
                    out, close = shell.handle(line)
                    if out:
                        chan.send(out + "\r\n")
                    if close:
                        return
                chan.send(shell.prompt)
            elif ch in ("\x7f", "\x08"):          # backspace
                if buffer:
                    buffer = buffer[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":                    # Ctrl+C
                buffer = ""
                chan.send("^C\r\n" + shell.prompt)
            elif ch == "\x04":                    # Ctrl+D
                return
            elif ch.isprintable():
                buffer += ch
                chan.send(ch)
            if len(buffer) > 4096:
                buffer = ""


def handle_client(sock: socket.socket, addr, host_key, logger: EventLogger, accept_all: bool,
                  max_attempts: int, session_timeout: int) -> None:
    ip, port = addr[0], addr[1]
    logger.log("connect", ip, port=port)
    transport = None
    try:
        sock.settimeout(session_timeout)
        transport = paramiko.Transport(sock)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(ip, logger, accept_all, max_attempts)
        transport.start_server(server=server)
        chan = transport.accept(30)
        if transport.remote_version:
            logger.log("client_version", ip, version=transport.remote_version)
        if chan is None:
            return
        server.ready.wait(10)
        shell = FakeShell(server.username or "root")
        if server.exec_command is not None:
            logger.log("command", ip, username=shell.user, command=server.exec_command, mode="exec")
            out, _ = shell.handle(server.exec_command)
            chan.send(out + "\r\n" if out else "")
            chan.send_exit_status(0)
        else:
            interactive(chan, shell, logger, ip)
        chan.close()
    except (paramiko.SSHException, EOFError, OSError, socket.timeout) as exc:
        logger.log("error", ip, error=type(exc).__name__)
    finally:
        if transport is not None:
            transport.close()
        logger.log("disconnect", ip)


def serve(host: str, port: int, key_path: str, log_path: str, accept_all: bool = False,
          max_attempts: int = 6, session_timeout: int = 300, max_clients: int = 50, quiet: bool = False) -> None:
    host_key = load_host_key(key_path)
    logger = EventLogger(log_path, echo=not quiet)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    limiter = threading.BoundedSemaphore(max_clients)
    print(f"sshpot listening on {host}:{port} - logging to {log_path} (Ctrl+C to stop)", flush=True)

    def worker(client, addr):
        try:
            handle_client(client, addr, host_key, logger, accept_all, max_attempts, session_timeout)
        finally:
            limiter.release()
            client.close()

    try:
        while True:
            client, addr = srv.accept()
            if not limiter.acquire(blocking=False):
                client.close()  # too many sessions: protect the machine
                continue
            threading.Thread(target=worker, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.close()
