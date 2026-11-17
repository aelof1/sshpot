"""Statistics from the honeypot log (works without paramiko)."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Stats:
    connections: int = 0
    unique_ips: set = field(default_factory=set)
    attempts: int = 0
    successes: int = 0
    ips: Counter = field(default_factory=Counter)
    usernames: Counter = field(default_factory=Counter)
    passwords: Counter = field(default_factory=Counter)
    combos: Counter = field(default_factory=Counter)
    commands: Counter = field(default_factory=Counter)
    clients: Counter = field(default_factory=Counter)
    downloads: list = field(default_factory=list)
    per_day: Counter = field(default_factory=Counter)


def load(path: str) -> Stats:
    s = Stats()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind, ip = ev.get("event"), ev.get("ip", "?")
            if kind == "connect":
                s.connections += 1
                s.unique_ips.add(ip)
                s.per_day[ev.get("time", "")[:10]] += 1
            elif kind in ("login_failed", "login_success"):
                s.attempts += 1
                s.ips[ip] += 1
                user, pwd = ev.get("username", ""), ev.get("password", "")
                s.usernames[user] += 1
                s.passwords[pwd] += 1
                s.combos[f"{user}:{pwd}"] += 1
                if kind == "login_success":
                    s.successes += 1
            elif kind == "command":
                cmd = ev.get("command", "")
                s.commands[cmd] += 1
                if any(tool in cmd for tool in ("wget ", "curl ", "tftp ", "ftpget ")):
                    s.downloads.append((ip, cmd))
            elif kind == "client_version":
                s.clients[ev.get("version", "")] += 1
    return s


def top(counter: Counter, n: int) -> str:
    if not counter:
        return "   (none)"
    width = max(len(str(k)) for k, _ in counter.most_common(n))
    return "\n".join(f"   {str(k)[:60]:<{min(width, 60)}}  {v}" for k, v in counter.most_common(n))


def report(s: Stats, n: int = 10) -> str:
    parts = [
        f"Connections      : {s.connections} from {len(s.unique_ips)} unique IPs",
        f"Login attempts   : {s.attempts} ({s.successes} accepted by the honeypot)",
        "",
        f"Top {n} attacking IPs:", top(s.ips, n), "",
        f"Top {n} usernames:", top(s.usernames, n), "",
        f"Top {n} passwords:", top(s.passwords, n), "",
        f"Top {n} username:password:", top(s.combos, n), "",
        f"Top {n} commands after login:", top(s.commands, n), "",
        "SSH clients used:", top(s.clients, 5),
    ]
    if s.downloads:
        parts += ["", "Download attempts (malware URLs - do NOT open them):"]
        parts += [f"   {ip:<15} {cmd[:100]}" for ip, cmd in s.downloads[:n]]
    if s.per_day:
        parts += ["", "Connections per day:"]
        biggest = max(s.per_day.values())
        for day in sorted(s.per_day):
            bar = "#" * max(1, round(40 * s.per_day[day] / biggest))
            parts.append(f"   {day}  {bar} {s.per_day[day]}")
    return "\n".join(parts)


def to_json(s: Stats, n: int = 10) -> str:
    return json.dumps({
        "connections": s.connections, "unique_ips": len(s.unique_ips),
        "attempts": s.attempts, "successes": s.successes,
        "top_ips": s.ips.most_common(n), "top_usernames": s.usernames.most_common(n),
        "top_passwords": s.passwords.most_common(n), "top_combos": s.combos.most_common(n),
        "top_commands": s.commands.most_common(n), "downloads": s.downloads,
        "per_day": dict(sorted(s.per_day.items())),
    }, indent=2)
