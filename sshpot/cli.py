"""sshpot command line: 'run' starts the honeypot, 'stats' analyses the log."""

from __future__ import annotations

import argparse
import sys

from . import __version__


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sshpot", description="Low-interaction SSH honeypot.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="start the honeypot")
    r.add_argument("--host", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    r.add_argument("--port", type=int, default=2222, help="port (default 2222)")
    r.add_argument("--log", default="sshpot.jsonl", help="log file (JSON lines)")
    r.add_argument("--key", default="sshpot_host.key", help="host key file (created if missing)")
    r.add_argument("--accept-all", action="store_true", help="accept every password (more commands captured)")
    r.add_argument("--timeout", type=int, default=300, help="max seconds per session")
    r.add_argument("--max-clients", type=int, default=50, help="max simultaneous sessions")
    r.add_argument("--quiet", action="store_true", help="don't print events to the terminal")

    s = sub.add_parser("stats", help="statistics from a log file")
    s.add_argument("log", nargs="?", default="sshpot.jsonl")
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--json", action="store_true")

    args = p.parse_args(argv)

    if args.command == "stats":
        from .stats import load, report, to_json
        try:
            st = load(args.log)
        except FileNotFoundError:
            print(f"error: {args.log} not found", file=sys.stderr)
            return 2
        print(to_json(st, args.top) if args.json else report(st, args.top))
        return 0

    try:
        from .server import serve
    except ImportError:
        print("error: the 'paramiko' library is required. Install it with: pip install paramiko", file=sys.stderr)
        return 2
    try:
        serve(args.host, args.port, args.key, args.log, args.accept_all,
              session_timeout=args.timeout, max_clients=args.max_clients, quiet=args.quiet)
    except PermissionError:
        print(f"error: permission denied for port {args.port}. Ports below 1024 need root; "
              "use 2222 and redirect (see README).", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
