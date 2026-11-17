# Running the honeypot in a container isolates it from the host.
FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin honeypot
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && mkdir /data && chown honeypot /data

USER honeypot
WORKDIR /data
EXPOSE 2222
CMD ["sshpot", "run", "--port", "2222", "--log", "/data/sshpot.jsonl", "--key", "/data/sshpot_host.key"]
