#!/usr/bin/env python3
"""
HoneySOC — real-time Telegram alerting.

Tails Cowrie's JSON log and pushes a Telegram message for high-severity
events only (successful login, malware download). Low-severity noise such
as failed logins is deliberately NOT alerted on, to avoid alert fatigue.

Secrets are read from /root/honeysoc-alerts/.env (never hardcoded).
Runs as a systemd service (see deploy.sh).
"""
import json
import os
import time
import html
import urllib.request
import urllib.parse

ENV_PATH = "/root/honeysoc-alerts/.env"
LOG_PATH = "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json"


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k] = v
    return env


ENV = load_env(ENV_PATH)
TOKEN = ENV["TELEGRAM_TOKEN"]
CHAT_ID = ENV["TELEGRAM_CHAT_ID"]


def send(msg):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"}
    ).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        print("telegram send error:", e)


def handle(ev):
    eid = ev.get("eventid", "")
    ip = ev.get("src_ip", "?")

    if eid == "cowrie.login.success":
        send(
            "🚨 <b>Successful login</b>\n"
            f"IP: <code>{ip}</code>\n"
            f"User: {html.escape(str(ev.get('username')))}\n"
            f"Pass: {html.escape(str(ev.get('password')))}"
        )
    elif eid == "cowrie.session.file_download":
        send(
            "🦠 <b>Malware download</b>\n"
            f"IP: <code>{ip}</code>\n"
            f"URL: {html.escape(str(ev.get('url')))}"
        )


def main():
    send("✅ HoneySOC alerting started")
    with open(LOG_PATH) as f:
        f.seek(0, 2)  # start at end — only new events
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                handle(json.loads(line))
            except Exception:
                pass  # ignore malformed / partial lines


if __name__ == "__main__":
    main()
