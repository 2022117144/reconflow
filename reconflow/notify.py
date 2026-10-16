"""
reconflow.notify
-----------------
Fire-and-forget webhook notification (Discord or Slack-compatible)
when a scan finishes, so you don't have to babysit long-running scans.
"""

import json
import urllib.request


def send_webhook(webhook_url: str, domain: str, stats: dict):
    lines = [f"**reconflow finished: {domain}**"]
    for label, value in stats.items():
        lines.append(f"- {label}: {value}")
    payload = {"content": "\n".join(lines)}  # Discord format; Slack handles extra fields

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        print("[+] Notification sent")
    except Exception as e:
        print(f"[!] Notification failed: {e}")
