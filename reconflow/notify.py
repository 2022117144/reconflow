"""reconflow.notify - Webhook notifications for Slack and Discord.

Delivers formatted diff summaries and lead hints to webhook targets.
Enforces HTTPS, chunking for Discord (2000 chars), request timeouts,
and strict secrecy for webhook URLs.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_TIMEOUT = 10
DISCORD_MAX_LENGTH = 1950


def resolve_webhook_url(explicit_url: str = None) -> str:
    """Resolve webhook URL from explicit parameter or standard environment variables.

    Never logs, prints, or exposes the returned URL.
    """
    if explicit_url and isinstance(explicit_url, str) and explicit_url.strip():
        return explicit_url.strip()

    for env_var in ("RECONFLOW_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL"):
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()

    return ""


def is_discord_webhook(url: str) -> bool:
    """Check if the webhook URL targets Discord."""
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        return "discord.com" in netloc or "discordapp.com" in netloc
    except Exception:
        return False


def chunk_message_for_discord(message: str, max_chunk: int = DISCORD_MAX_LENGTH) -> list:
    """Split a long markdown message into Discord-safe chunks (<= 2000 chars)."""
    if len(message) <= max_chunk:
        return [message]

    chunks = []
    lines = message.splitlines(keepends=True)
    current_chunk = []
    current_len = 0

    for line in lines:
        if current_len + len(line) > max_chunk:
            if current_chunk:
                chunks.append("".join(current_chunk))
                current_chunk = []
                current_len = 0

            # If a single line exceeds max_chunk, hard-slice it
            while len(line) > max_chunk:
                chunks.append(line[:max_chunk])
                line = line[max_chunk:]

        current_chunk.append(line)
        current_len += len(line)

    if current_chunk:
        chunks.append("".join(current_chunk))

    return chunks


def send_webhook(
    webhook_url: str,
    message: str,
    timeout: int = DEFAULT_TIMEOUT,
    opener=None,
) -> bool:
    """Send message to Discord or Slack webhook.

    Ensures HTTPS-only, enforces timeouts, never prints the URL, and fails gracefully.
    """
    if not webhook_url:
        print("[!] Cannot send notification: No webhook URL configured.", file=sys.stderr)
        return False

    # Enforce HTTPS-only
    if not webhook_url.lower().startswith("https://"):
        print("[!] Insecure webhook rejected: Webhook URL must use HTTPS.", file=sys.stderr)
        return False

    if not message.strip():
        return True

    is_discord = is_discord_webhook(webhook_url)
    chunks = chunk_message_for_discord(message) if is_discord else [message]

    _open = opener or urllib.request.urlopen

    success = True
    for chunk in chunks:
        if is_discord:
            payload = {"content": f"```\n{chunk}\n```" if not chunk.startswith("```") else chunk}
        else:
            payload = {"text": chunk}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "reconflow-notifier/0.3",
            },
            method="POST",
        )

        try:
            with _open(req, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                if status not in (200, 204):
                    print(
                        f"[!] Webhook returned non-success HTTP status: {status}",
                        file=sys.stderr,
                    )
                    success = False
        except urllib.error.HTTPError as e:
            print(f"[!] Webhook delivery failed with HTTP {e.code}", file=sys.stderr)
            success = False
        except Exception as e:
            err_name = type(e).__name__
            print(f"[!] Webhook delivery failed ({err_name})", file=sys.stderr)
            success = False

    return success
