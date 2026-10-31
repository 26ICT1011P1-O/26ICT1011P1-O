"""
gk_notify.py - Telegram alerts for GestureKey (standard library only, no extra install).

Setup (do NOT put the token in the code or commit it):
  1. In Telegram, talk to @BotFather, create a bot, copy the token.
  2. Send any message to your new bot, then open
     https://api.telegram.org/bot<TOKEN>/getUpdates  and read "chat":{"id": ...}
  3. Set two environment variables before running gk_lock.py:
       PowerShell:  $env:TELEGRAM_BOT_TOKEN="123456:ABC..."
                    $env:TELEGRAM_CHAT_ID="123456789"
       Linux/Pi:    export TELEGRAM_BOT_TOKEN=... ; export TELEGRAM_CHAT_ID=...
  4. Test:  python3 gk_lock.py --test-telegram

If the variables are not set, alerts are silently skipped and the lock still works.
Uses the Telegram Bot API 'sendMessage' method (https://core.telegram.org/bots/api).
"""
import os
import urllib.parse
import urllib.request


def configured() -> bool:
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


def send_telegram(text: str, timeout: float = 5.0) -> bool:
    """Send one message. Returns True on success, False otherwise. Never raises."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat_id):
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=timeout) as resp:
            return resp.status == 200
    except Exception as e:
        # Print only the exception class: messages/URLs can contain the bot token.
        print(f"[telegram] send failed ({e.__class__.__name__})")
        return False
