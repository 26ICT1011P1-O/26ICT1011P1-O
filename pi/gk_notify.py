"""
gk_notify.py - Telegram alerts, commands and approval buttons for GestureKey (standard library only).

Setup (do NOT put the token in the code or commit it):
  1. In Telegram, talk to @BotFather, create a bot, copy the token.
  2. Send any message to your new bot, then read your chat id from
     https://api.telegram.org/bot<TOKEN>/getUpdates   ("chat":{"id": ...}). It is NOT the
     number at the front of the token (that is the bot's own id).
  3. Put both in pi/.env (git-ignored, see .env.example) or set environment variables:
       PowerShell:  $env:TELEGRAM_BOT_TOKEN="123456:ABC..."
                    $env:TELEGRAM_CHAT_ID="123456789"
       Linux/Pi:    export TELEGRAM_BOT_TOKEN=... ; export TELEGRAM_CHAT_ID=...
  4. Test:  python3 gk_lock.py --test-telegram

If the variables are not set, alerts are silently skipped and the lock still works.

SECURITY: anyone can message a public bot, so commands and buttons are only obeyed when they come
from the chat id in TELEGRAM_CHAT_ID (see is_authorized). Everything else is ignored silently:
no reply, so strangers learn nothing. Approval buttons additionally require that the person who
pressed the button IS the owner (so a group chat cannot approve unlocks).

Uses the Telegram Bot API (https://core.telegram.org/bots/api): sendMessage, editMessageText,
getUpdates, answerCallbackQuery, setMyCommands.
"""
import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# Commands shown in Telegram's "/" menu
COMMANDS = [
    ("status", "Watch, lock and lockout state"),
    ("log", "Recent events (e.g. /log 10)"),
    ("summary", "Today's activity"),
    ("lockdown", "Block all unlocks"),
    ("resume", "Allow unlocks again"),
    ("help", "List commands"),
]

_HINTS = {
    401: "token invalid or revoked",
    404: "token wrong (typo, extra characters, or revoked)",
    400: "usually a wrong chat id, or you have not messaged the bot yet",
    403: "bot was blocked or cannot message this chat",
    409: "another program is already reading this bot's messages "
         "(only one machine can run commands at a time)",
}


# ---------------------------------------------------------------------------
# Config file (.env)
# ---------------------------------------------------------------------------
def load_env_file(path: str) -> int:
    """Load KEY=VALUE lines from a .env file into os.environ.
    Real environment variables always win. Returns how many values were set."""
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if value[:1] in ("'", '"') and value.find(value[0], 1) != -1:
                value = value[1:value.find(value[0], 1)]          # quoted: keep everything inside the quotes
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].strip()   # unquoted: drop "  # comment"
            if key and key not in os.environ:
                os.environ[key] = value
                n += 1
    return n


def configured() -> bool:
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


# ---------------------------------------------------------------------------
# Low-level Bot API calls
# ---------------------------------------------------------------------------
def _request(method: str, params: dict, timeout: float = 5.0, parse: bool = False):
    """POST to the Bot API. Returns (ok, data, status, retry_after).
    status is the HTTP code (None for network errors). Never raises, never prints the token."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        return False, None, None, None
    url = f"https://api.telegram.org/bot{token}/{method}"
    body = urllib.parse.urlencode(params).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=timeout) as resp:
            if resp.status != 200:
                return False, None, resp.status, None
            return True, (json.loads(resp.read().decode("utf-8")) if parse else None), 200, None
    except urllib.error.HTTPError as e:
        # Telegram answered with an error. Its 'description' is safe to show (never contains the token).
        reason, retry_after = "", None
        try:
            payload = json.loads(e.read().decode("utf-8", "replace"))
            reason = payload.get("description", "")
            retry_after = (payload.get("parameters") or {}).get("retry_after")
        except Exception:
            pass
        hint = _HINTS.get(e.code, "")
        print(f"[telegram] HTTP {e.code}: {reason}" + (f"  -> {hint}" if hint else ""))
        return False, None, e.code, retry_after
    except Exception as e:
        # Print only the exception class: messages/URLs can contain the bot token.
        print(f"[telegram] request failed ({e.__class__.__name__})")
        return False, None, None, None


def _call(method: str, params: dict, timeout: float = 5.0, parse: bool = False):
    """Like _request but returns just (ok, data)."""
    ok, data, _status, _retry = _request(method, params, timeout, parse)
    return ok, data


def send_telegram(text: str, timeout: float = 5.0) -> bool:
    """Send one message to the configured chat right now. Returns True on success."""
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not (os.environ.get("TELEGRAM_BOT_TOKEN") and chat_id):
        return False
    ok, _ = _call("sendMessage", {"chat_id": chat_id, "text": text}, timeout)
    return ok


def set_my_commands() -> bool:
    """Best effort: fills Telegram's '/' menu. Failure is harmless."""
    cmds = json.dumps([{"command": c, "description": d} for c, d in COMMANDS])
    ok, _ = _call("setMyCommands", {"commands": cmds})
    return ok


# ---------------------------------------------------------------------------
# Reliable alert delivery: a queue that retries instead of dropping messages
# ---------------------------------------------------------------------------
def _send_text(text: str):
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    ok, _data, status, retry_after = _request("sendMessage", {"chat_id": chat_id, "text": text})
    return ok, status, retry_after


class Outbox(threading.Thread):
    """Background sender. Messages go out in order, at most ~1 per second (Telegram's limit).
    Network errors, 429 (honours Telegram's retry_after) and 5xx are retried with exponential
    backoff; permanent errors (bad token, bad chat, ...) are dropped because retrying cannot help."""

    def __init__(self, send=_send_text, sleep=time.sleep, max_tries: int = 5,
                 base_delay: float = 2.0, min_gap: float = 1.1):
        super().__init__(daemon=True, name="telegram-outbox")
        self.send, self.sleep = send, sleep
        self.max_tries, self.base_delay, self.min_gap = max_tries, base_delay, min_gap
        self.q = queue.Queue()
        self._halt = threading.Event()

    def put(self, text: str):
        self.q.put(text)

    def stop(self):
        self._halt.set()

    def deliver(self, text: str) -> bool:
        for attempt in range(1, self.max_tries + 1):
            ok, status, retry_after = self.send(text)
            if ok:
                return True
            if status is not None and status != 429 and status < 500:
                print(f"[telegram] alert dropped (permanent error {status})")
                return False
            if attempt < self.max_tries:
                self.sleep(retry_after if retry_after else self.base_delay * 2 ** (attempt - 1))
        print(f"[telegram] alert dropped after {self.max_tries} tries")
        return False

    def run(self):
        while not self._halt.is_set():
            try:
                text = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.deliver(text)
            finally:
                self.q.task_done()
            self.sleep(self.min_gap)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait (up to timeout) for queued alerts to be sent. Returns True if the queue emptied."""
        end = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.05)
        return not self.q.unfinished_tasks


_outbox = None
_outbox_lock = threading.Lock()


def queue_alert(text: str) -> bool:
    """Queue an alert for reliable delivery. Returns immediately; False if Telegram isn't configured."""
    global _outbox
    if not configured():
        return False
    with _outbox_lock:
        if _outbox is None or not _outbox.is_alive():
            _outbox = Outbox()
            _outbox.start()
    _outbox.put(text)
    return True


def flush_alerts(timeout: float = 5.0) -> bool:
    return _outbox.flush(timeout) if _outbox is not None else True


# ---------------------------------------------------------------------------
# Approval buttons (second factor)
# ---------------------------------------------------------------------------
def send_approval_request(text: str, rid: str, timeout: float = 5.0):
    """Send a message with Approve / Deny buttons. Returns the message id, or None if it failed.
    rid ties the buttons to ONE request, so an old button can never approve a new one."""
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not (os.environ.get("TELEGRAM_BOT_TOKEN") and chat_id):
        return None
    markup = json.dumps({"inline_keyboard": [[
        {"text": "\u2705 Approve", "callback_data": "a:" + rid},
        {"text": "\u26D4 Deny", "callback_data": "d:" + rid},
    ]]})
    ok, data = _call("sendMessage", {"chat_id": chat_id, "text": text, "reply_markup": markup},
                     timeout, parse=True)
    if ok and data and data.get("ok"):
        return data["result"]["message_id"]
    return None


def edit_message(message_id, text: str) -> bool:
    """Replace a message's text and remove its buttons."""
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    ok, _ = _call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text,
                                      "reply_markup": json.dumps({"inline_keyboard": []})})
    return ok


def answer_callback(callback_id, text: str = "") -> bool:
    """Stops the button's loading spinner and shows a short toast."""
    ok, _ = _call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})
    return ok


# ---------------------------------------------------------------------------
# Commands and button presses
# ---------------------------------------------------------------------------
def is_authorized(chat_id) -> bool:
    """Only the owner's chat may control the lock."""
    allowed = os.environ.get("TELEGRAM_CHAT_ID")
    return bool(allowed) and str(chat_id) == str(allowed).strip()


def parse_command(text):
    """'/log@mybot 7' -> ('log', '7').  Normal text -> (None, '')."""
    if not text or not text.startswith("/"):
        return None, ""
    head, _, rest = text.strip().partition(" ")
    cmd = head[1:].split("@", 1)[0].lower()
    return (cmd or None), rest.strip()


class CommandListener(threading.Thread):
    """Long-polls getUpdates on a background (daemon) thread.
    handler(cmd, args) -> reply text for commands; callback_handler(data) -> toast text for buttons."""

    def __init__(self, handler, poll_timeout: int = 25, callback_handler=None):
        super().__init__(daemon=True, name="telegram-commands")
        self.handler = handler
        self.callback_handler = callback_handler
        self.poll_timeout = poll_timeout
        self.offset = None
        self._halt = threading.Event()      # (not '_stop': that name is used inside threading.Thread)

    def stop(self):
        self._halt.set()

    def skip_backlog(self):
        """Ignore anything sent while we were offline, so an old /lockdown cannot fire at startup."""
        ok, data = _call("getUpdates", {"offset": -1, "timeout": 0}, 10, parse=True)
        if ok and data and data.get("result"):
            self.offset = data["result"][-1]["update_id"] + 1

    def _process_callback(self, cq: dict):
        chat_id = ((cq.get("message") or {}).get("chat") or {}).get("id")
        sender_id = (cq.get("from") or {}).get("id")
        # Both the chat AND the person pressing must be the owner (a group chat cannot approve).
        if not (is_authorized(chat_id) and is_authorized(sender_id)):
            print(f"[telegram] ignored button press from unauthorised user {sender_id}")
            return
        if self.callback_handler is None:
            return
        try:
            text = self.callback_handler(cq.get("data") or "")
        except Exception as e:
            print(f"[telegram] error handling button: {e.__class__.__name__}")
            text = "Error"
        answer_callback(cq.get("id"), text or "")

    def process_update(self, upd: dict):
        self.offset = upd["update_id"] + 1          # always advance, even for ignored messages
        if upd.get("callback_query"):
            self._process_callback(upd["callback_query"])
            return
        msg = upd.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        text = msg.get("text")
        if chat_id is None or text is None:
            return
        if not is_authorized(chat_id):
            print(f"[telegram] ignored message from unauthorised chat {chat_id}")
            return                                  # no reply: strangers learn nothing
        cmd, args = parse_command(text)
        if cmd is None:
            return
        try:
            reply = self.handler(cmd, args)
        except Exception as e:
            print(f"[telegram] error handling /{cmd}: {e.__class__.__name__}")
            reply = f"Error handling /{cmd}"
        if reply:
            send_telegram(reply)

    def run(self):
        self.skip_backlog()
        set_my_commands()
        while not self._halt.is_set():
            params = {"timeout": self.poll_timeout}
            if self.offset is not None:
                params["offset"] = self.offset
            ok, data = _call("getUpdates", params, self.poll_timeout + 10, parse=True)
            if not ok or not data:
                self._halt.wait(5)                  # back off instead of hammering the API
                continue
            for upd in data.get("result", []):
                self.process_update(upd)
