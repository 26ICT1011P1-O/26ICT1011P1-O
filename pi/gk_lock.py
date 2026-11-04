#!/usr/bin/env python3
"""
gk_lock.py - Raspberry Pi side of GestureKey (BLE central + lock controller)

Two BLE devices, one laptop in charge (full message list in gk_proto.py):

  WATCH  (gesture)   laptop 'Q' -> watch 'Z'+wn | laptop 'C'+pn, 'M'+tag_P(wn,pn) | watch 'R'+tag_A(wn,pn) or 'N'
                     laptop may add 'W'+secs (approve on phone), 'D'+code (decision), 'L', 'T', 'S'
  LOCK   (servo)     laptop 'Q' -> lock 'Z'+ln | laptop 'O'+tag_O(ln) -> lock 'Y'+tag_Y(ln) or 'X'; lock closes itself

  The watch only prompts for a gesture after the laptop proves it knows the key (mutual authentication),
  and the lock only moves after the laptop proves it knows the key for a nonce the LOCK just chose.

Attribution: BLE UART UUIDs are the Nordic UART Service used by the TinyCircuits
SmartWatch example. BLE client uses the 'bleak' library; servo uses 'gpiozero'.
Everything else is our own work.

Run:  pip install bleak gpiozero pigpio
      python3 gk_lock.py --scan     (debug: list nearby BLE devices)
      python3 gk_lock.py --test-telegram   (check Telegram alert setup)
      python3 gk_lock.py            (press Enter to request an unlock)
"""
import asyncio, contextlib, datetime, hmac, hashlib, json, os, secrets, sys, time, warnings
from collections import Counter
import gk_notify                    # Telegram alerts (see gk_notify.py)
import gk_proto                     # wire protocol: tags and nonces (twin of the firmware's gk_auth.h)
warnings.filterwarnings("ignore")   # silence gpiozero pin-factory warnings when not on a Pi

# Optional pi/.env (git-ignored) holds the Telegram token etc. Real environment variables win.
_n = gk_notify.load_env_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
if _n:
    print(f"[config] loaded {_n} setting(s) from .env")

NAME_PREFIX = "GKey"                                   # the WATCH's advertised name (set in its UART.ino)
LOCK_PREFIX = "GLock"                                  # the LOCK's advertised name (set in LockKey/UART.ino)
NUS_WRITE  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"    # watch receives challenges here
NUS_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"    # watch sends responses here
KEY_FILE = os.environ.get("GK_KEY_FILE", os.path.join(os.path.dirname(__file__), "gk_key.txt"))
KEY = bytes.fromhex(open(KEY_FILE).read().strip())

RESPONSE_TIMEOUT_S = 15      # must be LONGER than the watch's CHALLENGE_TIMEOUT_MS (12 s) or the laptop gives up first
HANDSHAKE_TIMEOUT_S = 3      # how long to wait for a device's nonce
LOCK_TIMEOUT_S = 5           # how long to wait for the lock to confirm it opened
MAX_FAILS = 3
LOCKOUT_S = 30
UNLOCK_HOLD_S = 5
SERVO_PIN = 18
LOG_FILE = os.environ.get("GK_LOG_FILE", os.path.join(os.path.dirname(__file__), "access_log.jsonl"))
WATCH_ADDR = os.environ.get("GK_ADDR")      # optional: skip name matching, connect by address
LOCK_NAME = os.environ.get("GK_LOCK_NAME", "Front door")   # shown in every Telegram message
LOCKDOWN_FILE = LOG_FILE + ".lockdown"      # exists = lockdown on (survives a restart)
STATE_FILE = LOG_FILE + ".state"            # failure / timeout counters and lockout end time (survive a restart)
LOCK_ADDR = os.environ.get("GK_LOCK_ADDR")  # optional: connect to the lock by address
# 'ble' = a second TinyScreen+ with the servo shield is the lock;  'sim' = just print UNLOCKED (testing, or a Pi servo)
ACTUATOR = os.environ.get("GK_ACTUATOR", "sim").lower()

def _env_float(name: str, default: float) -> float:
    """Read a number from the environment; a typo gives a clear message instead of a traceback."""
    raw = os.environ.get(name, str(default))
    try:
        return float(raw)
    except ValueError:
        print(f"[config error] {name} must be a number, but it is {raw!r}")
        raise SystemExit(2)

def _env_int(name: str, default: int) -> int:
    return int(_env_float(name, default))

def _parse_hours(raw):
    """'7-23' -> (7, 23): unlocks allowed from 07:00 to 22:59. '22-6' wraps past midnight. Empty -> None."""
    if not raw:
        return None
    try:
        start, end = (int(x) for x in raw.split("-"))
        if not (0 <= start <= 23 and 0 <= end <= 24):
            raise ValueError
    except ValueError:
        print(f"[config error] GK_ALLOWED_HOURS must look like 7-23 (hours 0-23), but it is {raw!r}")
        raise SystemExit(2)
    return start, end

ALLOWED_HOURS = _parse_hours(os.environ.get("GK_ALLOWED_HOURS"))   # None = unlocks allowed at any time
SEND_DOOR_STATUS = True      # tell the watch whether the door is locked or unlocked
# Challenges nobody answered, in a row. Reaching this triggers a lockout, so an attacker cannot keep
# requesting challenges forever. 0 = unanswered challenges never cause a lockout.
MAX_TIMEOUTS = _env_int("GK_MAX_TIMEOUTS", 5)
BLE_GAP_S = 0.2              # pause between BLE writes: the watch has a single receive buffer
# Testing aid: failed attempts never lock you out. OFF by default, so the lockout (and its Telegram
# alert) works in the real demo. Turn on with GK_TEST_NO_LOCKOUT=1 in pi/.env while testing.
TEST_NO_LOCKOUT = os.environ.get("GK_TEST_NO_LOCKOUT") == "1"

# ---- optional second factor: after a valid gesture, you must also tap Approve in Telegram ----
REQUIRE_APPROVAL = os.environ.get("GK_REQUIRE_APPROVAL") == "1"
APPROVAL_TIMEOUT_S = _env_float("GK_APPROVAL_TIMEOUT", 20)
APPROVAL_FAIL_OPEN = os.environ.get("GK_APPROVAL_FAIL_OPEN") == "1"   # allow gesture-only if Telegram is unreachable
DAILY_SUMMARY_AT = os.environ.get("GK_DAILY_SUMMARY_AT")              # e.g. "21:00" (24 h clock); unset = off

# ---- servo (falls back to printing when not on a Pi, so you can test on a laptop) ----
try:
    from gpiozero import AngularServo
    _servo = AngularServo(SERVO_PIN, min_angle=0, max_angle=180)
    _servo.angle = 0
except Exception as e:
    _servo = None
    print(f"[servo] hardware not available ({e.__class__.__name__}); simulating")

def set_lock(unlocked: bool):
    if _servo:
        _servo.angle = 90 if unlocked else 0
    print("[lock]", "UNLOCKED" if unlocked else "locked")

def log(event: str, detail: str = ""):
    rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, "detail": detail}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("[log]", rec)

# ---- Telegram alerts: queued in the background with retries, so a slow or down network never delays the lock ----
_last_sent = {}          # alert key -> time last sent (used for cooldowns)

def fire_alert(text: str, key: str = None, cooldown: float = 0.0):
    """Queue a Telegram alert. With key+cooldown, repeats are suppressed. Never raises."""
    if key and cooldown:
        now = time.time()
        if now - _last_sent.get(key, -1e9) < cooldown:
            return
        _last_sent[key] = now
    try:
        gk_notify.queue_alert(text)
    except Exception as e:
        print(f"[alert] could not queue ({e.__class__.__name__})")

fails = 0
timeouts = 0             # consecutive challenges nobody answered
fail_reasons = []        # why each recent attempt failed (shown in the lockout alert)
locked_until = 0.0
watch_connected = False
watch_addr = ""
approval = {}            # the one approval request in flight: id, future, loop
lockdown = os.path.exists(LOCKDOWN_FILE)

def hms() -> str:
    return time.strftime("%H:%M:%S")

def set_lockdown(on: bool):
    """Block (or allow) all unlock requests. Stored in a file so a restart does not undo it."""
    global lockdown
    lockdown = on
    if on:
        open(LOCKDOWN_FILE, "w").close()
    elif os.path.exists(LOCKDOWN_FILE):
        os.remove(LOCKDOWN_FILE)
    log("lockdown", "enabled via Telegram" if on else "disabled via Telegram")

# ---- Telegram commands (called from the listener thread; only the owner's chat gets here) ----
def read_all_log():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        return [json.loads(l) for l in f if l.strip()]

def read_log(n: int):
    return read_all_log()[-n:]

def build_summary(rows, day: str) -> str:
    """Plain-text summary of one day (day = 'YYYY-MM-DD')."""
    today = [r for r in rows if r["t"].startswith(day)]
    c = Counter(r["event"] for r in today)
    unlock_times = [r["t"][11:16] for r in today if r["event"] == "unlock"]
    lines = [f"{LOCK_NAME} summary for {day}",
             f"Unlocks: {c['unlock']}" + (f" (at {', '.join(unlock_times[:10])})" if unlock_times else ""),
             f"Failed attempts: {c['fail']}",
             f"Lockouts: {c['lockout']}",
             f"Timeouts: {c['timeout']}",
             f"Blocked by lockdown: {c['blocked']}",
             f"Watch disconnects: {c['disconnected']}"]
    if not today:
        lines.append("(no events today)")
    return "\n".join(lines)

def seconds_until(hhmm: str, now: datetime.datetime = None) -> float:
    """Seconds from now until the next HH:MM (today if still ahead, otherwise tomorrow)."""
    hh, mm = (int(x) for x in hhmm.split(":"))
    now = now or datetime.datetime.now()
    target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return (target - now).total_seconds()

async def daily_summary_loop():
    while True:
        await asyncio.sleep(seconds_until(DAILY_SUMMARY_AT))
        fire_alert(build_summary(read_all_log(), time.strftime("%Y-%m-%d")))
        await asyncio.sleep(61)          # make sure we do not fire twice in the same minute

def fmt_row(r) -> str:
    return f"{r['t'][11:]} {r['event']}" + (f" - {r['detail']}" if r.get("detail") else "")

def handle_command(cmd: str, args: str) -> str:
    if cmd in ("start", "help"):
        return LOCK_NAME + " - GestureKey commands:\n" + "\n".join(f"/{c} - {d}" for c, d in gk_notify.COMMANDS)
    if cmd == "status":
        remaining = int(locked_until - time.time())
        last = read_log(1)
        return "\n".join([
            f"{LOCK_NAME} status",
            "Watch: " + (f"connected ({watch_addr})" if watch_connected else "NOT connected"),
            *(["Lock: " + ("connected" if lock.connected else "NOT connected")] if ACTUATOR == "ble" else []),
            "Lockdown: " + ("ON" if lockdown else "off"),
            *([f"Allowed hours: {ALLOWED_HOURS[0]:02d}:00-{ALLOWED_HOURS[1]:02d}:00"] if ALLOWED_HOURS else []),
            "Lockout: " + (f"{remaining} s left" if remaining > 0 else "none"),
            f"Failed attempts: {fails}/{MAX_FAILS}",
            *([f"Unanswered challenges: {timeouts}/{MAX_TIMEOUTS}"] if MAX_TIMEOUTS else []),
            "Last event: " + (fmt_row(last[0]) if last else "(none yet)"),
        ])
    if cmd == "log":
        try:
            n = max(1, min(10, int(args))) if args else 5
        except ValueError:
            n = 5
        rows = read_log(n)
        return "\n".join(fmt_row(r) for r in rows) if rows else "(no events yet)"
    if cmd == "summary":
        return build_summary(read_all_log(), time.strftime("%Y-%m-%d"))
    if cmd == "lockdown":
        set_lockdown(True)
        return f"LOCKDOWN ON. {LOCK_NAME} will not unlock until you send /resume."
    if cmd == "resume":
        set_lockdown(False)
        return "Lockdown off. Unlocking is allowed again."
    return "Unknown command. Try /help"

# ---- one BLE peripheral = one Link: send writes, wait for notifications ----
class Link:
    def __init__(self, name: str):
        self.name = name
        self.client = None
        self._q = None

    @property
    def connected(self) -> bool:
        return self.client is not None and bool(getattr(self.client, "is_connected", True))

    def flush(self):
        """Forget anything received so far (call before a new request so stale replies cannot be mistaken for answers)."""
        self._q = asyncio.Queue()

    def on_notify(self, _sender, data):
        if self._q is not None:
            self._q.put_nowait(bytes(data))

    async def send(self, data: bytes):
        await self.client.write_gatt_char(NUS_WRITE, data, response=False)

    async def expect(self, kinds: bytes, timeout: float):
        """Wait for a notification whose first byte is one of `kinds`. Returns it, or None on timeout."""
        if self._q is None:
            self.flush()
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                msg = await asyncio.wait_for(self._q.get(), left)
            except asyncio.TimeoutError:
                return None
            if msg and msg[:1] in kinds:
                return msg

watch = Link("watch")
lock = Link("lock")

async def safe_send(link: Link, data: bytes):
    """Write, but never raise: a dropped link must not crash an unlock attempt."""
    try:
        await link.send(data)
    except Exception as e:
        print(f"[{link.name}] message {data[:1]!r} not sent ({e.__class__.__name__})")

# ---- counters that survive a restart (otherwise restarting the script would reset the lockout) ----
def save_state():
    data = {"fails": fails, "timeouts": timeouts, "locked_until": locked_until,
            "reasons": list(fail_reasons)[-10:]}
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATE_FILE)              # atomic: a crash cannot leave half a file
    except OSError as e:
        print(f"[state] could not save ({e.__class__.__name__})")

def load_state():
    """Restore counters. A damaged or missing file is ignored; an expired lockout is dropped."""
    global fails, timeouts, locked_until
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
        f_, t_, lu = int(d.get("fails", 0)), int(d.get("timeouts", 0)), float(d.get("locked_until", 0))
        reasons = [str(r) for r in d.get("reasons", [])][-10:]
    except (OSError, ValueError, TypeError, AttributeError):
        return
    fails = max(0, min(f_, MAX_FAILS - 1))
    timeouts = max(0, min(t_, MAX_TIMEOUTS - 1)) if MAX_TIMEOUTS else 0
    locked_until = lu if lu > time.time() else 0.0
    fail_reasons[:] = reasons[:fails]
    if fails or timeouts or locked_until:
        print(f"[state] restored: {fails} failed, {timeouts} unanswered"
              + (f", lockout {int(locked_until - time.time())} s left" if locked_until else ""))

# ---- extras for the watch display: door status, clock sync, allowed hours (added by a teammate) ----
async def send_status(client, code: bytes):
    """Tell the watch the door state: b'U' = unlocked, b'K' = locked. Never raises."""
    if not SEND_DOOR_STATUS:
        return
    try:
        await client.write_gatt_char(NUS_WRITE, b"S" + code, response=False)
    except Exception as e:
        print(f"[status] not sent ({e.__class__.__name__})")

async def send_time(client):
    """Set the watch clock from the Pi's local time. Never raises."""
    t = time.localtime()
    try:
        await client.write_gatt_char(NUS_WRITE, bytes([ord("T"), t.tm_hour, t.tm_min, t.tm_sec]), response=False)
    except Exception as e:
        print(f"[time] not sent ({e.__class__.__name__})")

def hours_allowed() -> bool:
    if ALLOWED_HOURS is None:
        return True
    start, end = ALLOWED_HOURS
    h = time.localtime().tm_hour
    return (start <= h < end) if start < end else (h >= start or h < end)

# ---- second factor: Approve / Deny buttons in Telegram ----
def _resolve(fut, decision):
    if not fut.done():
        fut.set_result(decision)

def handle_callback(data: str) -> str:
    """A button was pressed (called from the Telegram listener thread; chat and person already verified)."""
    kind, _, rid = data.partition(":")
    a = dict(approval)                                  # snapshot: the request may finish at any moment
    if kind not in ("a", "d") or not a or not hmac.compare_digest(a["id"], rid):
        return "This request has expired."
    if a["future"].done():
        return "Already answered."
    a["loop"].call_soon_threadsafe(_resolve, a["future"], "approved" if kind == "a" else "denied")
    return "Approved" if kind == "a" else "Denied"

async def request_approval() -> str:
    """Ask the owner to approve. Returns 'approved', 'denied', 'timeout' or 'unavailable'."""
    loop = asyncio.get_running_loop()
    rid = secrets.token_hex(4)
    fut = loop.create_future()
    approval.clear()
    approval.update(id=rid, future=fut, loop=loop)
    text = (f"\U0001F511 {LOCK_NAME}: unlock requested at {hms()}.\n"
            f"Gesture and HMAC verified. Approve within {int(APPROVAL_TIMEOUT_S)} s?")
    msg_id = await loop.run_in_executor(None, gk_notify.send_approval_request, text, rid)
    if msg_id is None:
        approval.clear()
        return "unavailable"
    try:
        decision = await asyncio.wait_for(fut, APPROVAL_TIMEOUT_S)
    except asyncio.TimeoutError:
        decision = "timeout"
    finally:
        approval.clear()
    outcome = {"approved": f"\u2705 {LOCK_NAME}: APPROVED at {hms()}",
               "denied": f"\u26D4 {LOCK_NAME}: DENIED by you at {hms()}",
               "timeout": f"\u231B {LOCK_NAME}: approval timed out at {hms()}. Door stays locked."}[decision]
    await loop.run_in_executor(None, gk_notify.edit_message, msg_id, outcome)   # also removes the buttons
    return decision

def check_startup() -> list:
    """Configuration problems that should stop the program (fail closed, never silently weaker)."""
    errors = []
    if REQUIRE_APPROVAL:
        if not gk_notify.configured():
            errors.append("GK_REQUIRE_APPROVAL=1 needs TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        if os.environ.get("GK_TELEGRAM_COMMANDS", "1") == "0":
            errors.append("GK_REQUIRE_APPROVAL=1 needs the Telegram listener (do not set GK_TELEGRAM_COMMANDS=0)")
        if os.environ.get("TELEGRAM_CHAT_ID", "").startswith("-"):
            errors.append("approvals need your PRIVATE chat id (a positive number), not a group chat id")
    if ACTUATOR not in ("sim", "ble"):
        errors.append(f"GK_ACTUATOR must be 'sim' or 'ble', but it is {ACTUATOR!r}")
    if DAILY_SUMMARY_AT:
        try:
            seconds_until(DAILY_SUMMARY_AT)
        except Exception:
            errors.append(f"GK_DAILY_SUMMARY_AT={DAILY_SUMMARY_AT!r} is not a valid HH:MM time")
    return errors

# ---- messages to the watch about what happens after the gesture ----
async def send_waiting(seconds: int):
    """Tell the watch to show 'Approve on phone' with a countdown."""
    await safe_send(watch, b"W" + bytes([max(1, min(255, seconds))]))

async def send_decision(code: bytes):
    """N = denied by owner, T = approval timed out, X = phone unreachable, F = lock error."""
    await safe_send(watch, b"D" + code)

async def start_lockout(reason_text: str):
    global locked_until, fails, timeouts
    locked_until = time.time() + LOCKOUT_S
    fails = 0
    timeouts = 0
    log("lockout", f"{LOCKOUT_S} s")
    fire_alert(f"\U0001F6A8 {LOCK_NAME}: LOCKED OUT for {LOCKOUT_S} s at {hms()}\n{reason_text}")
    fail_reasons.clear()
    await safe_send(watch, b"L")

async def register_timeout(reason: str):
    """A challenge nobody answered. Several in a row cause a lockout too."""
    global timeouts
    log("timeout", reason)
    fire_alert(f"\u23F1 {LOCK_NAME}: unlock requested at {hms()} but the watch did not respond",
               key="timeout", cooldown=30)
    if MAX_TIMEOUTS and not TEST_NO_LOCKOUT:
        timeouts += 1
        if timeouts >= MAX_TIMEOUTS:
            await start_lockout(f"{MAX_TIMEOUTS} challenges in a row went unanswered")

async def watch_handshake():
    """Mutual authentication with the watch: it picks a nonce, we pick one, we prove we know the key.
    Returns (wn, pn), or None if the watch did not answer."""
    watch.flush()
    await watch.send(b"Q")
    z = await watch.expect(b"Z", HANDSHAKE_TIMEOUT_S)
    if z is None or len(z) != 1 + gk_proto.NONCE_LEN:
        return None
    wn, pn = z[1:], gk_proto.new_nonce()
    await watch.send(b"C" + pn)
    await asyncio.sleep(BLE_GAP_S)                   # one BLE write at a time: the device has a single receive buffer
    await watch.send(b"M" + gk_proto.tag_P(KEY, wn, pn))
    return wn, pn

async def actuate() -> bool:
    """Open the lock. In 'ble' mode the lock stack only moves after we prove we know the key for a nonce
    IT just chose, and it confirms with its own tag. Returns True once the door is really open."""
    if ACTUATOR != "ble":
        set_lock(True)
        return True
    try:
        lock.flush()
        await lock.send(b"Q")
        z = await lock.expect(b"Z", HANDSHAKE_TIMEOUT_S)
        if z is None or len(z) != 1 + gk_proto.NONCE_LEN:
            return False
        ln = z[1:]
        await lock.send(b"O" + gk_proto.tag_O(KEY, ln))
        y = await lock.expect(b"YX", LOCK_TIMEOUT_S)
    except Exception as e:
        print(f"[lock] error ({e.__class__.__name__})")
        return False
    return (y is not None and y[:1] == b"Y" and len(y) == 1 + gk_proto.TAG_LEN
            and gk_proto.equal(y[1:], gk_proto.tag_Y(KEY, ln)))

async def attempt(client):
    """One unlock attempt. `client` is the watch's BLE client (the lock's is lock.client)."""
    watch.client = client
    try:
        await _attempt()
    finally:
        save_state()

async def _attempt():
    global fails, timeouts
    if lockdown:
        print("[lockdown] unlock requests are blocked (send /resume in Telegram)")
        log("blocked", "lockdown active")
        fire_alert(f"\U0001F512 {LOCK_NAME}: unlock request blocked (lockdown is on)", key="blocked", cooldown=60)
        return
    now = time.time()
    if now < locked_until:
        print(f"[locked out] try again in {int(locked_until - now)} s")
        return

    if not hours_allowed():
        start, end = ALLOWED_HOURS
        log("outside_hours", f"unlock refused, allowed {start:02d}:00-{end:02d}:00")
        fire_alert(f"\U0001F319 {LOCK_NAME}: unlock attempt at {hms()} refused (allowed {start:02d}:00-{end:02d}:00)",
                   key="hours", cooldown=60)
        return

    if ACTUATOR == "ble" and not lock.connected:
        log("lock_offline", "lock stack not connected; unlock refused")
        fire_alert(f"\u26A0\uFE0F {LOCK_NAME}: unlock refused because the lock is not connected", key="lock_offline", cooldown=60)
        return

    hs = await watch_handshake()
    if hs is None:
        await register_timeout("watch did not answer the handshake")
        return
    wn, pn = hs
    print("[challenge sent] waiting for gesture on the watch...")

    resp = await watch.expect(b"RN", RESPONSE_TIMEOUT_S)
    if resp is None:
        await register_timeout("no response from watch")
        return
    timeouts = 0                                       # the watch answered, so the unanswered streak is over

    if resp[:1] == b"N":
        ok = False; why = "wrong gesture"
    elif resp[:1] == b"R" and len(resp) == 1 + gk_proto.TAG_LEN:
        ok = gk_proto.equal(resp[1:], gk_proto.tag_A(KEY, wn, pn))     # constant-time compare
        why = "" if ok else "bad HMAC"
    else:
        ok = False; why = "malformed response"

    if ok and REQUIRE_APPROVAL:
        await send_waiting(int(APPROVAL_TIMEOUT_S))     # the watch shows "Approve on phone" + countdown
        decision = await request_approval()
        if decision == "unavailable" and APPROVAL_FAIL_OPEN:
            log("approval_unavailable", "Telegram unreachable; gesture-only unlock (fail-open is ON)")
        elif decision != "approved":
            # A correct gesture that the owner did not approve is not a failed guess,
            # so it does not count towards the lockout.
            log({"denied": "denied", "timeout": "approval_timeout"}.get(decision, "approval_unavailable"),
                "gesture OK but " + {"denied": "owner denied", "timeout": "owner did not answer in time"}.get(
                    decision, "approval could not be requested (Telegram unreachable); door stays locked"))
            if decision == "unavailable":
                fire_alert(f"\u26A0\uFE0F {LOCK_NAME}: unlock needed approval but Telegram was unreachable. Door stays locked.",
                           key="approval_unavailable", cooldown=60)
            await send_decision({"denied": b"N", "timeout": b"T"}.get(decision, b"X"))
            return

    if ok:
        if not await actuate():
            log("lock_error", "gesture and HMAC were fine but the lock did not open")
            fire_alert(f"\U0001F6A8 {LOCK_NAME}: gesture OK but the LOCK did not open. Check the lock stack.",
                       key="lock_error", cooldown=30)
            await send_decision(b"F")
            return
        fails = 0
        fail_reasons.clear()
        log("unlock", "gesture + HMAC verified" + (" + owner approval" if REQUIRE_APPROVAL else ""))
        if not REQUIRE_APPROVAL:                        # with approval, the edited approval message already says so
            fire_alert(f"\u2705 {LOCK_NAME}: UNLOCKED at {hms()}\nGesture and HMAC verified.")
        await send_status(watch.client, b"U")
        await asyncio.sleep(UNLOCK_HOLD_S)               # in 'ble' mode the lock closes itself after the same time
        if ACTUATOR != "ble":
            set_lock(False)
        await send_status(watch.client, b"K")
        await asyncio.sleep(BLE_GAP_S)                   # one BLE write at a time: the watch has a single receive buffer
        await send_time(watch.client)                    # resync the clock after each unlock
    else:
        fails += 1
        fail_reasons.append(why)
        log("fail", f"{why} ({fails}/{MAX_FAILS})")
        if fails >= MAX_FAILS and TEST_NO_LOCKOUT:
            fire_alert(f"\u26A0\uFE0F {LOCK_NAME}: failed unlock attempt {fails}/{MAX_FAILS} at {hms()}\n"
                       f"Reason: {why}\n(test mode: lockout is disabled)")
            fails = 0                            # no lockout while testing; keep the counter from running past the limit
            fail_reasons.clear()
        elif fails >= MAX_FAILS:
            await start_lockout(f"{MAX_FAILS} failed attempts: " + ", ".join(fail_reasons))
        else:
            fire_alert(f"\u26A0\uFE0F {LOCK_NAME}: failed unlock attempt {fails}/{MAX_FAILS} at {hms()}\n"
                       f"Reason: {why}")

def _named(d, ad, prefix):
    # Check BOTH names: the OS may cache an old device name while the fresh advert says the new one
    return any((n or "").startswith(prefix) for n in (d.name, ad.local_name))

def is_watch(d, ad):
    return _named(d, ad, NAME_PREFIX)

def is_lock(d, ad):
    return _named(d, ad, LOCK_PREFIX)

async def list_devices():
    """Debug helper: python gk_lock.py --scan  -> prints every BLE device seen for 10 s."""
    from bleak import BleakScanner
    print("[scan] listing nearby BLE devices for 10 s...")
    found = await BleakScanner.discover(timeout=10, return_adv=True)
    for addr, (d, ad) in sorted(found.items(), key=lambda kv: -(kv[1][1].rssi or -999)):
        print(f"  {addr}  rssi={ad.rssi}  name={d.name!r}  local_name={ad.local_name!r}")
    print(f"[scan] {len(found)} devices")

async def find_devices(need_lock: bool, scan_s: float = 8):
    """Scan once and pick the watch (and the lock). Addresses from GK_ADDR / GK_LOCK_ADDR win over names."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=scan_s, return_adv=True)
    wdev = ldev = None
    for addr, (d, ad) in found.items():
        if WATCH_ADDR and addr.upper() == WATCH_ADDR.upper():
            wdev = d
        elif not WATCH_ADDR and is_watch(d, ad):
            wdev = wdev or d
        if need_lock:
            if LOCK_ADDR and addr.upper() == LOCK_ADDR.upper():
                ldev = d
            elif not LOCK_ADDR and is_lock(d, ad):
                ldev = ldev or d
    return wdev, ldev

async def session():
    from bleak import BleakClient
    global watch_connected, watch_addr
    need_lock = ACTUATOR == "ble"
    print("[scan] looking for the watch" + (" and the lock" if need_lock else "") + "...")
    wdev, ldev = await find_devices(need_lock)
    if wdev is None or (need_lock and ldev is None):
        print("[scan] not found:" + ("" if wdev else " watch") + ("" if (ldev or not need_lock) else " lock"))
        return
    try:
        async with contextlib.AsyncExitStack() as stack:
            wc = await stack.enter_async_context(BleakClient(wdev))
            await wc.start_notify(NUS_NOTIFY, watch.on_notify)
            watch.client = wc
            if need_lock:
                lc = await stack.enter_async_context(BleakClient(ldev))
                await lc.start_notify(NUS_NOTIFY, lock.on_notify)
                lock.client = lc
            watch_connected, watch_addr = True, wdev.address
            log("connected", wdev.address + (f" + lock {ldev.address}" if need_lock else ""))
            await send_status(wc, b"K")          # door is locked when we connect
            await asyncio.sleep(BLE_GAP_S)
            await send_time(wc)                  # set the watch clock
            loop = asyncio.get_running_loop()
            while watch.connected and (not need_lock or lock.connected):
                await loop.run_in_executor(None, input, "Press Enter to request unlock > ")
                await attempt(wc)
    finally:
        watch_connected = False
        watch.client = lock.client = None
    log("disconnected")
    fire_alert(f"\U0001F4E1 {LOCK_NAME}: watch" + (" or lock" if need_lock else "") + f" disconnected at {hms()}",
               key="disc", cooldown=60)

load_state()

async def main():
    problems = check_startup()
    if problems:
        for e in problems:
            print("[config error]", e)
        raise SystemExit(2)
    if gk_notify.configured() and os.environ.get("GK_TELEGRAM_COMMANDS", "1") != "0":
        gk_notify.CommandListener(handle_command, callback_handler=handle_callback).start()
        print("[telegram] commands enabled (/status /log /summary /lockdown /resume /help); "
              "only your own chat is obeyed. Set GK_TELEGRAM_COMMANDS=0 to turn off.")
    print(f"[lock] actuator = {ACTUATOR}" + (" (second TinyScreen+ with the servo shield)" if ACTUATOR == "ble"
                                          else " (simulated: prints UNLOCKED, no real lock)"))
    if TEST_NO_LOCKOUT:
        print("[WARNING] GK_TEST_NO_LOCKOUT is ON: failed attempts never lock you out. Turn it off for the real demo.")
    if REQUIRE_APPROVAL:
        print(f"[approval] second factor ON: tap Approve in Telegram within {int(APPROVAL_TIMEOUT_S)} s "
              f"({'gesture-only if Telegram is down' if APPROVAL_FAIL_OPEN else 'door stays locked if Telegram is down'})")
    if DAILY_SUMMARY_AT:
        asyncio.create_task(daily_summary_loop())
        print(f"[summary] daily summary at {DAILY_SUMMARY_AT}")
    while True:
        try:
            await session()
        except Exception as e:
            print("[error]", repr(e))
        await asyncio.sleep(3)      # then rescan / reconnect

if __name__ == "__main__":
    if "--test-telegram" in sys.argv:
        ok = gk_notify.send_telegram("GestureKey: test message")
        print("[telegram]", "sent" if ok else "NOT sent (check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID / network)")
        sys.exit(0 if ok else 1)
    try:
        asyncio.run(list_devices() if "--scan" in sys.argv else main())
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        gk_notify.flush_alerts(3)       # give queued alerts a moment to go out
