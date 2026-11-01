#!/usr/bin/env python3
"""
gk_lock.py - Raspberry Pi side of GestureKey (BLE central + lock controller)

Protocol (matches GestureKey.ino):
  Pi -> watch : b'C' + 16 random bytes   (challenge)
  watch -> Pi : b'R' + 16 bytes          (= HMAC-SHA256(key, b'A' + nonce)[:16])  approved
                b'N'                      denied (wrong gesture)
  Pi -> watch : b'L'                      locked out notice
  Pi -> watch : b'T' + hour, minute, second  clock sync (watch has no battery-backed clock)
  Pi -> watch : b'S' + b'U' / b'K'        door status: unlocked / locked (shown on the watch's idle screen)

Attribution: BLE UART UUIDs are the Nordic UART Service used by the TinyCircuits
SmartWatch example. BLE client uses the 'bleak' library; servo uses 'gpiozero'.
Everything else is our own work.

Run:  pip install bleak gpiozero pigpio
      python3 gk_lock.py --scan     (debug: list nearby BLE devices)
      python3 gk_lock.py --test-telegram   (check Telegram alert setup)
      python3 gk_lock.py            (press Enter to request an unlock)
"""
import asyncio, datetime, hmac, hashlib, json, os, secrets, sys, time, warnings
from collections import Counter
import gk_notify                    # Telegram alerts (see gk_notify.py)
warnings.filterwarnings("ignore")   # silence gpiozero pin-factory warnings when not on a Pi

# Optional pi/.env (git-ignored) holds the Telegram token etc. Real environment variables win.
_n = gk_notify.load_env_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
if _n:
    print(f"[config] loaded {_n} setting(s) from .env")

NAME_PREFIX = "GKey"                                   # advertised name set in UART.ino
NUS_WRITE  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"    # watch receives challenges here
NUS_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"    # watch sends responses here
KEY_FILE = os.environ.get("GK_KEY_FILE", os.path.join(os.path.dirname(__file__), "gk_key.txt"))
KEY = bytes.fromhex(open(KEY_FILE).read().strip())

RESPONSE_TIMEOUT_S = 15      # must be LONGER than the watch's CHALLENGE_TIMEOUT_MS (12 s) or the Pi gives up first
MAX_FAILS = 3
LOCKOUT_S = 30
UNLOCK_HOLD_S = 5
SERVO_PIN = 18
LOG_FILE = os.environ.get("GK_LOG_FILE", os.path.join(os.path.dirname(__file__), "access_log.jsonl"))
WATCH_ADDR = os.environ.get("GK_ADDR")      # optional: skip name matching, connect by address
LOCK_NAME = os.environ.get("GK_LOCK_NAME", "Front door")   # shown in every Telegram message
LOCKDOWN_FILE = LOG_FILE + ".lockdown"      # exists = lockdown on (survives a restart)

def _env_float(name: str, default: float) -> float:
    """Read a number from the environment; a typo gives a clear message instead of a traceback."""
    raw = os.environ.get(name, str(default))
    try:
        return float(raw)
    except ValueError:
        print(f"[config error] {name} must be a number, but it is {raw!r}")
        raise SystemExit(2)

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
fail_reasons = []        # why each recent attempt failed (shown in the lockout alert)
locked_until = 0.0
pending = None          # Future for the challenge currently in flight (one at a time)
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
            "Lockdown: " + ("ON" if lockdown else "off"),
            *([f"Allowed hours: {ALLOWED_HOURS[0]:02d}:00-{ALLOWED_HOURS[1]:02d}:00"] if ALLOWED_HOURS else []),
            "Lockout: " + (f"{remaining} s left" if remaining > 0 else "none"),
            f"Failed attempts: {fails}/{MAX_FAILS}",
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

def on_notify(_sender, data: bytearray):
    if pending is not None and not pending.done():
        pending.set_result(bytes(data))

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
    if DAILY_SUMMARY_AT:
        try:
            seconds_until(DAILY_SUMMARY_AT)
        except Exception:
            errors.append(f"GK_DAILY_SUMMARY_AT={DAILY_SUMMARY_AT!r} is not a valid HH:MM time")
    return errors

async def attempt(client):
    global fails, locked_until, pending
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

    nonce = os.urandom(16)                    # fresh every time -> replayed responses are useless
    pending = asyncio.get_running_loop().create_future()
    await client.write_gatt_char(NUS_WRITE, b"C" + nonce, response=False)
    print("[challenge sent] waiting for gesture on the watch...")

    try:
        resp = await asyncio.wait_for(pending, RESPONSE_TIMEOUT_S)
    except asyncio.TimeoutError:
        log("timeout", "no response from watch")
        fire_alert(f"\u23F1 {LOCK_NAME}: unlock requested at {hms()} but the watch did not respond",
                   key="timeout", cooldown=30)
        return
    finally:
        pending = None

    if resp[:1] == b"N":
        ok = False; why = "wrong gesture"
    elif resp[:1] == b"R" and len(resp) == 17:
        expected = hmac.new(KEY, b"A" + nonce, hashlib.sha256).digest()[:16]
        ok = hmac.compare_digest(resp[1:], expected)      # constant-time compare
        why = "" if ok else "bad HMAC"
    else:
        ok = False; why = "malformed response"

    if ok and REQUIRE_APPROVAL:
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
            return
    if ok:
        fails = 0
        fail_reasons.clear()
        log("unlock", "gesture + HMAC verified" + (" + owner approval" if REQUIRE_APPROVAL else ""))
        if not REQUIRE_APPROVAL:                        # with approval, the edited approval message already says so
            fire_alert(f"\u2705 {LOCK_NAME}: UNLOCKED at {hms()}\nGesture and HMAC verified.")
        set_lock(True)
        await send_status(client, b"U")
        await asyncio.sleep(UNLOCK_HOLD_S)
        set_lock(False)
        await send_status(client, b"K")
        await asyncio.sleep(BLE_GAP_S)                 # one BLE write at a time: the watch has a single receive buffer
        await send_time(client)                  # resync the clock after each unlock
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
            locked_until = time.time() + LOCKOUT_S
            fails = 0
            log("lockout", f"{LOCKOUT_S} s")
            fire_alert(f"\U0001F6A8 {LOCK_NAME}: LOCKED OUT for {LOCKOUT_S} s at {hms()}\n"
                       f"{MAX_FAILS} failed attempts: " + ", ".join(fail_reasons))
            fail_reasons.clear()
            await client.write_gatt_char(NUS_WRITE, b"L", response=False)
        else:
            fire_alert(f"\u26A0\uFE0F {LOCK_NAME}: failed unlock attempt {fails}/{MAX_FAILS} at {hms()}\n"
                       f"Reason: {why}")

def is_watch(d, ad):
    # Check BOTH names: the OS may cache an old device name while the fresh advert says GKey
    return any((n or "").startswith(NAME_PREFIX) for n in (d.name, ad.local_name))

async def list_devices():
    """Debug helper: python gk_lock.py --scan  -> prints every BLE device seen for 10 s."""
    from bleak import BleakScanner
    print("[scan] listing nearby BLE devices for 10 s...")
    found = await BleakScanner.discover(timeout=10, return_adv=True)
    for addr, (d, ad) in sorted(found.items(), key=lambda kv: -(kv[1][1].rssi or -999)):
        print(f"  {addr}  rssi={ad.rssi}  name={d.name!r}  local_name={ad.local_name!r}")
    print(f"[scan] {len(found)} devices")

async def session():
    from bleak import BleakScanner, BleakClient
    print("[scan] looking for the watch...")
    if WATCH_ADDR:
        dev = await BleakScanner.find_device_by_address(WATCH_ADDR, timeout=20)
    else:
        dev = await BleakScanner.find_device_by_filter(is_watch, timeout=20)
    if dev is None:
        print("[scan] not found"); return
    global watch_connected, watch_addr
    try:
        async with BleakClient(dev) as client:
            await client.start_notify(NUS_NOTIFY, on_notify)
            watch_connected, watch_addr = True, dev.address
            log("connected", dev.address)
            await send_status(client, b"K")      # door is locked when we connect
            await asyncio.sleep(BLE_GAP_S)
            await send_time(client)              # set the watch clock
            loop = asyncio.get_running_loop()
            while client.is_connected:
                await loop.run_in_executor(None, input, "Press Enter to request unlock > ")
                await attempt(client)
    finally:
        watch_connected = False
    log("disconnected")
    fire_alert(f"\U0001F4E1 {LOCK_NAME}: watch disconnected at {hms()}", key="disc", cooldown=60)

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
