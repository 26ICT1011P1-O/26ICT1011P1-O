#!/usr/bin/env python3
"""
gk_lock.py - Raspberry Pi side of GestureKey (BLE central + lock controller)

Protocol (matches GestureKey.ino):
  Pi -> watch : b'C' + 16 random bytes   (challenge)
  watch -> Pi : b'R' + 16 bytes          (= HMAC-SHA256(key, b'A' + nonce)[:16])  approved
                b'N'                      denied (wrong gesture)
  Pi -> watch : b'L'                      locked out notice
  Pi -> watch : b'S' + b'U' / b'K'        door status: unlocked / locked (shown on the watch's idle screen)

Attribution: BLE UART UUIDs are the Nordic UART Service used by the TinyCircuits
SmartWatch example. BLE client uses the 'bleak' library; servo uses 'gpiozero'.
Everything else is our own work.

Run:  pip install bleak gpiozero pigpio
      python3 gk_lock.py --scan     (debug: list nearby BLE devices)
      python3 gk_lock.py --test-telegram   (check Telegram alert setup)
      python3 gk_lock.py            (press Enter to request an unlock)
"""
import asyncio, hmac, hashlib, json, os, sys, time, warnings
import gk_notify                    # Telegram alerts (see gk_notify.py)
warnings.filterwarnings("ignore")   # silence gpiozero pin-factory warnings when not on a Pi

NAME_PREFIX = "GKey"                                   # advertised name set in UART.ino
NUS_WRITE  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"    # watch receives challenges here
NUS_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"    # watch sends responses here
KEY_FILE = os.environ.get("GK_KEY_FILE", os.path.join(os.path.dirname(__file__), "gk_key.txt"))
KEY = bytes.fromhex(open(KEY_FILE).read().strip())

RESPONSE_TIMEOUT_S = 15      # must be LONGER than the watch's CHALLENGE_TIMEOUT_MS (12 s) or the Pi gives up first
MAX_FAILS = 3
LOCKOUT_S = 30
SEND_DOOR_STATUS = True    # tell the watch whether the door is locked or unlocked
TEST_NO_LOCKOUT = True     # testing: wrong gestures never lock you out. Set False for the real demo
UNLOCK_HOLD_S = 5
SERVO_PIN = 18
LOG_FILE = os.environ.get("GK_LOG_FILE", os.path.join(os.path.dirname(__file__), "access_log.jsonl"))
WATCH_ADDR = os.environ.get("GK_ADDR")      # optional: skip name matching, connect by address

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

# ---- Telegram alerts: fire-and-forget so a slow network never delays the lock ----
_bg_tasks = set()

async def _send_alert(text: str):
    await asyncio.get_running_loop().run_in_executor(None, gk_notify.send_telegram, text)

def fire_alert(text: str):
    t = asyncio.get_running_loop().create_task(_send_alert(text))
    _bg_tasks.add(t)                       # keep a reference so the task is not garbage-collected
    t.add_done_callback(_bg_tasks.discard)

fails = 0
locked_until = 0.0
pending = None          # Future for the challenge currently in flight (one at a time)

async def send_status(client, code: bytes):
    """Tell the watch the door state: b'U' = unlocked, b'K' = locked. Never raises."""
    if not SEND_DOOR_STATUS:
        return
    try:
        await client.write_gatt_char(NUS_WRITE, b"S" + code, response=False)
    except Exception as e:
        print(f"[status] not sent ({e.__class__.__name__})")

def on_notify(_sender, data: bytearray):
    if pending is not None and not pending.done():
        pending.set_result(bytes(data))

async def attempt(client):
    global fails, locked_until, pending
    now = time.time()
    if now < locked_until:
        print(f"[locked out] try again in {int(locked_until - now)} s")
        return

    nonce = os.urandom(16)                    # fresh every time -> replayed responses are useless
    pending = asyncio.get_running_loop().create_future()
    await client.write_gatt_char(NUS_WRITE, b"C" + nonce, response=False)
    print("[challenge sent] waiting for gesture on the watch...")

    try:
        resp = await asyncio.wait_for(pending, RESPONSE_TIMEOUT_S)
    except asyncio.TimeoutError:
        log("timeout", "no response from watch")
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

    if ok:
        fails = 0
        log("unlock", "gesture + HMAC verified")
        fire_alert("GestureKey: door UNLOCKED at " + time.strftime("%H:%M:%S"))
        set_lock(True)
        await send_status(client, b"U")
        await asyncio.sleep(UNLOCK_HOLD_S)
        set_lock(False)
        await send_status(client, b"K")
    else:
        fails += 1
        log("fail", f"{why} ({fails}/{MAX_FAILS})")
        if fails >= MAX_FAILS and TEST_NO_LOCKOUT:
            fails = 0                         # testing: no lockout, keep the counter from running past the limit
        elif fails >= MAX_FAILS:
            locked_until = time.time() + LOCKOUT_S
            fails = 0
            log("lockout", f"{LOCKOUT_S} s")
            fire_alert(f"GestureKey ALERT: {MAX_FAILS} failed unlock attempts. "
                       f"Locked out for {LOCKOUT_S} s (" + time.strftime("%H:%M:%S") + ")")
            await client.write_gatt_char(NUS_WRITE, b"L", response=False)

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
    async with BleakClient(dev) as client:
        await client.start_notify(NUS_NOTIFY, on_notify)
        log("connected", dev.address)
        await send_status(client, b"K")          # door is locked when we connect
        loop = asyncio.get_running_loop()
        while client.is_connected:
            await loop.run_in_executor(None, input, "Press Enter to request unlock > ")
            await attempt(client)
    log("disconnected")

async def main():
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

        