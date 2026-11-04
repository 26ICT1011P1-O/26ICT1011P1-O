# GestureKey

A wrist-worn challenge-response door lock for the ICT1011 Team Exploration Project.

Two TinyScreen+ kits and a laptop:
- the **watch** judges a secret wrist gesture (direction *and* rhythm);
- the **lock** (second kit with the servo shield) moves a latch;
- the **laptop** decides everything (HMAC check, Telegram approval, lockdown, hours, lockout) and talks to both over
  Bluetooth Low Energy. Neither kit acts on anything the laptop has not proved it sent.

> Prototype for coursework, not production security. See "Security design" and "Limitations".

## How it works
```
 WATCH (gesture)                 LAPTOP (decides)                 LOCK (servo)
   |  <--- 'Q' ------------------   |                                 |
   |  ---- 'Z' + wn ------------>   |   watch picks nonce wn          |
   |  <--- 'C' + pn, 'M' + proof    |   laptop picks pn and proves it |
   |   (ignored unless the proof    |   knows the shared key          |
   |    is valid)                   |                                 |
   |  wearer flicks the gesture     |                                 |
   |  ---- 'R' + tag(wn,pn) ---->   |   checks gesture + HMAC         |
   |                                |   Telegram approval (optional)  |
   |  <--- 'W' approve on phone     |                                 |
   |                                |  ---- 'Q' ------------------->  |
   |                                |  <---- 'Z' + ln --------------  |   lock picks nonce ln
   |                                |  ---- 'O' + tag(ln) --------->  |   only the laptop can sign this
   |                                |  <---- 'Y' + tag(ln) ---------  |   opens, then closes ITSELF
   |  <--- 'S' U / K, 'T' clock     |                                 |   after a few seconds
```
All tags are `HMAC-SHA256(key, label || nonces)` cut to 16 bytes (`firmware gk_auth.h` / `pi/gk_proto.py`).
Full message list: the header of `pi/gk_proto.py`.

## Repository layout
```
GestureKey/            WATCH sketch (open GestureKey.ino)
  GestureKey.ino       state machine, flick detection, rhythm, BLE protocol, screens
  UART.ino             BLE UART service (adapted from TinyCircuits example); advertises as "GKey"
  BMA250.h/.cpp        accelerometer driver (TinyCircuits)
  gk_crypto.h          SHA-256 + HMAC (FIPS 180-4 / RFC 2104)
  gk_auth.h            tags and nonces       (identical copy in LockKey/)
  gk_gesture.h         direction + rhythm matching
  secrets.h            shared key  -- NOT in git
LockKey/               LOCK sketch (open LockKey.ino)
  LockKey.ino          servo, authenticated open order, closes itself
  UART.ino             same service, advertises as "GLock", different Bluetooth address
  gk_crypto.h, gk_auth.h, secrets.h    identical copies of the watch's
pi/                    LAPTOP program (named "pi" because it was designed for a Raspberry Pi; runs on any laptop)
  gk_lock.py           connects to both devices, decides, logs, Telegram, lockout
  gk_proto.py          the wire protocol (Python twin of gk_auth.h)
  gk_notify.py         Telegram alerts, commands, approval buttons (standard library only)
  dashboard.py         Flask page showing the access log
  virtual_door.py      on-screen door (red LOCKED / green UNLOCKED / orange flash when refused); reads the files
                       gk_lock.py writes. Needs only tkinter. Run it in a second terminal.
  .env.example         template for pi/.env (token, chat id, options)
  gk_key.txt           shared key (hex) -- NOT in git
  tests/               about 200 tests, see "Tests"
```

## Hardware
| Stack | Parts |
|---|---|
| **Watch** (kit 1) | TinyScreen+, Accelerometer TinyShield, ST BLE TinyShield, 150 mAh battery, micro-USB |
| **Lock** (kit 2) | TinyScreen+, ST BLE TinyShield, **Servo TinyShield (ASD2303-R)**, **servo ES9251** (plugs into the shield's 3-pin connector), a **separate battery** on the shield's 2-pin power connector (not the stack's own), micro-USB, 3D-printed latch bracket |
| **Laptop** | Bluetooth, Python 3.10 or newer |

The servo shield does not power the servo from the stack: the servo needs its own battery on the shield's
2-pin connector. The ES9251 is rated 4.5-6 V and a single LiPo is a little lower, so expect reduced torque
and test it. Keep the latch light (the servo is about 0.3 kgf*cm).

## Setup

### 1. Libraries (Arduino IDE)
TinyScreen+ board package, TinyScreen library and the ST BLE library (from the lab's `TinyCircuit_Examples.zip`).
The **lock** sketch also needs TinyCircuits' **ATtiny841 library** (provides `ServoDriver.h`).

### 2. The shared key (three copies that must match)
```
python3 -c "import os;print(os.urandom(16).hex())"
```
Put the hex string in `pi/gk_key.txt`, and the same 16 bytes as a C array in **both** `GestureKey/secrets.h` and
`LockKey/secrets.h`. They are git-ignored; share them with teammates privately. A test checks all three match.

### 3. Bluetooth names and addresses
Every kit in the lab advertises the same address unless you change it. In each `UART.ino` change the last byte of
`bdaddr` to something unique to your team. The watch is `GKey`, the lock is `GLock`, and their addresses must differ
from each other (a test checks this).

### 4. Lock calibration (`LockKey.ino`)
`SERVO_CLOSED_US` / `SERVO_OPEN_US` (pulse in microseconds, usually 1000-2000): set them on your latch.
`HOLD_MS` is how long the latch stays open and must equal `UNLOCK_HOLD_S` in `gk_lock.py` (a test checks this).
The sketch deliberately does **not** call `servo.useResetPin()`: that uses Pin 9, which the BLE shield needs for its
own reset.

### 5. Laptop
```
pip install bleak flask
cd pi
copy .env.example .env          # then fill it in (Telegram, GK_ACTUATOR=ble, ...)
python gk_lock.py --scan        # should list GKey and GLock
python gk_lock.py               # press Enter to request an unlock
```

## First-time test order (each step proves one thing)
1. Upload TinyCircuits' own servo example to the lock stack: does the servo sweep? (hardware + power OK)
2. Upload `LockKey.ino`: screen shows `GLock / LOCKED`. Run `python gk_lock.py --scan`: `GLock` appears.
3. Upload `GestureKey.ino` to the watch stack. `--scan` now also shows `GKey` (two different addresses).
4. Run the laptop with `GK_ACTUATOR=sim` (default): the watch and the gesture only, the lock is just printed.
5. Switch to `GK_ACTUATOR=ble`: the full chain, and the latch moves.
6. Then turn on Telegram, approval, lockdown, one at a time.
Uploading to the TinyScreen+ is sometimes flaky: hold the button nearest the USB port while switching on to force
bootloader mode, then pick the new COM port.

## Secrets
`secrets.h` (both folders), `pi/gk_key.txt` and `pi/.env` are git-ignored. Never paste the Telegram token or the
key into chats, screenshots or the repo.

## Security design
What each device proves, and what an attacker can and cannot do:

| Attacker has | Can they get the door open? |
|---|---|
| A recording of an earlier unlock (all Bluetooth traffic) | **No.** Every message is tied to a nonce that was used once. The lock's nonce is chosen by the lock itself, so a recorded order is useless. |
| A Bluetooth device in range, no key | **No.** The watch ignores requests without a valid proof; the lock refuses orders without a valid tag and says nothing useful. They *can* connect first and block the laptop (see Limitations). |
| The watch, without the owner's gesture | **No.** The laptop never orders the lock to open without a correct gesture (and, if on, your Telegram approval). |
| The owner's gesture (directions only), not the rhythm | **No**, the rhythm must match too. |
| Both gesture and rhythm, from watching the owner | Gets past the watch. With approval on, they still need your tap on your phone. |
| The shared key (extracted from a lost device) | **Yes.** One key is shared by all three programs. |

Other properties: the lock closes itself even if Bluetooth drops; a failed or silent lock is reported and the watch
shows `LOCK ERROR`; 3 failed guesses, or 5 unanswered challenges in a row, trigger a lockout that survives restarting
the laptop script; lockdown and lockout state are stored in files next to the log.

## Gesture: direction and rhythm
The secret is three flicks (4 directions each, 64 combinations) **and** the pauses between them. A pause matches if it
is within the larger of 350 ms or 40 % of the stored pause (`RHYTHM_MIN_TOL_MS`, `RHYTHM_TOL_PCT`). That adds only a
few bits, because people cannot repeat a pause more precisely than that; it makes copying the directions by
watching clearly harder, not impossible. A wrong gesture always shows the same "Wrong gesture" screen, so an
onlooker cannot tell whether the directions or the rhythm were off. Set `USE_RHYTHM false` to check directions only.

**Make your rehearsed gesture the default** (the watch has no memory that survives a restart): re-record it with the
upper-left button within 5 minutes of power-up, note what you did, and put the same directions in `gestureTemplate`
and the same pauses (in ms) in `gestureGapMs` in `GestureKey.ino`.

## Telegram bot
The Pi sends Telegram alerts, accepts a few commands, and can require your approval as a second factor.

**Settings go in `pi/.env`** (copy `pi/.env.example`; it is git-ignored). Real environment variables
override it. Never commit the token.

**Alerts** (each message names the lock, e.g. "Front door"; set `GK_LOCK_NAME` to change it)
- Unlock: time and confirmation that gesture + HMAC were verified
- Each failed attempt: counter (1/3, 2/3) and the reason (wrong gesture, bad HMAC, ...)
- Lockout: duration and the list of reasons for all 3 failures
- Timeout (watch did not respond) and watch disconnect, rate-limited so they cannot spam you
- Optional daily summary: set `GK_DAILY_SUMMARY_AT=21:00`

**Reliable delivery:** alerts go through a background queue. Network errors and server errors are retried
with growing delays (2, 4, 8, 16 s), Telegram's "slow down" (429) is honoured, messages go out in order
at most about 1 per second, and permanent errors (bad token or chat id) are dropped with a log line.
A slow or offline network never delays the lock.

**Commands** (send these to your bot)
| Command | What it does |
|---|---|
| `/status` | watch connected?, lockdown, lockout time left, failed attempts, last event |
| `/log [n]` | last n events (default 5, max 10) |
| `/summary` | today's counts: unlocks, failures, lockouts, timeouts, ... |
| `/lockdown` | block all unlock requests, even valid ones, until `/resume`. Survives a restart |
| `/resume` | allow unlocking again |
| `/help` | list commands |

**Second factor (optional): `GK_REQUIRE_APPROVAL=1`**
After a correct gesture and a valid HMAC, the bot sends "Unlock requested. Approve?" with **Approve** and
**Deny** buttons. The door only opens if you tap Approve within `GK_APPROVAL_TIMEOUT` seconds (default 20).
- A wrong gesture or bad HMAC never reaches this step.
- Deny or no answer keeps the door locked. That is **not** counted as a failed guess (the gesture was right).
- Each request has its own random id, so an old button can never approve a newer request.
- If Telegram is unreachable the door **stays locked** (fail closed). `GK_APPROVAL_FAIL_OPEN=1` allows
  gesture-only unlocks in that case, which is more convenient but weaker: someone who can block your
  network can then bypass the second factor. Leave it off unless you accept that.
- The script refuses to start if approval is on but Telegram is not configured, the listener is off, or
  the chat id is a group (negative number). It never silently runs with weaker security than you asked for.
- Note: the watch already shows "APPROVED" after the gesture, before you tap Approve on your phone.

**Security of commands and buttons:** a bot username is public, so anyone can message it. Commands are
obeyed **only** from the chat id in `TELEGRAM_CHAT_ID`; every other chat is ignored with no reply. Button
presses additionally require that the person pressing is the owner. Messages sent while the script was
offline are skipped at startup so an old `/lockdown` cannot fire later. Only one machine can read a bot's
messages at a time, so teammates should use their own bots, or set `GK_TELEGRAM_COMMANDS=0` for alerts only.

**Setup**
1. Create a bot with **@BotFather** and copy the token.
2. Send your bot any message, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`
   and read your chat id (`"chat":{"id":...}`). It is not the number at the front of the token.
3. Put both in `pi/.env`, or set them in the terminal:
```
# PowerShell
$env:TELEGRAM_BOT_TOKEN="123456:ABC..."
$env:TELEGRAM_CHAT_ID="123456789"
# Linux / Pi
export TELEGRAM_BOT_TOKEN=...  TELEGRAM_CHAT_ID=...
```
4. Check it works: `python3 gk_lock.py --test-telegram`

If the variables are not set, alerts and commands are skipped and the lock works as normal.

## Tests
```
cd pi
python -m unittest discover -s tests -v
```
- `test_merged_features.py`: watch clock and door-status messages, allowed hours (including windows
  that wrap past midnight), and the test-mode switch.
- `test_gk_lock.py`: verify, replay rejection, forged/wrong-key responses, timeouts, lockout and
  expiry (fake watch, mocked network, no hardware needed).
- `test_telegram_bot.py`: alert contents and rate limiting, every command, lockdown (including
  surviving a restart), and the chat-id allow-list: strangers are ignored, the owner is obeyed.
- `test_approval_and_hygiene.py`: the approval second factor (approve, deny, timeout, Telegram down,
  stale and double button presses, impostors), alert retries and backoff, the `.env` loader, the daily
  summary and the startup safety checks.
- `test_firmware_crypto.py`: compiles the watch's `gk_crypto.h` with gcc/clang and checks it matches
  Python's HMAC, including the RFC 4231 test vector. Skipped if no C compiler is installed.
- `test_firmware_protocol_crypto.py`: the firmware's tags and nonces are byte-identical to Python's, the labels
  keep purposes apart, and the rhythm tolerance behaves exactly at its edges.
- `test_two_stack.py`: the lock stack (valid, forged, replayed, expired and silent orders, a rogue lock), mutual
  authentication with the watch, unanswered challenges, counters surviving a restart, and the "approve on phone"
  messages.
- `test_proximity.py`: the decision logic (smoothing, threshold edges, the dead zone, walking away and back,
  silence) and the whole `auto_session()` against a fake Bluetooth library (one check per visit, lock connected
  and released, invisible lock, failed connection, pinned address, lookalikes ignored).
- `test_virtual_door.py`: the on-screen door's file reading (missing, half-written, stale, junk), that `gk_lock.py`
  writes the door state in both modes, and a guard that fails if `gk_lock.py` ever logs an event the window does not know.
- `test_firmware_sim.py`: runs the real `GestureKey.ino` and `LockKey.ino` on your PC against simulated hardware
  (needs g++/clang++), and checks the three programs agree: same key, same shared files, matching timings, different
  Bluetooth names, no Pin-9 reset, no debug display left on.
  It cannot prove the sketches work on the real boards.

## Proximity mode and the on-screen door (added by a teammate)
- **`GK_AUTO=1`** removes the Enter key: the laptop scans the watch's Bluetooth adverts, and when the signal is strong
  enough it connects (to the lock stack too, in `ble` mode) and runs the normal unlock check by itself.
- Distance is judged from signal strength in dBm (closer to 0 = nearer). It is noisy and depends on walls, bodies
  and the room. Run once and read the `[proximity] watch at -xx dBm` lines while you walk up, then set
  `GK_NEAR_RSSI` (start the check) and `GK_FAR_RSSI` (walked away). NEAR must be stronger than FAR, which gives a
  dead zone between them so it does not flap at the edge. Readings are averaged over 3 adverts, and it will not
  trigger again until the watch has walked away or gone quiet for `GK_AWAY_S`.
- **Proximity only starts the check.** The gesture, HMAC, approval, lockdown, hours and lockout all still apply, so a
  person standing near with the watch still has to do the gesture. It is a convenience, not a security factor.
  A side effect: the watch buzzes whenever it comes within range.
- If the lock stack is on but not visible when the watch arrives, the check is refused and logged (`lock_offline`).
- **`python virtual_door.py`** in a second terminal shows the door: green while open, red while locked, an orange flash
  with a beep for refusals (including `lock_error` and `lock_offline`). In `sim` mode it stands in for the lock; in
  `ble` mode it mirrors the real one, which makes it a good backup view for the video. F11 = full screen, Esc = quit.
  `gk_lock.py` writes `door_state.json` (with an expiry, so a crashed program cannot leave the window showing open).

## Door rules
- **Allowed hours:** `GK_ALLOWED_HOURS=7-23` in `pi/.env` refuses unlock attempts outside 07:00-22:59
  (`22-6` wraps past midnight). Refusals are logged and sent to Telegram.
- **Test mode:** `GK_TEST_NO_LOCKOUT=1` stops failed attempts from locking you out while you test gestures.
  It is **off by default** and the script prints a warning when it is on. Turn it off for the demo, or the
  lockout and its Telegram alert will not happen.
- **Clock and door status on the watch** are sent automatically on connect and after every unlock.

## What the watch shows
- **Idle screen:** the clock (set by the Pi on connect and after every unlock), the door state
  (green `UNLOCKED` / red `LOCKED`, shown once the Pi is connected) and the time of the last unlock.
- **During a challenge:** progress dots and a `Time left` countdown that turns red for the last 3 seconds.
  The countdown redraws only its own line, so it never disturbs flick detection.
- The accelerometer is only read while a gesture is being entered, which saves battery.

## Gesture tips (how the detector behaves)
- Wait for the buzz and the `Unlock? Flick` screen, then flick. Motion in the first half second after
  the buzz or after a screen redraw is deliberately ignored.
- Pause about half a second between flicks. The arm must settle (`REARM_THRESHOLD` for `REARM_SAMPLES`
  samples) before the next flick can start, so a flick made too soon is **missed, never misread as the
  opposite direction**. In our simulation, flicking too early gave 73 wrong symbols out of 150 without
  this check and 0 with it (normal pacing: 150 of 150 correct either way). A missed flick costs you
  nothing; a wrong one would count as a failed attempt.
- Brief knocks (`MIN_SUSTAIN_SAMPLES`) and diagonal moves (`DOMINANCE_RATIO`) are ignored.
- Use `TUNE_MODE true` to see the peak values and adjust `FLICK_THRESHOLD`. Set `REARM_THRESHOLD` to
  `9999` to switch the settle check off. These numbers come from a simulator, not the real watch, so
  confirm them on your wrist.
- `GESTURE_LEN` is 3: with 4 directions that is 64 combinations. A single flick (4 combinations) can be
  guessed in a few tries, so keep it at 3 or more outside of testing.

## Tuning the gesture
Set `TUNE_MODE true` in `GestureKey.ino`, open the Serial Monitor at 115200, and watch the values while flicking.
Adjust `FLICK_THRESHOLD` and the settle settings until detection is reliable. Default gesture: RIGHT, RIGHT, DOWN with
1.0 s pauses. Re-record with the upper-left button within 5 minutes of power-up.

## Limitations
Be upfront about these in the video.
- **One shared key** in the watch, the lock and the laptop: extracting it from any one device (for example the
  flash of a lost watch) compromises all three. A real product would use a key per device and protected storage.
- **Re-enrolment:** anyone holding the watch can re-record the gesture in the first 5 minutes after power-up. The
  laptop still has to approve, but a stolen watch with a new gesture is a stolen watch that unlocks for its thief
  if the thief can also pass the laptop's rules. Do not rely on the enrol window for security.
- **Gesture memory:** the gesture lives in RAM (no EEPROM shield), so it returns to the default in the code after a
  restart. Put your rehearsed values in the code as the default.
- **Weak guessing resistance:** 64 direction combinations times a few bits of rhythm is a few hundred possibilities.
  The lockout slows guessing but does not make it hard; the Telegram approval is the real second factor.
- **No encryption:** an eavesdropper sees the nonces, tags, door state and clock. They cannot forge anything, but they
  learn when the door is used. The display-only messages (`S`, `T`, `L`, `W`, `D`) are not authenticated, so a nearby
  attacker could change what the watch *shows* (never whether the door opens).
- **Bluetooth denial of service:** a device that connects to the watch or lock first blocks the laptop (one connection
  at a time). A device advertising as `GKey` could trick the laptop into connecting to it; it cannot forge an approval,
  but set `GK_ADDR` and `GK_LOCK_ADDR` to pin the real addresses.
- **No hardware random number generator** on the SAMD21: nonces are `HMAC(secret key, counter || timers)`, which
  nobody can predict without the key, and which never repeat.
- **The laptop is the single point of trust.** If it is compromised, so is the door.
- **The latch is a demo.** A 2.5 g servo cannot resist being forced.

## Team and contributions
Credit each person for what they built. Example: the watch clock, the door-status display and the
allowed-hours rule were added by a teammate (add their name below).

| Member | Area |
|---|---|
| | Watch UI and firmware |
| | Gesture engine |
| | Crypto and BLE protocol |
| | Laptop controller (`pi/`), proximity mode, on-screen door |
| | Hardware and 3D printing |
| | Dashboard, video, submission |

Commit your own work under your own name so the history shows who did what.

## References
Background reading for the design. These are cited for ideas only; none of their code is used.

**HMAC and hashing**
- H. Krawczyk, M. Bellare, R. Canetti, *HMAC: Keyed-Hashing for Message Authentication*,
  RFC 2104, 1997. https://www.rfc-editor.org/info/rfc2104
- NIST, *Secure Hash Standard (SHS)*, FIPS 180-4 (specification used for `gk_crypto.h`).

**Challenge-response and replay attacks**
- UPenn CIS 551 lecture notes, *Authentication protocols* (nonces and replay).
  https://www.cis.upenn.edu/~stevez/cis551/2007/web/lectures/CIS551-17.pdf
- JumpCloud, *What Is Challenge Response Authentication?* (explainer).
  https://jumpcloud.com/it-index/what-is-challenge-response-authentication

**Wrist-motion authentication research** (behavioural biometrics; GestureKey instead uses a
secret flick sequence, so these are context, not a claim of equivalence)
- A. Buriro et al., *AirSign: A Gesture-Based Smartwatch User Authentication*, ICCST 2018.
  https://repository.essex.ac.uk/40839/
- M. Eskandari et al., *SnapAuth: A Gesture-Based Unobtrusive Smartwatch User Authentication
  Scheme*, 2018. https://cris.fbk.eu/handle/11582/315865
- F. Kerber, P. Schardt, M. Loechtefeld, *WristRotate: A Personalized Motion Gesture Delimiter
  for Wrist-Worn Devices*, MUM 2015.
  https://www.dfki.de/web/forschung/projekte-publikationen/publikation/8163

## Attribution
- Proximity mode (`GK_AUTO`) and `virtual_door.py`: written by a teammate (add their name); adapted to the two-stack
  version of `gk_lock.py`.
- BLE UART service and example structure: TinyCircuits ST BLE SmartWatch example
- BMA250 driver and TinyScreen library: TinyCircuits
- Accelerometer polling pattern: TinyScreen_FlappyBirds_accelero example
- SHA-256 / HMAC: implemented from FIPS 180-4 and RFC 2104
- Servo control on the lock stack: TinyCircuits ATtiny841 library (`ServoDriver.h`) and the Servo Controller
  TinyShield tutorial, https://learn.tinycircuits.com/Motors/Servo-Controller_TinyShield_Tutorial/
- Bluetooth on the laptop: `bleak`; dashboard: Flask; optional local servo on a Raspberry Pi: `gpiozero`
- The handshake design (a nonce from each side, authenticated with HMAC) follows standard challenge-response
  practice; see the references above. The code is our own.
- Add any further code you adapt here and in the source file headers.
