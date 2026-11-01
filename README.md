# GestureKey

A wrist-worn challenge-response door lock built for the ICT1011 Team Exploration Project.
A TinyScreen+ watch asks the wearer for a secret wrist gesture, then proves it to a
Raspberry Pi over Bluetooth Low Energy using HMAC-SHA256. The Pi drives a servo lock,
logs every attempt and enforces a lockout after repeated failures.

> Prototype for coursework, not production security. See "Limitations".

## How it works
1. Pi sends `'C'` + 16 random bytes (the challenge) to the watch.
2. Watch wakes and asks for 3 flicks. Progress is shown as dots only.
3. If the gesture matches, the watch replies `'R'` + first 16 bytes of
   `HMAC-SHA256(key, 'A' + nonce)`. Otherwise it replies `'N'`.
4. Pi verifies the HMAC, unlocks the servo, and logs the result.
5. After 3 failures the Pi locks out for 30 s and sends `'L'` to the watch.
6. The Pi also keeps the watch informed: `'T'` + hour, minute, second sets its clock (the watch has no
   battery-backed clock), and `'S'` + `U`/`K` tells it whether the door is unlocked or locked.

## Repository layout
```
GestureKey/            Arduino sketch for the TinyScreen+ (open GestureKey.ino)
  GestureKey.ino       state machine, gesture detection, BLE protocol
  UART.ino             BLE UART service (adapted from TinyCircuits example)
  BMA250.h/.cpp        accelerometer driver (TinyCircuits)
  gk_crypto.h          SHA-256 + HMAC (FIPS 180-4 / RFC 2104)
  secrets.h            shared key  -- NOT in git, see below
pi/
  gk_lock.py           BLE client, verifier, lockout, servo, logging
  gk_notify.py         Telegram alerts, commands, approval buttons (standard library only)
  .env.example         template for pi/.env (token, chat id, options)
  dashboard.py         Flask page showing the access log
  gk_key.txt           shared key (hex) -- NOT in git
```

## Hardware
- TinyScreen+ with accelerometer board and BLE (ST) board, 3.7 V battery, micro-USB cable
- Raspberry Pi with Bluetooth, plus a hobby servo (signal on GPIO 18)
- 3D-printed lock bracket and watch mount

## Setup

### Watch
1. Install the Arduino IDE.
2. Follow the TinyScreen+ setup tutorial linked in the Lab 4 manual
   (TinyCircuits board package and drivers; select the TinyScreen+ board).
3. Install the libraries used by the lab examples: TinyScreen and the ST BLE library
   (provides `STBLE.h`). Take them from `TinyCircuit_Examples.zip` on the LMS if needed.
4. Create `GestureKey/secrets.h` (see Secrets).
5. In `UART.ino`, change the last byte of `bdaddr` so your watch is unique in the lab.
6. Open `GestureKey/GestureKey.ino`, select the board and port, Upload.

### Raspberry Pi
```
pip install bleak gpiozero pigpio flask
python3 pi/gk_lock.py        # press Enter to request an unlock
python3 pi/dashboard.py      # log page on http://<pi-ip>:5000
```

## Secrets
`secrets.h` and `pi/gk_key.txt` hold the same 16-byte key and are git-ignored.
Generate a key and share it with teammates privately (not via GitHub):
```
python3 -c "import os;print(os.urandom(16).hex())"
```
`gk_key.txt` holds the hex string; `secrets.h` holds the same bytes as a C array.

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

## Door rules
- **Allowed hours:** `GK_ALLOWED_HOURS=7-23` in `pi/.env` refuses unlock attempts outside 07:00-22:59
  (`22-6` wraps past midnight). Refusals are logged and sent to Telegram.
- **Test mode:** `GK_TEST_NO_LOCKOUT=1` stops failed attempts from locking you out while you test gestures.
  It is **off by default** and the script prints a warning when it is on. Turn it off for the demo, or the
  lockout and its Telegram alert will not happen.
- **Clock and door status on the watch** are sent automatically on connect and after every unlock.

## Tuning the gesture
Set `TUNE_MODE true` in `GestureKey.ino`, open the Serial Monitor, and watch the values
while flicking. Adjust `FLICK_THRESHOLD` and `REFRACTORY_MS` until detection is reliable.
Default gesture: X+, X+, Y-. Re-record with the upper-left button within 60 s of power-up.

## Limitations
- Gesture is stored in RAM only and resets on power cycle.
- Anyone with physical access can power-cycle the watch and re-enrol.
- Protects against replayed responses and brute-force guessing at the Pi;
  does not defend against a stolen watch whose owner is coerced, or a compromised Pi.

## Team and contributions
Credit each person for what they built. Example: the watch clock, the door-status display and the
allowed-hours rule were added by a teammate (add their name below).

| Member | Area |
|---|---|
| | Watch UI and firmware |
| | Gesture engine |
| | Crypto and BLE protocol |
| | Pi backend |
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
- BLE UART service and example structure: TinyCircuits ST BLE SmartWatch example
- BMA250 driver and TinyScreen library: TinyCircuits
- Accelerometer polling pattern: TinyScreen_FlappyBirds_accelero example
- SHA-256 / HMAC: implemented from FIPS 180-4 and RFC 2104
- BLE on the Pi: `bleak`; servo: `gpiozero`; dashboard: Flask
- Add any further code you adapt here and in the source file headers.
