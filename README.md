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
  gk_notify.py         Telegram alerts (standard library only)
  dashboard.py         Flask page showing the access log
  gk_key.txt           shared key (hex) -- NOT in git
  tests/               unit tests (verify/lockout logic, Telegram, firmware crypto)
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

## Telegram alerts
The Pi sends a Telegram message on every unlock and when a lockout starts.
1. Create a bot with **@BotFather** and copy the token.
2. Send your bot any message, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`
   and read your chat id.
3. Set environment variables (never commit the token):
```
# PowerShell
$env:TELEGRAM_BOT_TOKEN="123456:ABC..."
$env:TELEGRAM_CHAT_ID="123456789"
# Linux / Pi
export TELEGRAM_BOT_TOKEN=...  TELEGRAM_CHAT_ID=...
```
4. Check it works: `python3 gk_lock.py --test-telegram`

If the variables are not set, alerts are skipped and the lock works as normal.

## Tests
```
cd pi
python -m unittest discover -s tests -v
```
- `test_gk_lock.py`: verify, replay rejection, forged/wrong-key responses, timeouts, lockout and
  expiry, Telegram alerts (fake watch, mocked network, no hardware needed).
- `test_firmware_crypto.py`: compiles the watch's `gk_crypto.h` with gcc/clang and checks it matches
  Python's HMAC, including the RFC 4231 test vector. Skipped if no C compiler is installed.

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
