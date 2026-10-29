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

## Unlock method: scrambled button keypad

The watch is unlocked with its four physical buttons (the TinyScreen+ screen is not
touch). Instead of a fixed PIN pad, the watch shows four letters in the corners of the
screen, one beside each button, and **reshuffles them for every challenge**. The secret
is a sequence of *letters* (currently **B, then D**), so the button you press changes
every attempt. Someone watching your hand cannot copy the code, because the buttons
pressed are different each time.

### How it works
1. The Pi sends a challenge (`'C'` + 16 random bytes).
2. `shuffleLayout()` uses those random bytes to shuffle which letter sits beside which
   button (Fisher-Yates shuffle).
3. `drawKeypad()` draws the four letters in the screen corners, with progress dots in the
   middle. The letters pressed are never shown, only dots.
4. `pollKeypad()` detects each button press (with debounce) and converts the button back
   into the letter currently beside it.
5. After `GESTURE_LEN` presses the watch compares the letters with the secret. A match
   sends `'R'` + HMAC to the Pi. A mismatch sends `'N'` (denied).

### Button positions
| Button | Index | Screen corner |
|---|---|---|
| Upper left | 0 | top-left |
| Upper right | 1 | top-right |
| Lower left | 2 | bottom-left |
| Lower right | 3 | bottom-right |


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
