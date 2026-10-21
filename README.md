# 26ICT1011P1-O
ICT1011 Team Exploration Project
Project concept: GestureKey, a wrist-worn challenge-response door lock
A TinyScreen+ acts as a physical authenticator. You unlock a door by performing a secret wrist gesture (a motion "password") and approving a challenge on the OLED. The TinyScreen+ and a Raspberry Pi-controlled lock then complete a cryptographic handshake over BLE, so it isn't just a static code.
I chose a security theme because it gives you a strong story for the Creativity rubric. It also forces real programming on more than one platform, which is what the Technical rubric rewards.

How it works
1. The Raspberry Pi (BLE central, next to the lock) sends a random challenge to the TinyScreen+.
2. The watch shows "Unlock? Perform gesture" on the OLED.
3. The wearer performs a secret gesture (for example flick, flick, tilt). The accelerometer data is matched against the stored gesture template on the watch.
4. If the gesture matches, the watch computes a response (HMAC of the challenge with a shared key) and sends it back over BLE.
5. The Pi verifies the response, drives a servo to unlock, and logs the event (success, failure, timestamp).
6. After 3 failed attempts the Pi locks out for a period, and the watch shows an alert.
7. A small web dashboard on the Pi shows the live access log.

Mapping to the rubric
I could only see part of the rubric table, so I'm assuming the rightmost column is the top band. The visible text of the lower bands already shows what to avoid.
Criterion
What the lower bands penalise
What GestureKey does for top marks
Creativity (5)
Copies of Lab 4, simple re-implementations, or cases "found online"
A security-focused wearable with gesture auth and challenge-response is not a stock smartwatch or Flappy Bird variant. The 3D-printed lock mechanism also shows it isn't "just a watch" (the briefing says the application need not be a watch).
Technical (5)
Unmodified code, or a single platform with light changes
Original firmware on the TinyScreen+ (gesture matching, HMAC, BLE protocol, UI), plus a Raspberry Pi service (BLE client, verification, servo control, Flask dashboard). That is multiple platforms with significant programming on at least one, which is the top band's wording.
YouTube (5)
Minimal demo, no evidence of effort
Clear big picture (the problem with keys and PINs), a live demo including a failed attempt and lockout, distribution of work, and citations of sources. Keep it to 2–3 minutes.
Demonstration (5)
Partial or minimal working
Fully working end to end on 26 Nov, with a rehearsed script and a fallback plan (see risks).

Materials
Already in your kit: TinyScreen+, accelerometer board, BLE expansion board, 3.7V 150mAh battery, micro-USB cable.

Likely extras (check what's available):
Raspberry Pi with Bluetooth (a Pi 3, 4 or Zero 2 W works) and a microSD card
Small hobby servo (SG90 or similar) and jumper wires
5V supply for the Pi and servo
3D-printed parts: watch case or strap mount, and a servo bracket or latch model (the briefing says you'll have some 3D printer access)
Optional: a TinyCircuits buzzer or vibration/haptic shield for feedback on a wrong gesture. I couldn't see the contents of the TinyCircuit_Accessories_Oct26 deck, so check there for what's actually offered.

Software and libraries:
Arduino IDE with the TinyCircuits board support and the TinyScreen+ library
The nRF8001 BLE library used by the TinyCircuits BLE board and the examples in the LMS zips
A lightweight SHA-256/HMAC library for Arduino/SAMD21
On the Pi: Python 3, a BLE library (bleak or bluepy), Flask, and gpiozero or pigpio for servo control
GitHub for version control, which also helps with the work-distribution evidence
