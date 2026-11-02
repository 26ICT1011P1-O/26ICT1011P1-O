//-------------------------------------------------------------------------------
//  GestureKey - wrist-worn challenge-response authenticator (TinyScreen+)
//
//  Flow:
//    1. Raspberry Pi (BLE central) writes  'C' + 16-byte random nonce  to the watch.
//    2. Watch wakes and asks for the secret wrist gesture (3 flicks).
//    3. Gesture is read from the BMA250 accelerometer and compared with the template.
//    4. Match    -> watch notifies  'R' + first 16 bytes of HMAC-SHA256(key, 'A'+nonce)
//       No match -> watch notifies  'N'  (denied)
//    5. Pi verifies the HMAC, drives the servo lock, logs the attempt.
//    Pi may also send 'L' (locked out) which the watch just displays.
//    Pi sends 'T'+hour+min+sec to set the watch clock (the watch has no battery-backed RTC).
//    Pi also sends 'S'+'U' (door unlocked) / 'S'+'K' (door locked) so the idle screen shows the door state.
//
//  ATTRIBUTION (the brief requires this - keep it in the video too):
//    - BLE UART service (UART.ino, STBLE library): TinyCircuits ST BLE smartwatch
//      example "SmartWatchAndroidST_TZ", by Ben Rose / TinyCircuits.
//    - Accelerometer driver (BMA250.h/.cpp) and TinyScreen library: TinyCircuits.
//    - Button handling, screen on/off and vibration-pin pattern adapted from the
//      same SmartWatch example.
//    - Accelerometer polling pattern adapted from TinyScreen_FlappyBirds_accelero.
//    - gk_crypto.h: SHA-256/HMAC implemented from FIPS 180-4 / RFC 2104.
//    - Everything else (gesture detection, state machine, protocol, clock, countdown): our own work.
//
//  Files that must sit in this sketch folder: GestureKey.ino, UART.ino,
//  BMA250.h, BMA250.cpp, gk_crypto.h, secrets.h
//-------------------------------------------------------------------------------

#include <stdio.h>
#include <SPI.h>
#include <Wire.h>
#include <TinyScreen.h>
#include <STBLE.h>
#include "BMA250.h"
#include "gk_crypto.h"
#include "secrets.h"

#define BLE_DEBUG true
#define SerialMonitorInterface SerialUSB
#define TUNE_MODE false          // true = stream h / v flick values to Serial Monitor (for calibration)

// If the screen stays blank, try TinyScreenPlus here (the lab examples use Default).
TinyScreen display = TinyScreen(TinyScreenPlus);
BMA250 accel;

// ---- variables UART.ino expects to exist (same names as the SmartWatch example) ----
uint8_t ble_rx_buffer[21];
uint8_t ble_rx_buffer_len = 0;
uint8_t ble_can_sleep = false;
uint8_t ble_connection_state = false;

// ---- tuning ----
// Counts are above the gravity baseline (256 counts = 1 g at +/-2 g).
const float         FLICK_THRESHOLD     = 110.0;  // peak needed to START a flick. Raise if small movements count, lower if real flicks are missed
const float         SUSTAIN_THRESHOLD   = 60.0;   // a real flick stays above this for a few samples; a cable tug or knock is a brief spike
const uint8_t       MIN_SUSTAIN_SAMPLES = 3;      // samples (10 ms each) that must reach SUSTAIN_THRESHOLD. 1 = most forgiving, 4 = strict
const float         DOMINANCE_RATIO     = 1.3;    // winning axis must beat the other axis by this factor, else the flick is ignored as diagonal
const float         LP_ALPHA            = 0.05;   // gravity baseline speed (smaller = slower)
const uint8_t       REARM_SAMPLES       = 4;      // ...and stay below it for this many samples in a row (4 x 10 ms). One sample is not enough:
                                                  // the signal passes through zero between a flick and its swing-back
const float         REARM_THRESHOLD     = 40.0;   // before a new flick can start, the arm must settle below this. Stops the swing-back of a flick that was
                                                  // missed (e.g. you flicked too soon after the buzz) being misread as a flick in the OPPOSITE direction. 9999 = off
const unsigned long SAMPLE_MS           = 10;     // 100 Hz sampling
const unsigned long CAPTURE_MS          = 60;     // after a flick starts, track the peak this long before choosing a direction
const unsigned long REFRACTORY_MS       = 450;    // ignore the "return swing" after a flick
const unsigned long STEP_TIMEOUT_MS     = 4000;   // max pause between flicks of one gesture
const unsigned long CHALLENGE_TIMEOUT_MS = 12000; // must stay BELOW RESPONSE_TIMEOUT_S in gk_lock.py (15 s), or the Pi gives up first
const unsigned long RESULT_SHOW_MS      = 2000;
const unsigned long SCREEN_TIMEOUT_MS   = 15000;
const unsigned long ENROL_WINDOW_MS     = 300000; // gesture can only be re-recorded this long after power-up (5 min)
// Number of flicks in the secret. With 4 directions there are 4^GESTURE_LEN combinations:
// 1 flick = 4 (guessable in a few tries), 3 flicks = 64. Keep at 3 or more for real use.
const uint8_t       GESTURE_LEN         = 3;

// ---- orientation (set these during calibration so UP/DOWN/LEFT/RIGHT match how the watch is worn) ----
const bool SWAP_AXES = false;   // true if the board's X axis is your up/down axis
const bool INVERT_H  = false;   // true if right/left come out reversed
const bool INVERT_V  = false;   // true if up/down come out reversed

// Flick symbols: direction the watch is pushed
enum { SYM_RIGHT = 0, SYM_LEFT = 1, SYM_UP = 2, SYM_DOWN = 3 };

// Default gesture: RIGHT, RIGHT, DOWN.  Re-record with UPPER-LEFT button within 5 min of power-up.
// (Kept in RAM only: the SAMD21 has no EEPROM, so it resets to this default on power cycle.)
uint8_t gestureTemplate[GESTURE_LEN] = { SYM_RIGHT, SYM_RIGHT, SYM_DOWN };

// Debug aid: shows each detected flick direction on the watch. Set to false for the demo,
// because it leaks the secret gesture.
const bool DEBUG_SHOW_DIR = false;

const char* symName(int8_t s) {
  switch (s) {
    case SYM_RIGHT: return "RIGHT";
    case SYM_LEFT:  return "LEFT";
    case SYM_UP:    return "UP";
    default:        return "DOWN";
  }
}

char symChar(int8_t s) {
  switch (s) {
    case SYM_RIGHT: return 'R';
    case SYM_LEFT:  return 'L';
    case SYM_UP:    return 'U';
    default:        return 'D';
  }
}

// ---- state machine ----
enum State { ST_IDLE, ST_CHALLENGE, ST_ENROL, ST_RESULT };
State state = ST_IDLE;

uint8_t  nonce[16];
uint8_t  entered[GESTURE_LEN];
uint8_t  enteredCount = 0;
unsigned long lastStepTime = 0;
unsigned long stateStart = 0;
unsigned long screenTimer = 0;
uint8_t  displayOn = 0;
uint8_t  buttonReleased = 1;
uint8_t  lastBleShown = 255;
enum DoorState { DOOR_UNKNOWN, DOOR_LOCKED, DOOR_UNLOCKED };
DoorState doorState = DOOR_UNKNOWN;   // last door state reported by the Pi

// ---- clock: the Pi sets the time, the watch counts forward from its own timer ----
bool          timeKnown = false;
uint32_t      timeBaseSec = 0;          // seconds since midnight at the last sync
unsigned long timeBaseMs = 0;           // millis() at the last sync
int32_t       lastUnlockSec = -1;       // time of the last unlock confirmed by the Pi (-1 = none yet)
uint32_t      lastClockMinute = 0xFFFFFFFF;   // minute currently drawn, so the screen refreshes once a minute

uint32_t nowSec() { return (timeBaseSec + (millis() - timeBaseMs) / 1000UL) % 86400UL; }

void fmtTime(char* out, uint32_t sec) {   // out must hold at least 6 chars: "HH:MM"
  snprintf(out, 6, "%02lu:%02lu", (unsigned long)((sec / 3600UL) % 24UL), (unsigned long)((sec / 60UL) % 60UL));
}
uint8_t  lastCountdownShown = 255;   // seconds-left value currently drawn (255 = redraw needed)
bool     flickReset = true;       // set after anything slow (screen redraw, buzz) or at the start of a gesture, so the gravity baseline re-primes

const FONT_INFO& font10pt = thinPixel7_10ptFontInfo;
const uint8_t vibratePin = 6;      // same pin as the SmartWatch example (optional vibration board)

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------
void showScreen(const char* l1, const char* l2, const char* l3, uint8_t color) {
  flickReset = true;   // a redraw blocks the loop, so the baseline must re-prime afterwards
  lastCountdownShown = 255;   // a full redraw wipes the countdown line, so draw it again
  display.clearScreen();
  display.setFont(font10pt);
  display.fontColor(color, TS_8b_Black);
  display.setCursor(2, 8);  display.print(l1);
  display.fontColor(TS_8b_White, TS_8b_Black);
  display.setCursor(2, 26); display.print(l2);
  display.setCursor(2, 42); display.print(l3);
}

void wakeScreen() {
  screenTimer = millis();
  if (!displayOn) { display.on(); displayOn = 1; }
}

// Progress is shown as dots. With DEBUG_SHOW_DIR the last flick direction is also shown.
void showProgress(const char* title) {
  char dots[2 * GESTURE_LEN + 1];
  for (uint8_t i = 0; i < GESTURE_LEN; i++) {
    dots[2 * i]     = (i < enteredCount) ? '*' : '-';
    dots[2 * i + 1] = ' ';
  }
  dots[2 * GESTURE_LEN] = '\0';
  showScreen(title, dots,
             (DEBUG_SHOW_DIR && enteredCount > 0) ? symName(entered[enteredCount - 1]) : "",
             TS_8b_Yellow);
}

// Shows "Time left 12s" on the third line during a challenge. It redraws only that line
// (no clearScreen, no baseline reset), once per second, so it never disturbs flick detection.
void drawCountdown() {
  unsigned long elapsed = millis() - stateStart;
  uint8_t left = (elapsed >= CHALLENGE_TIMEOUT_MS) ? 0 : (uint8_t)((CHALLENGE_TIMEOUT_MS - elapsed + 999UL) / 1000UL);
  if (left == lastCountdownShown) return;
  lastCountdownShown = left;
  char buf[16];
  snprintf(buf, sizeof(buf), "Time left %2ds ", (int)left);   // trailing space wipes leftover characters
  display.setFont(font10pt);
  display.fontColor(left <= 3 ? TS_8b_Red : TS_8b_Gray, TS_8b_Black);   // turns red for the last 3 seconds
  display.setCursor(2, 42);
  display.print(buf);
}

void showIdle() {
  lastBleShown = ble_connection_state;
  char l1[16], l3[16], t[6];
  if (timeKnown) { fmtTime(t, nowSec()); snprintf(l1, sizeof(l1), "GKey  %s", t); }
  else           { snprintf(l1, sizeof(l1), "GKey  --:--"); }
  lastClockMinute = timeKnown ? nowSec() / 60UL : 0xFFFFFFFF;

  bool showDoor = ble_connection_state && doorState != DOOR_UNKNOWN;
  const char* l2 = showDoor ? (doorState == DOOR_UNLOCKED ? "Door: UNLOCKED" : "Door: LOCKED")
                            : (ble_connection_state ? "Pi: connected" : "Pi: waiting...");
  if (lastUnlockSec >= 0) { fmtTime(t, (uint32_t)lastUnlockSec); snprintf(l3, sizeof(l3), "Last: %s", t); }
  else snprintf(l3, sizeof(l3), "%s", (millis() < ENROL_WINDOW_MS) ? "UL btn = enrol" : "Ready");

  showScreen(l1, l2, l3, ble_connection_state ? TS_8b_Green : TS_8b_Gray);
  if (showDoor) {                       // redraw the door line in colour: green = unlocked, red = locked
    display.fontColor(doorState == DOOR_UNLOCKED ? TS_8b_Green : TS_8b_Red, TS_8b_Black);
    display.setCursor(2, 26);
    display.print(l2);
  }
}

void buzz(unsigned int ms) {
  digitalWrite(vibratePin, HIGH);
  delay(ms);
  digitalWrite(vibratePin, LOW);
  flickReset = true;
}

// ---------------------------------------------------------------------------
// Gesture detection
// ---------------------------------------------------------------------------
// Returns a symbol (0..3) when a flick is detected, otherwise -1.
// Method: a slow low-pass filter tracks gravity (the "baseline"); subtracting it leaves
// only the motion. The board axes are first mapped to horizontal (h) and vertical (v)
// using the orientation settings above. A flick STARTS when h or v passes FLICK_THRESHOLD.
// The peak on each axis is then tracked for CAPTURE_MS and the direction is chosen from the
// strongest swing (not the first sample, which is often noise). It is only accepted if it
// stays strong for MIN_SUSTAIN_SAMPLES (rejects cable tugs and knocks) and one axis clearly
// beats the other (rejects diagonal movements). A refractory period, then a short "settle" check
// (REARM_THRESHOLD), stop the opposite "return swing" being counted as a second flick.
int8_t pollFlick() {
  static unsigned long lastSample = 0, lastFlick = 0, capStart = 0;
  static float lpX = 0, lpY = 0, pkH = 0, pkV = 0;
  static bool capturing = false, armed = false;
  static uint8_t sustain = 0, quiet = 0;

  if (millis() - lastSample < SAMPLE_MS) return -1;
  lastSample = millis();

  accel.read();
  float x = accel.X, y = accel.Y;
  if (flickReset) { lpX = x; lpY = y; capturing = false; armed = false; quiet = 0; lastFlick = millis(); flickReset = false; }
  float hpX = x - lpX, hpY = y - lpY;
  lpX += LP_ALPHA * (x - lpX);
  lpY += LP_ALPHA * (y - lpY);

  float h = SWAP_AXES ? hpY : hpX;      // horizontal motion
  float v = SWAP_AXES ? hpX : hpY;      // vertical motion
  if (INVERT_H) h = -h;
  if (INVERT_V) v = -v;

  float ah = h < 0 ? -h : h;
  float av = v < 0 ? -v : v;

#if TUNE_MODE
  if (ah >= 25 || av >= 25) {           // only print real movement so the numbers are readable
    SerialMonitorInterface.print("h="); SerialMonitorInterface.print((int)h);
    SerialMonitorInterface.print(" v="); SerialMonitorInterface.println((int)v);
  }
#endif

  if (!capturing) {
    if (millis() - lastFlick < REFRACTORY_MS) { armed = false; quiet = 0; return -1; }
    if (!armed) {                                   // wait for the arm to come to rest first (see REARM_THRESHOLD)
      if (ah < REARM_THRESHOLD && av < REARM_THRESHOLD) { if (++quiet >= REARM_SAMPLES) armed = true; }
      else quiet = 0;
      return -1;
    }
    if (ah < FLICK_THRESHOLD && av < FLICK_THRESHOLD) return -1;
    armed = false; quiet = 0;                       // after this flick the arm must settle again before the next one
    capturing = true; capStart = millis(); pkH = h; pkV = v; sustain = 1;   // flick started: watch the peak for a moment
    return -1;
  }

  // Keep the largest swing on each axis (with its sign) during the capture window
  if (ah > (pkH < 0 ? -pkH : pkH)) pkH = h;
  if (av > (pkV < 0 ? -pkV : pkV)) pkV = v;
  if (ah >= SUSTAIN_THRESHOLD || av >= SUSTAIN_THRESHOLD) sustain++;
  if (millis() - capStart < CAPTURE_MS) return -1;

  capturing = false;
  float aH = pkH < 0 ? -pkH : pkH;
  float aV = pkV < 0 ? -pkV : pkV;
#if TUNE_MODE
  SerialMonitorInterface.print("FLICK pkH="); SerialMonitorInterface.print((int)pkH);
  SerialMonitorInterface.print(" pkV=");      SerialMonitorInterface.print((int)pkV);
  SerialMonitorInterface.print(" samples=");  SerialMonitorInterface.println(sustain);
#endif
  if (sustain < MIN_SUSTAIN_SAMPLES) return -1;   // too brief: cable tug or knock, not a deliberate flick
  lastFlick = millis();
  if (aH >= aV * DOMINANCE_RATIO) return (pkH > 0) ? SYM_RIGHT : SYM_LEFT;
  if (aV >= aH * DOMINANCE_RATIO) return (pkV > 0) ? SYM_UP : SYM_DOWN;
  return -1;                                      // diagonal / ambiguous: ignore rather than guess
}

// ---------------------------------------------------------------------------
// BLE protocol
// ---------------------------------------------------------------------------
void sendApproval() {
  uint8_t msg[17];
  msg[0] = 'A';
  memcpy(msg + 1, nonce, 16);
  uint8_t mac[32];
  gk_hmac_sha256(GK_KEY, sizeof(GK_KEY), msg, sizeof(msg), mac);

  uint8_t out[17];
  out[0] = 'R';
  memcpy(out + 1, mac, 16);               // truncated to 128 bits so it fits one BLE packet
  lib_aci_send_data(0, out, sizeof(out));  // notify on the RX characteristic (from UART.ino)
}

void sendDenied() {
  uint8_t out[1] = { 'N' };
  lib_aci_send_data(0, out, 1);
}

void handleBleMessage() {
  if (!ble_rx_buffer_len) return;
  uint8_t type = ble_rx_buffer[0];
  uint8_t len  = ble_rx_buffer_len;

  // Debug: shows in Arduino Serial Monitor (115200) for every packet from the Pi
  SerialMonitorInterface.print("BLE rx type=");
  SerialMonitorInterface.print((char)((type >= 32 && type < 127) ? type : '?'));
  SerialMonitorInterface.print(" len=");
  SerialMonitorInterface.println(len);

  if (type == 'C' && len == 17 && state != ST_ENROL) {
    memcpy(nonce, ble_rx_buffer + 1, 16);   // copy at once: the buffer is overwritten by the next write
    enteredCount = 0;
    flickReset = true;
    state = ST_CHALLENGE;
    stateStart = millis();
    wakeScreen();
    buzz(80);
    showProgress("Unlock? Flick");
  } else if (type == 'S' && len == 2) {
    // Door status from the Pi: 'U' = unlocked, 'K' = locked
    DoorState prev = doorState;
    doorState = (ble_rx_buffer[1] == 'U') ? DOOR_UNLOCKED : DOOR_LOCKED;
    if (doorState == DOOR_UNLOCKED && prev != DOOR_UNLOCKED && timeKnown) lastUnlockSec = (int32_t)nowSec();
    if (state == ST_IDLE) {              // never interrupt a gesture or a result screen; the idle redraw shows it later
      wakeScreen();
      showIdle();
      if (doorState == DOOR_UNLOCKED && prev != DOOR_UNLOCKED) { buzz(60); delay(80); buzz(60); }   // double pulse
    }
  } else if (type == 'T' && len == 4) {
    // Clock sync from the Pi: hour, minute, second
    if (ble_rx_buffer[1] < 24 && ble_rx_buffer[2] < 60 && ble_rx_buffer[3] < 60) {
      timeBaseSec = ble_rx_buffer[1] * 3600UL + ble_rx_buffer[2] * 60UL + ble_rx_buffer[3];
      timeBaseMs = millis();
      timeKnown = true;
      if (state == ST_IDLE && displayOn) showIdle();     // update the clock without waking the screen
    }
  } else if (type == 'L') {
    state = ST_RESULT;
    stateStart = millis();
    wakeScreen();
    showScreen("LOCKED OUT", "Too many", "failed tries", TS_8b_Red);
  } else {
    // Packet arrived but was not a valid challenge: say so on screen instead of ignoring silently
    char l2[24];
    snprintf(l2, sizeof(l2), "type=%c len=%d", (type >= 32 && type < 127) ? (char)type : '?', len);
    state = ST_RESULT;
    stateStart = millis();
    wakeScreen();
    showScreen("RX ignored", l2, (type == 'C' && len == 17) ? "enrol mode?" : "expect C,17", TS_8b_Yellow);
  }
  ble_rx_buffer_len = 0;
}

// ---------------------------------------------------------------------------
// State handling
// ---------------------------------------------------------------------------
bool gestureMatches() {
  uint8_t diff = 0;                        // accumulate differences, no early exit
  for (uint8_t i = 0; i < GESTURE_LEN; i++) diff |= (entered[i] ^ gestureTemplate[i]);
  return diff == 0;
}

void finishResult(bool ok) {
  state = ST_RESULT;
  stateStart = millis();
  if (ok) {
    sendApproval();
    showScreen("APPROVED", "Door unlocking", "", TS_8b_Green);
    buzz(80);
  } else {
    sendDenied();
    char got[GESTURE_LEN + 1];
    for (uint8_t i = 0; i < GESTURE_LEN; i++) got[i] = symChar(entered[i]);
    got[GESTURE_LEN] = '\0';
    showScreen("DENIED", "Wrong gesture", DEBUG_SHOW_DIR ? got : "", TS_8b_Red);
    buzz(400);
  }
}

void onFlick(int8_t sym) {
  wakeScreen();

  // A long pause means the person restarted the gesture
  if (enteredCount > 0 && millis() - lastStepTime > STEP_TIMEOUT_MS) enteredCount = 0;
  entered[enteredCount++] = sym;
  lastStepTime = millis();

  if (state == ST_CHALLENGE) {
    if (enteredCount < GESTURE_LEN) { showProgress("Unlock? Flick"); return; }
    finishResult(gestureMatches());
  } else if (state == ST_ENROL) {
    if (enteredCount < GESTURE_LEN) { showProgress("Enrol: flick"); return; }
    memcpy(gestureTemplate, entered, GESTURE_LEN);
    state = ST_RESULT;
    stateStart = millis();
    showScreen("SAVED", "New gesture", "stored in RAM", TS_8b_Green);
    buzz(80);
  }
}

void checkButtons() {
  uint8_t buttons = display.getButtons();
  if (buttonReleased && buttons) {
    bool wasOff = !displayOn;
    wakeScreen();
    // Enrol: only from idle, only shortly after power-up
    if (!wasOff && state == ST_IDLE && (buttons & TSButtonUpperLeft) && millis() < ENROL_WINDOW_MS) {
      state = ST_ENROL;
      enteredCount = 0;
      flickReset = true;
      stateStart = millis();
      showProgress("Enrol: flick");
    } else if (wasOff && state == ST_IDLE) {
      showIdle();
    }
    buttonReleased = 0;
  }
  if (!buttonReleased && !(buttons & 0x0F)) buttonReleased = 1;
}

void setup() {
  SerialMonitorInterface.begin(115200);
  Wire.begin();
  display.begin();
  display.setFlip(true);
  display.setBrightness(5);
  pinMode(vibratePin, OUTPUT);
  digitalWrite(vibratePin, LOW);

  if (accel.begin(BMA250_range_2g, BMA250_update_time_4ms) != 0) {
    showScreen("ERROR", "No accel board", "check stack", TS_8b_Red);
    while (1) {}
  }
  displayOn = 1;
  screenTimer = millis();
  BLEsetup();            // from UART.ino
  showIdle();
}

void loop() {
  aci_loop();            // BLE handler from UART.ino: must run often, keep loop short
  handleBleMessage();

  if (state == ST_CHALLENGE || state == ST_ENROL) {   // idle: skip the accelerometer (saves battery)
    int8_t sym = pollFlick();
    if (sym >= 0) onFlick(sym);
  }

  switch (state) {
    case ST_CHALLENGE:
      drawCountdown();
      if (millis() - stateStart > CHALLENGE_TIMEOUT_MS) {
        state = ST_RESULT;
        stateStart = millis();
        showScreen("TIMED OUT", "No gesture", "", TS_8b_Gray);
      }
      break;
    case ST_RESULT:
      if (millis() - stateStart > RESULT_SHOW_MS) { state = ST_IDLE; showIdle(); }
      break;
    case ST_ENROL:
      if (millis() - stateStart > 30000) { state = ST_IDLE; showIdle(); }   // give up quietly
      break;
    case ST_IDLE:
      if (lastBleShown != ble_connection_state) {
        if (!ble_connection_state) doorState = DOOR_UNKNOWN;   // link lost: we no longer know the door state
        wakeScreen(); showIdle();
      }   // wake + redraw when the link changes
      if (displayOn && timeKnown && nowSec() / 60UL != lastClockMinute) showIdle();   // clock tick, once a minute
      if (displayOn && millis() - screenTimer > SCREEN_TIMEOUT_MS) { display.off(); displayOn = 0; }
      break;
  }
  checkButtons();
}
