//-------------------------------------------------------------------------------
//  GestureKey - wrist-worn challenge-response authenticator (TinyScreen+)
//
//  Flow (the laptop decides everything; the watch only judges the gesture):
//    1. Laptop sends 'Q'. Watch answers 'Z'+wn (its own fresh nonce).
//    2. Laptop sends 'C'+pn (its nonce) and 'M'+tag, proving it knows the shared key.
//       The watch IGNORES any request that does not carry a valid proof (mutual authentication).
//    3. Watch wakes and asks for the secret wrist gesture (3 flicks, direction AND rhythm).
//    4. Match    -> watch notifies 'R'+tag_A(wn,pn), then shows "Checking..." until the laptop answers
//       No match -> watch notifies 'N' (denied)
//    5. Laptop verifies, applies approval/lockdown/hours rules, and opens the LOCK (a second TinyScreen+
//       with the servo shield). The watch itself drives no lock.
//    Laptop may also send: 'W'+secs (approve on phone), 'D'+code (N denied, T timed out, X phone
//    unreachable, F lock error), 'L'+secs (locked out, with countdown), 'B'+reason (refused before a challenge:
//    D lockdown, H outside hours +start+end, K lock offline), 'S'+'U'/'K' (door state), 'T'+h+m+s (clock).
//    Upper-right button at the idle screen starts CALIBRATION (sets orientation and flick strength from the wearer's own flicks).
//    Tags are HMAC-SHA256 truncated to 16 bytes (see gk_auth.h).
//
//  ATTRIBUTION (the brief requires this - keep it in the video too):
//    - BLE UART service (UART.ino, STBLE library): TinyCircuits ST BLE smartwatch
//      example "SmartWatchAndroidST_TZ", by Ben Rose / TinyCircuits.
//    - Accelerometer driver (BMA250.h/.cpp) and TinyScreen library: TinyCircuits.
//    - Button handling, screen on/off and vibration-pin pattern adapted from the
//      same SmartWatch example.
//    - Accelerometer polling pattern adapted from TinyScreen_FlappyBirds_accelero.
//    - gk_crypto.h: SHA-256/HMAC implemented from FIPS 180-4 / RFC 2104.
//    - Calibration, lockout countdown, refusal screens and haptic ticks: added by a teammate (credit them in the video).
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
#include "gk_auth.h"
#include "gk_gesture.h"
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

// Rhythm: the pauses between flicks are part of the secret too, so copying the directions by watching is not enough.
// A pause matches if it is within max(RHYTHM_MIN_TOL_MS, RHYTHM_TOL_PCT % of the stored pause). Set USE_RHYTHM false to check directions only.
const bool          USE_RHYTHM          = true;
const uint16_t      RHYTHM_MIN_TOL_MS   = 350;
const uint8_t       RHYTHM_TOL_PCT      = 40;
const unsigned long AUTH_WINDOW_MS      = 5000;   // the laptop has this long to finish its proof after the watch hands out a nonce
const unsigned long VERIFY_TIMEOUT_MS   = 30000;  // after a correct gesture, how long to wait for the laptop's verdict

// ---- haptic feedback while entering a gesture ----
const bool          TICK_ON_FLICK       = true;   // short vibration when a flick is counted (not the last one: that has its own buzz)
const bool          TICK_ON_REJECT      = true;   // two very short pulses when a movement was too brief or too diagonal and was ignored
const unsigned int  TICK_MS             = 25;

// ---- calibration (upper-right button at the idle screen) ----
const float         CAL_START_THRESHOLD = 45.0;   // detector sensitivity while calibrating, so gentle flicks are still seen
const float         CAL_MIN_MEAN_PEAK   = 90.0;   // calibration is refused if the wearer's flicks average weaker than this
const unsigned long CAL_TIMEOUT_MS      = 45000;
const uint8_t       CAL_RIGHT_FLICKS    = 3;      // "flick RIGHT" this many times, then
const uint8_t       CAL_DOWN_FLICKS     = 2;      // "flick DOWN" this many times

// ---- orientation (calibration sets these at run time; these are the defaults after power-up) ----
const bool SWAP_AXES = false;   // true if the board's X axis is your up/down axis
const bool INVERT_H  = false;   // true if right/left come out reversed
const bool INVERT_V  = false;   // true if up/down come out reversed

// Flick symbols: direction the watch is pushed
enum { SYM_RIGHT = 0, SYM_LEFT = 1, SYM_UP = 2, SYM_DOWN = 3 };

// Default gesture: RIGHT, RIGHT, DOWN.  Re-record with UPPER-LEFT button within 5 min of power-up.
// (Kept in RAM only: the SAMD21 has no EEPROM, so it resets to this default on power cycle.)
uint8_t gestureTemplate[GESTURE_LEN] = { SYM_RIGHT, SYM_RIGHT, SYM_DOWN };
// Default rhythm: the pause (ms) after flick 1 and after flick 2. One entry per pause (GESTURE_LEN - 1); the last entry is unused.
// Re-recorded together with the directions. Put your rehearsed values here to make them the default after a restart.
uint16_t gestureGapMs[GESTURE_LEN] = { 1000, 1000 };

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
enum State { ST_IDLE, ST_CHALLENGE, ST_VERIFY, ST_ENROL, ST_RESULT, ST_LOCKOUT, ST_CALIB };
State state = ST_IDLE;

uint8_t  wn[16], pn[16];              // watch nonce + laptop nonce of the CURRENT challenge
uint8_t  wnNext[16], pnNext[16];      // handshake in progress: becomes current only after the laptop's proof checks out
bool     authWait = false, havePn = false;
unsigned long authSince = 0;
uint32_t nonceCounter = 0;
uint16_t enteredGapMs[GESTURE_LEN];   // pauses measured during this attempt
unsigned long countdownMs = CHALLENGE_TIMEOUT_MS;   // length of the countdown currently shown
unsigned long verifyLimitMs = VERIFY_TIMEOUT_MS;    // how long to wait for the laptop in ST_VERIFY
bool     waitingPhone = false;        // true while the laptop is waiting for the owner's tap
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
// Run-time copies of the tuning that calibration can change (they start at the constants above).
bool     swapAxes = SWAP_AXES, invertH = INVERT_H, invertV = INVERT_V;
float    flickThreshold = FLICK_THRESHOLD;
bool     flickIgnored = false;            // set by pollFlick when a movement was rejected (too brief / too diagonal)
float    calPkX = 0, calPkY = 0;          // raw (un-mapped) peaks of the last flick, used by calibration
bool     calibrating = false;
unsigned long lockoutEndMs = 0;           // when the lockout countdown ends
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

// Shows "Time left 12s" (gesture) or "Approve in 20s" (phone) on the third line. It redraws only that line
// (no clearScreen, no baseline reset), once per second, so it never disturbs flick detection.
void drawCountdown() {
  unsigned long elapsed = millis() - stateStart;
  uint8_t left = (elapsed >= countdownMs) ? 0 : (uint8_t)((countdownMs - elapsed + 999UL) / 1000UL);
  if (left == lastCountdownShown) return;
  lastCountdownShown = left;
  char buf[24];
  snprintf(buf, sizeof(buf), "%s %2ds ", waitingPhone ? "Approve in" : "Time left", (int)left);   // trailing space wipes leftover characters
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
  static float lpX = 0, lpY = 0, pkH = 0, pkV = 0, pkX = 0, pkY = 0;
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

  float h = swapAxes ? hpY : hpX;       // horizontal motion
  float v = swapAxes ? hpX : hpY;       // vertical motion
  if (invertH) h = -h;
  if (invertV) v = -v;

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
    if (ah < flickThreshold && av < flickThreshold) return -1;
    armed = false; quiet = 0;                       // after this flick the arm must settle again before the next one
    capturing = true; capStart = millis(); pkH = h; pkV = v; pkX = hpX; pkY = hpY; sustain = 1;   // flick started: watch the peak for a moment
    return -1;
  }

  // Keep the largest swing on each axis (with its sign) during the capture window
  if (ah > (pkH < 0 ? -pkH : pkH)) pkH = h;
  if (av > (pkV < 0 ? -pkV : pkV)) pkV = v;
  if ((hpX < 0 ? -hpX : hpX) > (pkX < 0 ? -pkX : pkX)) pkX = hpX;      // raw peaks (before axis mapping) for calibration
  if ((hpY < 0 ? -hpY : hpY) > (pkY < 0 ? -pkY : pkY)) pkY = hpY;
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
  if (sustain < MIN_SUSTAIN_SAMPLES) { flickIgnored = true; return -1; }   // too brief: cable tug or knock, not a deliberate flick
  lastFlick = millis();
  if (calibrating) { calPkX = pkX; calPkY = pkY; return SYM_RIGHT; }       // calibration measures the raw peaks and does not care about direction
  if (aH >= aV * DOMINANCE_RATIO) return (pkH > 0) ? SYM_RIGHT : SYM_LEFT;
  if (aV >= aH * DOMINANCE_RATIO) return (pkV > 0) ? SYM_UP : SYM_DOWN;
  flickIgnored = true;
  return -1;                                      // diagonal / ambiguous: ignore rather than guess
}

void showResult(const char* l1, const char* l2, const char* l3, uint8_t color);   // defined further down
void abortCalibrationIfRunning();                                                  // defined with the calibration code

// ---------------------------------------------------------------------------
// Lockout countdown
// ---------------------------------------------------------------------------
void startLockoutScreen(uint8_t secs) {
  abortCalibrationIfRunning();
  lockoutEndMs = millis() + (unsigned long)secs * 1000UL;
  state = ST_LOCKOUT;
  stateStart = millis();
  waitingPhone = false;
  wakeScreen();
  showScreen("LOCKED OUT", "Try again in", "", TS_8b_Red);
}

// Redraws only the third line, once a second (same idea as drawCountdown).
void drawLockoutCountdown() {
  unsigned long now = millis();
  uint8_t left = (now >= lockoutEndMs) ? 0 : (uint8_t)((lockoutEndMs - now + 999UL) / 1000UL);
  if (left == lastCountdownShown) return;
  lastCountdownShown = left;
  char buf[16];
  snprintf(buf, sizeof(buf), "%3d s    ", (int)left);
  display.setFont(font10pt);
  display.fontColor(TS_8b_White, TS_8b_Black);
  display.setCursor(2, 42);
  display.print(buf);
}

// ---------------------------------------------------------------------------
// Calibration: "flick RIGHT" x3, then "flick DOWN" x2. From the raw peaks it works out which board axis is
// right/left, which is up/down and their signs, and sets the flick threshold to 60 % of the wearer's average peak.
// ---------------------------------------------------------------------------
uint8_t calStage = 0;           // flicks collected so far
float   calSumRX, calSumRY, calAbsRX, calAbsRY;     // RIGHT flicks: signed and absolute sums of the raw X / Y peaks
float   calSumDX, calSumDY, calAbsDX, calAbsDY;     // DOWN flicks
float   calSumPeak;             // sum of the strongest raw axis of every flick
float   calSavedThreshold;

void calShowStep() {
  char l3[16];
  if (calStage < CAL_RIGHT_FLICKS) { snprintf(l3, sizeof(l3), "%d of %d", calStage + 1, CAL_RIGHT_FLICKS); showScreen("Calibrate", "Flick RIGHT", l3, TS_8b_Yellow); }
  else { snprintf(l3, sizeof(l3), "%d of %d", calStage - CAL_RIGHT_FLICKS + 1, CAL_DOWN_FLICKS); showScreen("Calibrate", "Flick DOWN", l3, TS_8b_Yellow); }
}

void startCalibration() {
  calibrating = true;
  calSavedThreshold = flickThreshold;
  flickThreshold = CAL_START_THRESHOLD;
  calStage = 0;
  calSumRX = calSumRY = calAbsRX = calAbsRY = calSumDX = calSumDY = calAbsDX = calAbsDY = calSumPeak = 0;
  state = ST_CALIB;
  stateStart = millis();
  flickReset = true;
  wakeScreen();
  calShowStep();
}

// Anything that takes the screen away from calibration (a lockout, a stray message...) must also end it. Otherwise the
// watch would keep counting every flick as RIGHT with the gentle calibration threshold, and the real gesture would fail.
void abortCalibrationIfRunning() {
  if (!calibrating) return;
  calibrating = false;
  flickThreshold = calSavedThreshold;
}

void endCalibration(const char* l1, const char* l2, const char* l3, uint8_t color, bool keep) {
  calibrating = false;
  if (!keep) flickThreshold = calSavedThreshold;      // cancelled or refused: back to the old settings
  showResult(l1, l2, l3, color);
}

// Works out the settings from the sums. Returns false (and says why on screen) if the flicks were inconsistent or too weak.
void calFinish() {
  float absX = calAbsRX, absY = calAbsRY;
  bool  rightOnY = absY > absX;                                   // the axis the RIGHT flicks moved along
  float rightSigned = rightOnY ? calSumRY : calSumRX;
  float rightAbs    = rightOnY ? calAbsRY : calAbsRX;
  float rightOther  = rightOnY ? calAbsRX : calAbsRY;
  float downSigned  = rightOnY ? calSumDX : calSumDY;             // DOWN must use the OTHER axis
  float downAbs     = rightOnY ? calAbsDX : calAbsDY;
  float downOther   = rightOnY ? calAbsDY : calAbsDX;
  float meanPeak = calSumPeak / (CAL_RIGHT_FLICKS + CAL_DOWN_FLICKS);

  float rs = rightSigned < 0 ? -rightSigned : rightSigned;
  float ds = downSigned < 0 ? -downSigned : downSigned;
  if (rs < 0.6 * rightAbs || ds < 0.6 * downAbs) {                // signs disagree: the flicks were not consistent
    endCalibration("CAL FAILED", "Inconsistent", "try again", TS_8b_Red, false); buzz(300); return;
  }
  if (downAbs < 1.3 * downOther || rightAbs < 1.3 * rightOther) { // movement not clearly along one axis each time
    endCalibration("CAL FAILED", "Not straight", "try again", TS_8b_Red, false); buzz(300); return;
  }
  if (meanPeak < CAL_MIN_MEAN_PEAK) {
    endCalibration("TOO GENTLE", "Flick harder", "try again", TS_8b_Yellow, false); buzz(300); return;
  }

  swapAxes = rightOnY;
  invertH  = rightSigned < 0;                 // RIGHT must come out positive on the horizontal axis
  invertV  = downSigned > 0;                  // DOWN must come out negative on the vertical axis
  float thr = 0.6 * meanPeak;
  if (thr < 60.0) thr = 60.0;
  if (thr > 200.0) thr = 200.0;
  flickThreshold = thr;

  SerialMonitorInterface.print("CALIBRATION swap="); SerialMonitorInterface.print(swapAxes);
  SerialMonitorInterface.print(" invertH=");        SerialMonitorInterface.print(invertH);
  SerialMonitorInterface.print(" invertV=");        SerialMonitorInterface.print(invertV);
  SerialMonitorInterface.print(" threshold=");      SerialMonitorInterface.println((int)flickThreshold);
  char l2[16], l3[16];
  snprintf(l2, sizeof(l2), "thr %d", (int)flickThreshold);
  snprintf(l3, sizeof(l3), "%s%s%s", swapAxes ? "S" : "-", invertH ? "H" : "-", invertV ? "V" : "-");
  endCalibration("CAL DONE", l2, l3, TS_8b_Green, true);
  buzz(80);
}

void onCalFlick() {
  float ax = calPkX < 0 ? -calPkX : calPkX, ay = calPkY < 0 ? -calPkY : calPkY;
  calSumPeak += (ax > ay) ? ax : ay;
  if (calStage < CAL_RIGHT_FLICKS) { calSumRX += calPkX; calSumRY += calPkY; calAbsRX += ax; calAbsRY += ay; }
  else                              { calSumDX += calPkX; calSumDY += calPkY; calAbsDX += ax; calAbsDY += ay; }
  calStage++;
  if (calStage >= CAL_RIGHT_FLICKS + CAL_DOWN_FLICKS) { calFinish(); return; }
  if (TICK_ON_FLICK) buzz(TICK_MS);
  calShowStep();
}

// ---------------------------------------------------------------------------
// BLE protocol
// ---------------------------------------------------------------------------
void sendApproval() {
  uint8_t out[1 + GK_TAG_LEN];
  out[0] = 'R';
  gk_tag_A(GK_KEY, sizeof(GK_KEY), wn, pn, out + 1);   // proves THIS gesture answered THIS pair of nonces
  lib_aci_send_data(0, out, sizeof(out));              // notify on the RX characteristic (from UART.ino)
}

void sendDenied() {
  uint8_t out[1] = { 'N' };
  lib_aci_send_data(0, out, 1);
}

void showResult(const char* l1, const char* l2, const char* l3, uint8_t color) {
  abortCalibrationIfRunning();
  state = ST_RESULT;
  stateStart = millis();
  waitingPhone = false;
  wakeScreen();
  showScreen(l1, l2, l3, color);
}

void startChallenge() {                       // the laptop has proven it knows the key
  memcpy(wn, wnNext, GK_NONCE_LEN);
  memcpy(pn, pnNext, GK_NONCE_LEN);
  enteredCount = 0;
  flickReset = true;
  waitingPhone = false;
  countdownMs = CHALLENGE_TIMEOUT_MS;
  state = ST_CHALLENGE;
  stateStart = millis();
  wakeScreen();
  buzz(80);
  showProgress("Unlock? Flick");
}

void handleBleMessage() {
  if (!ble_rx_buffer_len) return;
  uint8_t type = ble_rx_buffer[0];
  uint8_t len  = ble_rx_buffer_len;

  // Debug: shows in Arduino Serial Monitor (115200) for every packet from the laptop
  SerialMonitorInterface.print("BLE rx type=");
  SerialMonitorInterface.print((char)((type >= 32 && type < 127) ? type : '?'));
  SerialMonitorInterface.print(" len=");
  SerialMonitorInterface.println(len);

  if (type == 'Q' && len == 1) {
    // Laptop asks for a nonce. Written to wnNext, so a challenge already in progress is never disturbed.
    gk_make_nonce(GK_KEY, sizeof(GK_KEY), nonceCounter++, micros(), millis(), wnNext);
    authWait = true; havePn = false; authSince = millis();
    uint8_t out[1 + GK_NONCE_LEN];
    out[0] = 'Z';
    memcpy(out + 1, wnNext, GK_NONCE_LEN);
    lib_aci_send_data(0, out, sizeof(out));
  } else if (type == 'C' && len == 1 + GK_NONCE_LEN) {
    // Laptop's nonce. Only taken while a handshake we started is open; otherwise silently dropped.
    if (authWait && millis() - authSince <= AUTH_WINDOW_MS) { memcpy(pnNext, ble_rx_buffer + 1, GK_NONCE_LEN); havePn = true; }
  } else if (type == 'M' && len == 1 + GK_TAG_LEN) {
    // Laptop's proof that it knows the key. A nonce is used once, whether the proof is good or not.
    bool ok = false;
    if (authWait && havePn && state != ST_ENROL && state != ST_CALIB && state != ST_LOCKOUT && millis() - authSince <= AUTH_WINDOW_MS) {
      uint8_t expect[GK_TAG_LEN];
      gk_tag_P(GK_KEY, sizeof(GK_KEY), wnNext, pnNext, expect);
      ok = gk_ct_equal(expect, ble_rx_buffer + 1, GK_TAG_LEN) != 0;
    }
    authWait = false; havePn = false;
    if (ok) startChallenge();
    else SerialMonitorInterface.println("auth: proof rejected, request ignored");   // no screen change: strangers get no reaction
  } else if (type == 'W' && len == 2) {
    // Laptop: gesture accepted, now waiting for the owner to tap Approve on the phone. ble_rx_buffer[1] = seconds.
    if (state == ST_VERIFY) {
      waitingPhone = true;
      countdownMs = (unsigned long)ble_rx_buffer[1] * 1000UL;
      verifyLimitMs = countdownMs + 8000UL;            // grace for the laptop's final message
      stateStart = millis();
      wakeScreen();
      showScreen("Approve on", "your phone", "", TS_8b_Yellow);
    }
  } else if (type == 'D' && len == 2) {
    // Laptop's decision after a correct gesture that did not lead to an unlock
    if (state == ST_VERIFY) {
      switch (ble_rx_buffer[1]) {
        case 'N': showResult("DENIED", "Owner said no", "", TS_8b_Red); buzz(300); break;
        case 'T': showResult("TIMED OUT", "No approval", "", TS_8b_Gray); break;
        case 'X': showResult("NOT APPROVED", "Phone unreachable", "", TS_8b_Red); break;
        case 'F': showResult("LOCK ERROR", "Door not opened", "", TS_8b_Red); buzz(300); break;
        default:  showResult("NOT APPROVED", "Laptop said no", "", TS_8b_Red); break;
      }
    }
  } else if (type == 'S' && len == 2) {
    // Door status from the laptop: 'U' = unlocked, 'K' = locked
    DoorState prev = doorState;
    doorState = (ble_rx_buffer[1] == 'U') ? DOOR_UNLOCKED : DOOR_LOCKED;
    if (doorState == DOOR_UNLOCKED && prev != DOOR_UNLOCKED && timeKnown) lastUnlockSec = (int32_t)nowSec();
    if (state == ST_VERIFY && doorState == DOOR_UNLOCKED) {      // the laptop opened the lock: this is the real "approved"
      showResult("APPROVED", "Door unlocking", "", TS_8b_Green);
      buzz(80);
    } else if (state == ST_IDLE) {       // never interrupt a gesture or a result screen; the idle redraw shows it later
      wakeScreen();
      showIdle();
      if (doorState == DOOR_UNLOCKED && prev != DOOR_UNLOCKED) { buzz(60); delay(80); buzz(60); }   // double pulse
    }
  } else if (type == 'T' && len == 4) {
    // Clock sync from the laptop: hour, minute, second
    if (ble_rx_buffer[1] < 24 && ble_rx_buffer[2] < 60 && ble_rx_buffer[3] < 60) {
      timeBaseSec = ble_rx_buffer[1] * 3600UL + ble_rx_buffer[2] * 60UL + ble_rx_buffer[3];
      timeBaseMs = millis();
      timeKnown = true;
      if (state == ST_IDLE && displayOn) showIdle();     // update the clock without waking the screen
    }
  } else if (type == 'L') {
    // Locked out. 'L' + seconds starts a live countdown; a bare 'L' (older laptop program) shows the short message.
    uint8_t secs = (len >= 2) ? ble_rx_buffer[1] : 0;
    if (secs > 0) { startLockoutScreen(secs); buzz(200); }
    else showResult("LOCKED OUT", "Too many", "failed tries", TS_8b_Red);
  } else if (type == 'B' && len >= 2) {
    // The laptop refused before asking for a gesture. Only shown from the idle screen (never interrupts anything).
    if (state == ST_IDLE) {
      char l3[20];
      switch (ble_rx_buffer[1]) {
        case 'D': showResult("LOCKDOWN", "Door is locked", "by the owner", TS_8b_Red); buzz(150); break;
        case 'H':
          if (len >= 4 && ble_rx_buffer[2] < 24 && ble_rx_buffer[3] <= 24) snprintf(l3, sizeof(l3), "Open %02d-%02d h", ble_rx_buffer[2], ble_rx_buffer[3]);
          else snprintf(l3, sizeof(l3), "later");
          showResult("CLOSED NOW", "Outside hours", l3, TS_8b_Yellow); buzz(150); break;
        case 'K': showResult("LOCK OFFLINE", "Door not ready", "try again soon", TS_8b_Yellow); buzz(150); break;
        default:  showResult("REFUSED", "by the laptop", "", TS_8b_Yellow); break;
      }
    }
  } else {
    // Packet we do not understand: say so on screen instead of ignoring silently
    char l2[24];
    snprintf(l2, sizeof(l2), "type=%c len=%d", (type >= 32 && type < 127) ? (char)type : '?', len);
    showResult("RX ignored", l2, "unknown message", TS_8b_Yellow);
  }
  ble_rx_buffer_len = 0;
}

// ---------------------------------------------------------------------------
// State handling
// ---------------------------------------------------------------------------
bool gestureMatches() {
  // Both checks always run, so the time taken never reveals which part failed (and the screen says only "Wrong gesture").
  int dirs   = gk_dirs_match(gestureTemplate, entered, GESTURE_LEN);
  int rhythm = USE_RHYTHM ? gk_rhythm_match(gestureGapMs, enteredGapMs, GESTURE_LEN - 1, RHYTHM_MIN_TOL_MS, RHYTHM_TOL_PCT) : 1;
  return dirs && rhythm;
}

void finishResult(bool ok) {
  state = ST_RESULT;
  stateStart = millis();
  if (ok) {
    sendApproval();
    // Not "approved" yet: the laptop still has to check, apply its rules and open the lock.
    waitingPhone = false;
    countdownMs = VERIFY_TIMEOUT_MS;
    verifyLimitMs = VERIFY_TIMEOUT_MS;
    state = ST_VERIFY;
    showScreen("Gesture OK", "Checking...", "", TS_8b_Green);
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
  if (enteredCount > 0) {                       // pause since the previous flick = the rhythm
    unsigned long gap = millis() - lastStepTime;
    enteredGapMs[enteredCount - 1] = (gap > 65535UL) ? 65535 : (uint16_t)gap;
  }
  entered[enteredCount++] = sym;
  lastStepTime = millis();

  if (state == ST_CHALLENGE) {
    if (enteredCount < GESTURE_LEN) { if (TICK_ON_FLICK) buzz(TICK_MS); showProgress("Unlock? Flick"); return; }
    finishResult(gestureMatches());
  } else if (state == ST_ENROL) {
    if (enteredCount < GESTURE_LEN) { if (TICK_ON_FLICK) buzz(TICK_MS); showProgress("Enrol: flick"); return; }
    memcpy(gestureTemplate, entered, GESTURE_LEN);
    memcpy(gestureGapMs, enteredGapMs, sizeof(gestureGapMs));      // the rhythm is saved together with the directions
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
    } else if (!wasOff && state == ST_IDLE && (buttons & TSButtonUpperRight)) {
      startCalibration();
    } else if (state == ST_CALIB) {
      endCalibration("Calibration", "cancelled", "", TS_8b_Gray, false);
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

  if (state == ST_CHALLENGE || state == ST_ENROL || state == ST_CALIB) {   // idle: skip the accelerometer (saves battery)
    int8_t sym = pollFlick();
    if (sym >= 0) { if (state == ST_CALIB) onCalFlick(); else onFlick(sym); }
    else if (flickIgnored) {                                   // movement seen but rejected: tell the wearer without looking
      flickIgnored = false;
      if (TICK_ON_REJECT && state != ST_CALIB) { buzz(15); delay(60); buzz(15); }
    }
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
    case ST_VERIFY:
      if (waitingPhone) drawCountdown();
      if (millis() - stateStart > verifyLimitMs) showResult("NO REPLY", "from laptop", "", TS_8b_Gray);
      break;
    case ST_RESULT:
      if (millis() - stateStart > RESULT_SHOW_MS) { state = ST_IDLE; showIdle(); }
      break;
    case ST_ENROL:
      if (millis() - stateStart > 30000) { state = ST_IDLE; showIdle(); }   // give up quietly
      break;
    case ST_LOCKOUT:
      drawLockoutCountdown();
      if (millis() >= lockoutEndMs) { state = ST_IDLE; showIdle(); }
      break;
    case ST_CALIB:
      if (millis() - stateStart > CAL_TIMEOUT_MS) endCalibration("Calibration", "timed out", "", TS_8b_Gray, false);
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
