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
//
//  ATTRIBUTION (the brief requires this - keep it in the video too):
//    - BLE UART service (UART.ino, STBLE library): TinyCircuits ST BLE smartwatch
//      example "SmartWatchAndroidST_TZ", by Ben Rose / TinyCircuits.
//    - Accelerometer driver (BMA250.h/.cpp) and TinyScreen library: TinyCircuits.
//    - Button handling, screen on/off and vibration-pin pattern adapted from the
//      same SmartWatch example.
//    - Accelerometer polling pattern adapted from TinyScreen_FlappyBirds_accelero.
//    - gk_crypto.h: SHA-256/HMAC implemented from FIPS 180-4 / RFC 2104.
//    - Everything else (gesture detection, state machine, protocol): our own work.
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
#define KEYPAD_MODE true         // true = scrambled button keypad unlock (no wrist movement). false = old flick gesture
#define EASY_MODE false          // true = ANY 3 flicks/shakes unlock (direction ignored). Use this to get the demo working, then set false for a secret direction gesture
#define TEST_NO_TIMEOUT true    // true = no time limit on flicks while testing (normal timeouts are on)
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
// FLICK_THRESHOLD is in counts above the gravity baseline (256 counts = 1 g at +/-2 g)
const float         FLICK_THRESHOLD     = 45.0;   // peak needed to START a flick (about 0.4 g). Raise if cable jitter still counts, lower if real flicks are missed
const float         SUSTAIN_THRESHOLD   = 25.0;   // a real flick stays above this for several samples; a cable twitch is a brief spike
const uint8_t       MIN_SUSTAIN_SAMPLES = 1;      // samples (10 ms each) that must reach SUSTAIN_THRESHOLD. 2 = more forgiving, 4 = stricter
const float         DOMINANCE_RATIO     = 1.0;    // direction mode only: winning axis must beat the other axis by this factor
const float         LP_ALPHA            = 0.05;   // gravity baseline tracking (smaller = slower, ~200 ms at 100 Hz)
const unsigned long SAMPLE_MS           = 10;     // 100 Hz sampling (was 50 Hz)
const unsigned long CAPTURE_MS          = 60;     // after a flick starts, track the peak this long before deciding direction
const unsigned long REFRACTORY_MS       = 250;    // ignore the "return swing" after a flick
const unsigned long STEP_TIMEOUT_MS     = 6000;   // max pause between flicks of one gesture
const unsigned long CHALLENGE_TIMEOUT_MS = 9000;  // Pi gives up after ~10 s
const unsigned long RESULT_SHOW_MS      = 2000;
const unsigned long SCREEN_TIMEOUT_MS   = 15000;
const unsigned long ENROL_WINDOW_MS     = 60000;  // gesture can only be re-recorded this long after power-up
const uint8_t       GESTURE_LEN         = 2;      // testing: 2 flicks (was 3)

// ---- orientation (set these during calibration so UP/DOWN/LEFT/RIGHT match how the watch is worn) ----
const bool SWAP_AXES = false;   // true if the board's X axis is your up/down axis
const bool INVERT_H  = false;   // true if right/left come out reversed
const bool INVERT_V  = false;   // true if up/down come out reversed

// Flick symbols: direction the watch is pushed
enum { SYM_RIGHT = 0, SYM_LEFT = 1, SYM_UP = 2, SYM_DOWN = 3 };

// Default gesture (testing): UP, RIGHT.  Re-record with UPPER-LEFT button within 60 s of power-up.
// (Kept in RAM only: the SAMD21 has no EEPROM, so it resets to this default on power cycle.)
uint8_t gestureTemplate[GESTURE_LEN] = { SYM_UP, SYM_RIGHT };

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

const FONT_INFO& font10pt = thinPixel7_10ptFontInfo;
const uint8_t vibratePin = 6;      // same pin as the SmartWatch example (optional vibration board)

// ---------------------------------------------------------------------------
// Scrambled button keypad (KEYPAD_MODE)
// Four glyphs are shown in the screen corners, one beside each physical button. The
// layout is reshuffled for every challenge (seeded from the Pi's random nonce), so
// watching which BUTTONS someone presses does not reveal the secret. The secret is a
// sequence of GLYPHS, e.g. "B then D", and you press whichever button currently sits
// beside that glyph. The screen is not touch: use the 4 buttons on the watch body.
// ---------------------------------------------------------------------------
const char    KEY_GLYPHS[4] = { 'A', 'B', 'C', 'D' };                         // try "*#+@" for symbols
const uint8_t KEY_COLORS[4] = { TS_8b_Red, TS_8b_Green, TS_8b_Yellow, TS_8b_White };
uint8_t keypadSecret[GESTURE_LEN] = { 1, 3 };   // glyph indexes: 0=A 1=B 2=C 3=D  -> secret is "B then D"
const bool KEYPAD_FLIP = false;                 // set true if a glyph appears on the opposite side to its button
uint8_t layout[4] = { 0, 1, 2, 3 };             // layout[button position] = glyph index. Positions: 0=UL 1=UR 2=LL 3=LR

void shuffleLayout() {
  for (uint8_t i = 0; i < 4; i++) layout[i] = i;
  for (uint8_t i = 3; i > 0; i--) {              // Fisher-Yates, driven by the random challenge bytes
    uint8_t j = nonce[i] % (i + 1);
    uint8_t t = layout[i]; layout[i] = layout[j]; layout[j] = t;
  }
}

void drawKeypad() {
  static const uint8_t px[4] = { 4, 84, 4, 84 };   // screen corners: UL, UR, LL, LR
  static const uint8_t py[4] = { 4, 4, 50, 50 };
  display.clearScreen();
  display.setFont(font10pt);
  for (uint8_t pos = 0; pos < 4; pos++) {
    uint8_t slot = KEYPAD_FLIP ? 3 - pos : pos;
    display.fontColor(KEY_COLORS[layout[pos]], TS_8b_Black);
    display.setCursor(px[slot], py[slot]);
    display.print(KEY_GLYPHS[layout[pos]]);
  }
  char dots[2 * GESTURE_LEN + 1];                  // progress as dots only, never the glyphs chosen
  for (uint8_t i = 0; i < GESTURE_LEN; i++) {
    dots[2 * i]     = (i < enteredCount) ? '*' : '-';
    dots[2 * i + 1] = ' ';
  }
  dots[2 * GESTURE_LEN] = '\0';
  display.fontColor(TS_8b_Gray, TS_8b_Black);
  display.setCursor(28, 28);
  display.print(dots);
}

// Returns the glyph index of the button just pressed, or -1.
int8_t pollKeypad() {
  static uint8_t prev = 0xFF;
  static unsigned long lastPress = 0;
  if (state != ST_CHALLENGE) { prev = 0xFF; return -1; }   // ignore buttons held down when the challenge starts
  uint8_t b = display.getButtons() & 0x0F;
  uint8_t newly = b & ~prev;
  prev = b;
  if (!newly || millis() - lastPress < 150) return -1;     // 150 ms debounce
  lastPress = millis();
  int8_t pos = -1;
  if (newly & TSButtonUpperLeft)       pos = 0;
  else if (newly & TSButtonUpperRight) pos = 1;
  else if (newly & TSButtonLowerLeft)  pos = 2;
  else if (newly & TSButtonLowerRight) pos = 3;
  if (pos < 0) return -1;
  return layout[pos];
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------
extern bool flickReset;
void showScreen(const char* l1, const char* l2, const char* l3, uint8_t color) {
  flickReset = true;   // redraw blocks the loop; gesture baseline must re-prime afterwards
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

// Progress is shown as dots only. Showing the flick directions would leak the secret.
void showProgress(const char* title) {
  if (KEYPAD_MODE && state == ST_CHALLENGE) { flickReset = true; drawKeypad(); return; }
  char dots[2 * GESTURE_LEN + 1];
  for (uint8_t i = 0; i < GESTURE_LEN; i++) {
    dots[2 * i]     = (i < enteredCount) ? '*' : '-';
    dots[2 * i + 1] = ' ';
  }
  dots[2 * GESTURE_LEN] = '\0';
  showScreen(title, dots, "", TS_8b_Yellow);
}

void showIdle() {
  lastBleShown = ble_connection_state;
  showScreen("GestureKey",
             ble_connection_state ? "Pi: connected" : "Pi: waiting...",
             (!KEYPAD_MODE && millis() < ENROL_WINDOW_MS) ? "UL btn = enrol" : "Ready",
             ble_connection_state ? TS_8b_Green : TS_8b_Gray);
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
// using the orientation settings above. A flick = motion on h or v above FLICK_THRESHOLD.
// The axis with the larger value and its sign give RIGHT/LEFT/UP/DOWN. A refractory
// period stops the opposite "return swing" being counted as a second flick.
// Set to true after anything slow (screen redraw, buzz) so the baseline re-primes
// instead of treating the stale baseline as a sudden flick.
bool flickReset = true;

int8_t pollFlick() {
  static unsigned long lastSample = 0, lastFlick = 0, capStart = 0;
  static float lpX = 0, lpY = 0, pkH = 0, pkV = 0;
  static bool capturing = false;
  static uint8_t sustain = 0;

  if (millis() - lastSample < SAMPLE_MS) return -1;
  lastSample = millis();

  accel.read();
  float x = accel.X, y = accel.Y;
  if (flickReset) { lpX = x; lpY = y; capturing = false; lastFlick = millis(); flickReset = false; }
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
  if (ah >= 25 || av >= 25) {     // only show real movement, so the numbers are readable
    SerialMonitorInterface.print("h="); SerialMonitorInterface.print((int)h);
    SerialMonitorInterface.print(" v="); SerialMonitorInterface.println((int)v);
  }
#endif

  if (!capturing) {
    if (millis() - lastFlick < REFRACTORY_MS) return -1;
    if (ah < FLICK_THRESHOLD && av < FLICK_THRESHOLD) return -1;
    capturing = true; capStart = millis(); pkH = h; pkV = v; sustain = 1;   // flick started: watch the peak for a moment
    return -1;
  }

  // Keep the largest swing on each axis (with its sign) during the capture window
  if (ah > (pkH < 0 ? -pkH : pkH)) pkH = h;
  if (av > (pkV < 0 ? -pkV : pkV)) pkV = v;
  if (ah >= SUSTAIN_THRESHOLD || av >= SUSTAIN_THRESHOLD) sustain++;
  if (millis() - capStart < CAPTURE_MS) return -1;

  capturing = false;
  if (sustain < MIN_SUSTAIN_SAMPLES) {      // too brief: cable tug / table knock, not a deliberate flick
#if TUNE_MODE
    SerialMonitorInterface.print("REJECT brief spike, samples="); SerialMonitorInterface.println(sustain);
#endif
    return -1;                              // no refractory, so a real flick right after is still caught
  }
  lastFlick = millis();
  float aH = pkH < 0 ? -pkH : pkH;
  float aV = pkV < 0 ? -pkV : pkV;
#if TUNE_MODE
  SerialMonitorInterface.print("FLICK pkH="); SerialMonitorInterface.print((int)pkH);
  SerialMonitorInterface.print(" pkV=");      SerialMonitorInterface.print((int)pkV);
  SerialMonitorInterface.print(" samples=");  SerialMonitorInterface.println(sustain);
#endif
#if EASY_MODE
  return SYM_RIGHT;   // any flick counts, whatever the direction
#endif
  if (aH >= aV * DOMINANCE_RATIO) return (pkH > 0) ? SYM_RIGHT : SYM_LEFT;
  if (aV >= aH * DOMINANCE_RATIO) return (pkV > 0) ? SYM_UP : SYM_DOWN;
#if TUNE_MODE
  SerialMonitorInterface.println("REJECT diagonal (too close between h and v)");
#endif
  return -1;   // diagonal / ambiguous: ignore rather than guess
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
    state = ST_CHALLENGE;
    stateStart = millis();
    wakeScreen();
    buzz(80);
    shuffleLayout();
    showProgress("Unlock? Flick");
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
#if EASY_MODE
  return true;        // 3 flicks were counted, that is enough
#endif
  const uint8_t* ref = KEYPAD_MODE ? keypadSecret : gestureTemplate;
  uint8_t diff = 0;                        // accumulate differences, no early exit
  for (uint8_t i = 0; i < GESTURE_LEN; i++) diff |= (entered[i] ^ ref[i]);
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
    showScreen("DENIED", "Wrong gesture", "", TS_8b_Red);
    buzz(400);
  }
}

void onFlick(int8_t sym) {
  wakeScreen();

  // A long pause means the person restarted the gesture
#if !TEST_NO_TIMEOUT
  if (enteredCount > 0 && millis() - lastStepTime > STEP_TIMEOUT_MS) enteredCount = 0;
#endif
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
    if (!KEYPAD_MODE && !wasOff && state == ST_IDLE && (buttons & TSButtonUpperLeft) && millis() < ENROL_WINDOW_MS) {
      state = ST_ENROL;
      enteredCount = 0;
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

  int8_t sym = KEYPAD_MODE ? pollKeypad() : pollFlick();
  if (sym >= 0 && (state == ST_CHALLENGE || state == ST_ENROL)) onFlick(sym);

  switch (state) {
    case ST_CHALLENGE:
#if !TEST_NO_TIMEOUT
      if (millis() - stateStart > CHALLENGE_TIMEOUT_MS) {
        state = ST_RESULT;
        stateStart = millis();
        showScreen("TIMED OUT", "No gesture", "", TS_8b_Gray);
      }
#endif
      break;
    case ST_RESULT:
      if (millis() - stateStart > RESULT_SHOW_MS) { state = ST_IDLE; showIdle(); }
      break;
    case ST_ENROL:
      if (millis() - stateStart > 20000) { state = ST_IDLE; showIdle(); }   // give up quietly
      break;
    case ST_IDLE:
      if (lastBleShown != ble_connection_state) { wakeScreen(); showIdle(); }   // wake + redraw when the link changes
      if (displayOn && millis() - screenTimer > SCREEN_TIMEOUT_MS) { display.off(); displayOn = 0; }
      break;
  }
  checkButtons();
}
