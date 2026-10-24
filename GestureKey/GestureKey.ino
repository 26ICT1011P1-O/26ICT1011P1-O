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
#define TUNE_MODE false          // true = stream accelerometer high-pass values to Serial Monitor

// If the screen stays blank, try TinyScreenPlus here (the lab examples use Default).
TinyScreen display = TinyScreen(TinyScreenDefault);
BMA250 accel;

// ---- variables UART.ino expects to exist (same names as the SmartWatch example) ----
uint8_t ble_rx_buffer[21];
uint8_t ble_rx_buffer_len = 0;
uint8_t ble_can_sleep = false;
uint8_t ble_connection_state = false;

// ---- tuning ----
const float         FLICK_THRESHOLD     = 130.0;  // counts above gravity baseline (256 counts = 1 g at +/-2 g)
const unsigned long SAMPLE_MS           = 20;     // 50 Hz sampling
const unsigned long REFRACTORY_MS       = 350;    // ignore the "return swing" after a flick
const unsigned long STEP_TIMEOUT_MS     = 2500;   // max pause between flicks of one gesture
const unsigned long CHALLENGE_TIMEOUT_MS = 8000;  // Pi gives up after ~10 s
const unsigned long RESULT_SHOW_MS      = 2000;
const unsigned long SCREEN_TIMEOUT_MS   = 15000;
const unsigned long ENROL_WINDOW_MS     = 60000;  // gesture can only be re-recorded this long after power-up
const uint8_t       GESTURE_LEN         = 3;

// Flick symbols: direction of the first strong acceleration along the board's axes
enum { SYM_XP = 0, SYM_XN = 1, SYM_YP = 2, SYM_YN = 3 };

// Default gesture: X+, X+, Y-.  Re-record with UPPER-LEFT button within 60 s of power-up.
// (Kept in RAM only: the SAMD21 has no EEPROM, so it resets to this default on power cycle.)
uint8_t gestureTemplate[GESTURE_LEN] = { SYM_XP, SYM_XP, SYM_YN };

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
// Display helpers
// ---------------------------------------------------------------------------
void showScreen(const char* l1, const char* l2, const char* l3, uint8_t color) {
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
             (millis() < ENROL_WINDOW_MS) ? "UL btn = enrol" : "Ready",
             ble_connection_state ? TS_8b_Green : TS_8b_Gray);
}

void buzz(unsigned int ms) {
  digitalWrite(vibratePin, HIGH);
  delay(ms);
  digitalWrite(vibratePin, LOW);
}

// ---------------------------------------------------------------------------
// Gesture detection
// ---------------------------------------------------------------------------
// Returns a symbol (0..3) when a flick is detected, otherwise -1.
// Method: a slow low-pass filter tracks gravity (the "baseline"); subtracting it leaves
// only the motion. A flick = motion on X or Y above FLICK_THRESHOLD. The axis with the
// larger value and its sign give the symbol. A refractory period stops the opposite
// "return swing" being counted as a second flick.
int8_t pollFlick() {
  static unsigned long lastSample = 0, lastFlick = 0;
  static float lpX = 0, lpY = 0;
  static bool primed = false;

  if (millis() - lastSample < SAMPLE_MS) return -1;
  lastSample = millis();

  accel.read();
  float x = accel.X, y = accel.Y;
  if (!primed) { lpX = x; lpY = y; primed = true; }
  float hpX = x - lpX, hpY = y - lpY;
  lpX += 0.1 * (x - lpX);
  lpY += 0.1 * (y - lpY);

  float ax = hpX < 0 ? -hpX : hpX;
  float ay = hpY < 0 ? -hpY : hpY;

#if TUNE_MODE
  SerialMonitorInterface.print((int)hpX); SerialMonitorInterface.print(' ');
  SerialMonitorInterface.println((int)hpY);
#endif

  if (millis() - lastFlick < REFRACTORY_MS) return -1;
  float peak = (ax > ay) ? ax : ay;
  if (peak < FLICK_THRESHOLD) return -1;

  lastFlick = millis();
  if (ax >= ay) return (hpX > 0) ? SYM_XP : SYM_XN;
  return (hpY > 0) ? SYM_YP : SYM_YN;
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
    showScreen("DENIED", "Wrong gesture", "", TS_8b_Red);
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

  if (accel.begin(BMA250_range_2g, BMA250_update_time_16ms) != 0) {
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

  int8_t sym = pollFlick();
  if (sym >= 0 && (state == ST_CHALLENGE || state == ST_ENROL)) onFlick(sym);

  switch (state) {
    case ST_CHALLENGE:
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
      if (millis() - stateStart > 20000) { state = ST_IDLE; showIdle(); }   // give up quietly
      break;
    case ST_IDLE:
      if (lastBleShown != ble_connection_state) { wakeScreen(); showIdle(); }   // wake + redraw when the link changes
      if (displayOn && millis() - screenTimer > SCREEN_TIMEOUT_MS) { display.off(); displayOn = 0; }
      break;
  }
  checkButtons();
}


