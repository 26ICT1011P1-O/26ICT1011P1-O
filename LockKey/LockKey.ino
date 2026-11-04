//-------------------------------------------------------------------------------
//  LockKey - the LOCK stack of GestureKey (second TinyScreen+ with the Servo TinyShield)
//
//  This stack has no gesture sensor. It only moves a latch, and only when the laptop proves it knows
//  the shared key for a nonce THIS stack just chose, so a recorded or forged message can never open it:
//
//    laptop 'Q'                -> lock replies 'Z' + ln   (ln = fresh nonce, valid ONCE, for AUTH_WINDOW_MS)
//    laptop 'O' + tag_O(ln)    -> lock checks the tag. Good: opens, replies 'Y' + tag_Y(ln). Bad: replies 'X'.
//    ... HOLD_MS later the lock closes ITSELF and notifies 'K'. If Bluetooth drops, it still closes.
//
//  Hardware: TinyScreen+, ST BLE TinyShield, Servo TinyShield (I2C: A4/SDA, A5/SCL), servo on channel 1,
//  separate battery on the servo shield's 2-pin power connector (never the stack's own battery).
//
//  PIN WARNING: TinyCircuits' servo example calls servo.useResetPin(), which uses Pin 9. The ST BLE shield uses
//  Pin 9 as ITS reset line, so this sketch deliberately does NOT call useResetPin().
//
//  ATTRIBUTION (the brief requires this - keep it in the video too):
//    - BLE UART service (UART.ino, STBLE library): TinyCircuits ST BLE smartwatch example, Ben Rose / TinyCircuits.
//    - Servo control: TinyCircuits ATtiny841 library (ServoDriver.h) and its servo example.
//    - gk_crypto.h: SHA-256/HMAC implemented from FIPS 180-4 / RFC 2104.
//    - Everything else (protocol, state machine, authentication): our own work.
//
//  Files that must sit in this sketch folder: LockKey.ino, UART.ino, gk_crypto.h, gk_auth.h, secrets.h
//-------------------------------------------------------------------------------

#include <stdio.h>
#include <SPI.h>
#include <Wire.h>
#include <TinyScreen.h>
#include <STBLE.h>
#include <ServoDriver.h>           // TinyCircuits ATtiny841 library
#include "gk_crypto.h"
#include "gk_auth.h"
#include "secrets.h"

#define BLE_DEBUG true
#define SerialMonitorInterface SerialUSB

TinyScreen display = TinyScreen(TinyScreenPlus);
ServoDriver servo(NO_R_REMOVED);   // default I2C address (none of the address resistors removed)

// ---- variables UART.ino expects to exist ----
uint8_t ble_rx_buffer[21];
uint8_t ble_rx_buffer_len = 0;
uint8_t ble_can_sleep = false;
uint8_t ble_connection_state = false;

// ---- settings: calibrate the two servo positions on YOUR latch (microseconds of pulse; 1000-2000 is the usual range) ----
const uint8_t       SERVO_CHANNEL    = 1;
const uint16_t      SERVO_CLOSED_US  = 1000;
const uint16_t      SERVO_OPEN_US    = 2000;
const unsigned long HOLD_MS          = 5000;   // how long the latch stays open (keep equal to UNLOCK_HOLD_S in gk_lock.py)
const unsigned long AUTH_WINDOW_MS   = 6000;   // the laptop has this long to answer a nonce
const unsigned long REFRESH_MS       = 200;    // resend the position often: the shield's failsafe switches the servo off after 1 s of silence
const unsigned long SCREEN_TIMEOUT_MS = 15000;

enum LockState { LOCKED, OPEN };
LockState lockState = LOCKED;
uint16_t  currentUs = SERVO_CLOSED_US;
unsigned long openUntil = 0, lastRefresh = 0, screenTimer = 0, pendingSince = 0;
uint8_t   ln[GK_NONCE_LEN];            // the nonce we handed out
bool      havePending = false;
uint32_t  nonceCounter = 0;
uint8_t   displayOn = 0, lastBleShown = 255, lastShownLeft = 255;
bool      servoOk = true;

void setPosition(uint16_t us) {
  currentUs = us;
  if (servoOk) servo.setServo(SERVO_CHANNEL, us);
}

void notify(const uint8_t* data, uint8_t n) { lib_aci_send_data(0, (uint8_t*)data, n); }

// ---- screen ----
void showScreen(const char* l1, const char* l2, const char* l3, uint8_t color) {
  display.clearScreen();
  display.setFont(thinPixel7_10ptFontInfo);
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

void drawStatus() {
  lastBleShown = ble_connection_state;
  lastShownLeft = 255;
  if (lockState == OPEN) showScreen("GLock", "OPEN", "closing...", TS_8b_Green);
  else showScreen("GLock", "LOCKED", ble_connection_state ? "laptop: linked" : "laptop: waiting", TS_8b_Red);
}

// ---- protocol ----
void closeLock() {
  setPosition(SERVO_CLOSED_US);
  lockState = LOCKED;
  uint8_t k = 'K';
  notify(&k, 1);
  drawStatus();
}

void handleBleMessage() {
  if (!ble_rx_buffer_len) return;
  uint8_t type = ble_rx_buffer[0];
  uint8_t len  = ble_rx_buffer_len;

  SerialMonitorInterface.print("BLE rx type=");
  SerialMonitorInterface.print((char)((type >= 32 && type < 127) ? type : '?'));
  SerialMonitorInterface.print(" len=");
  SerialMonitorInterface.println(len);

  if (type == 'Q' && len == 1) {
    // Hand out a fresh one-time nonce. A new 'Q' replaces any earlier one.
    gk_make_nonce(GK_KEY, sizeof(GK_KEY), nonceCounter++, micros(), millis(), ln);
    havePending = true;
    pendingSince = millis();
    uint8_t out[1 + GK_NONCE_LEN];
    out[0] = 'Z';
    memcpy(out + 1, ln, GK_NONCE_LEN);
    notify(out, sizeof(out));
  } else if (type == 'O' && len == 1 + GK_TAG_LEN) {
    bool ok = false;
    if (havePending && millis() - pendingSince <= AUTH_WINDOW_MS) {
      uint8_t expect[GK_TAG_LEN];
      gk_tag_O(GK_KEY, sizeof(GK_KEY), ln, expect);
      ok = gk_ct_equal(expect, ble_rx_buffer + 1, GK_TAG_LEN) != 0;
    }
    havePending = false;                         // one nonce, one try: good or bad it is now spent
    if (ok) {
      setPosition(SERVO_OPEN_US);
      lockState = OPEN;
      openUntil = millis() + HOLD_MS;
      uint8_t out[1 + GK_TAG_LEN];
      out[0] = 'Y';
      gk_tag_Y(GK_KEY, sizeof(GK_KEY), ln, out + 1);   // signed confirmation: the laptop can tell a real lock from an impostor
      notify(out, sizeof(out));
      wakeScreen();
      drawStatus();
    } else {
      uint8_t x = 'X';
      notify(&x, 1);
      SerialMonitorInterface.println("open order refused");
    }
  }
  // anything else is ignored: this stack takes orders from nobody but the laptop's authenticated 'O'
  ble_rx_buffer_len = 0;
}

void setup() {
  SerialMonitorInterface.begin(115200);
  Wire.begin();
  display.begin();
  display.setFlip(true);
  display.setBrightness(5);
  displayOn = 1;
  screenTimer = millis();

  // Note: no servo.useResetPin() here, see the PIN WARNING above.
  if (servo.begin(20000)) {                       // non-zero = the servo shield did not answer on I2C
    servoOk = false;
    showScreen("ERROR", "Servo shield", "not found", TS_8b_Red);
  } else {
    servo.setFailsafe(1000);                      // PWM off if no command for 1 s (we resend every REFRESH_MS)
    setPosition(SERVO_CLOSED_US);                 // always start locked
    BLEsetup();                                   // from UART.ino
    drawStatus();
    return;
  }
  BLEsetup();                                     // still advertise so the problem can be diagnosed from the laptop
}

void loop() {
  aci_loop();
  if (!servoOk) return;          // no servo shield: show the error and never act on any message
  handleBleMessage();

  if (lockState == OPEN && (long)(millis() - openUntil) >= 0) closeLock();    // closes itself, even if Bluetooth dropped

  if (millis() - lastRefresh >= REFRESH_MS) {     // keep the servo holding its position
    lastRefresh = millis();
    setPosition(currentUs);
  }

  if (havePending && millis() - pendingSince > AUTH_WINDOW_MS) havePending = false;   // unused nonce expires

  if (lockState == OPEN) {                        // countdown on the screen, once a second
    unsigned long left = (openUntil > millis()) ? (openUntil - millis() + 999UL) / 1000UL : 0;
    if (left != lastShownLeft) {
      lastShownLeft = (uint8_t)left;
      char buf[24];
      snprintf(buf, sizeof(buf), "closing in %us ", (unsigned)left);
      display.setFont(thinPixel7_10ptFontInfo);
      display.fontColor(TS_8b_Gray, TS_8b_Black);
      display.setCursor(2, 42);
      display.print(buf);
    }
  } else if (lastBleShown != ble_connection_state) {
    wakeScreen();
    drawStatus();
  }

  if (displayOn && lockState == LOCKED && millis() - screenTimer > SCREEN_TIMEOUT_MS) { display.off(); displayOn = 0; }
  if (display.getButtons()) { wakeScreen(); if (lockState == LOCKED) drawStatus(); }
}
