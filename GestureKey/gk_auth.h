// gk_auth.h - message authentication for GestureKey (header-only, needs gk_crypto.h)
//
// Every authenticated message carries a 16-byte tag = HMAC-SHA256(key, label || a || b)[:16].
// The one-letter label separates the purposes, so a tag made for one purpose can never be
// replayed as another. The nonces make every tag single-use:
//
//   'P'  laptop proves itself to the WATCH : tag over  wn || pn   (wn = watch nonce, pn = laptop nonce)
//   'A'  watch approves the gesture        : tag over  wn || pn
//   'O'  laptop orders the LOCK to open    : tag over  ln        (ln = lock nonce)
//   'Y'  lock confirms it opened           : tag over  ln
//
// Python twin: pi/gk_proto.py (the unit tests check both give identical bytes).
#ifndef GK_AUTH_H
#define GK_AUTH_H

#include "gk_crypto.h"

#define GK_TAG_LEN   16
#define GK_NONCE_LEN 16

static void gk_tag(const uint8_t *key, uint32_t keyLen, uint8_t label,
                   const uint8_t *a, uint8_t aLen, const uint8_t *b, uint8_t bLen,
                   uint8_t out[GK_TAG_LEN]) {
  uint8_t msg[1 + 2 * GK_NONCE_LEN];
  uint8_t n = 0;
  msg[n++] = label;
  memcpy(msg + n, a, aLen); n += aLen;
  if (bLen) { memcpy(msg + n, b, bLen); n += bLen; }
  uint8_t full[32];
  gk_hmac_sha256(key, keyLen, msg, n, full);
  memcpy(out, full, GK_TAG_LEN);
}

// Compare without stopping at the first difference. Returns 1 if equal.
static int gk_ct_equal(const uint8_t *a, const uint8_t *b, uint8_t n) {
  uint8_t d = 0;
  for (uint8_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

static void gk_tag_P(const uint8_t *k, uint32_t kl, const uint8_t *wn, const uint8_t *pn, uint8_t out[GK_TAG_LEN]) {
  gk_tag(k, kl, 'P', wn, GK_NONCE_LEN, pn, GK_NONCE_LEN, out);
}
static void gk_tag_A(const uint8_t *k, uint32_t kl, const uint8_t *wn, const uint8_t *pn, uint8_t out[GK_TAG_LEN]) {
  gk_tag(k, kl, 'A', wn, GK_NONCE_LEN, pn, GK_NONCE_LEN, out);
}
static void gk_tag_O(const uint8_t *k, uint32_t kl, const uint8_t *ln, uint8_t out[GK_TAG_LEN]) {
  gk_tag(k, kl, 'O', ln, GK_NONCE_LEN, 0, 0, out);
}
static void gk_tag_Y(const uint8_t *k, uint32_t kl, const uint8_t *ln, uint8_t out[GK_TAG_LEN]) {
  gk_tag(k, kl, 'Y', ln, GK_NONCE_LEN, 0, 0, out);
}

// The SAMD21 has no hardware random number generator, so a nonce is
//   HMAC-SHA256(secret key, 'N' || counter || two timer readings)[:16].
// Without the key nobody can predict it (even knowing the timer values); the counter and the
// timers make sure it is never the same twice.
static void gk_make_nonce(const uint8_t *key, uint32_t keyLen, uint32_t counter,
                          uint32_t t1, uint32_t t2, uint8_t out[GK_NONCE_LEN]) {
  uint8_t msg[13];
  msg[0] = 'N';
  for (int i = 0; i < 4; i++) {
    msg[1 + i] = (uint8_t)(counter >> (24 - 8 * i));
    msg[5 + i] = (uint8_t)(t1 >> (24 - 8 * i));
    msg[9 + i] = (uint8_t)(t2 >> (24 - 8 * i));
  }
  uint8_t full[32];
  gk_hmac_sha256(key, keyLen, msg, sizeof(msg), full);
  memcpy(out, full, GK_NONCE_LEN);
}

#endif