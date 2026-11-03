// gk_gesture.h - comparing a performed gesture with the stored one (pure logic, no hardware)
#ifndef GK_GESTURE_H
#define GK_GESTURE_H
#include <stdint.h>

// Same directions in the same order? (compares everything, no early exit). Returns 1 if equal.
static int gk_dirs_match(const uint8_t *tmpl, const uint8_t *got, uint8_t n) {
  uint8_t d = 0;
  for (uint8_t i = 0; i < n; i++) d |= (uint8_t)(tmpl[i] ^ got[i]);
  return d == 0;
}

// Rhythm: are the pauses between flicks close enough to the stored pauses?
// A gap passes if |got - tmpl| <= max(minTolMs, tmpl * tolPct / 100). Returns 1 if every gap passes.
static int gk_rhythm_match(const uint16_t *tmpl, const uint16_t *got, uint8_t nGaps,
                           uint16_t minTolMs, uint8_t tolPct) {
  uint8_t bad = 0;
  for (uint8_t i = 0; i < nGaps; i++) {
    uint32_t t = tmpl[i], g = got[i];
    uint32_t tol = (t * tolPct) / 100;
    if (tol < minTolMs) tol = minTolMs;
    uint32_t diff = (g > t) ? (g - t) : (t - g);
    if (diff > tol) bad = 1;
  }
  return bad == 0;
}

#endif