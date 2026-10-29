// gk_crypto.h  -  minimal SHA-256 + HMAC-SHA256 for the GestureKey watch firmware
// Implemented from the public FIPS 180-4 (SHA-256) and RFC 2104 (HMAC) specifications.
// Self-contained so the sketch needs no extra Arduino library. Verified against
// Python's hashlib/hmac on a PC (see tests in the project notes).
#ifndef GK_CRYPTO_H
#define GK_CRYPTO_H

#include <stdint.h>
#include <string.h>

typedef struct {
  uint32_t h[8];
  uint8_t  buf[64];
  uint32_t bufLen;
  uint64_t totalLen;   // bytes hashed so far
} gk_sha256_ctx;

static const uint32_t GK_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define GK_ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void gk_sha256_block(gk_sha256_ctx *c, const uint8_t *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)                       // big-endian load
    w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
           ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
  for (int i = 16; i < 64; i++) {                    // message schedule
    uint32_t s0 = GK_ROR(w[i-15], 7) ^ GK_ROR(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = GK_ROR(w[i-2], 17) ^ GK_ROR(w[i-2], 19)  ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3];
  uint32_t e=c->h[4], f=c->h[5], g=c->h[6],  h=c->h[7];
  for (int i = 0; i < 64; i++) {                     // 64 rounds
    uint32_t S1 = GK_ROR(e,6) ^ GK_ROR(e,11) ^ GK_ROR(e,25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + GK_K[i] + w[i];
    uint32_t S0 = GK_ROR(a,2) ^ GK_ROR(a,13) ^ GK_ROR(a,22);
    uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
    uint32_t t2 = S0 + mj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
  c->h[4]+=e; c->h[5]+=f; c->h[6]+=g;  c->h[7]+=h;
}

static void gk_sha256_init(gk_sha256_ctx *c) {
  static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  memcpy(c->h, iv, sizeof(iv));
  c->bufLen = 0;
  c->totalLen = 0;
}

static void gk_sha256_update(gk_sha256_ctx *c, const uint8_t *data, uint32_t len) {
  c->totalLen += len;
  while (len) {
    uint32_t n = 64 - c->bufLen;
    if (n > len) n = len;
    memcpy(c->buf + c->bufLen, data, n);
    c->bufLen += n; data += n; len -= n;
    if (c->bufLen == 64) { gk_sha256_block(c, c->buf); c->bufLen = 0; }
  }
}

static void gk_sha256_final(gk_sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits = c->totalLen * 8;
  uint8_t pad = 0x80;
  gk_sha256_update(c, &pad, 1);
  pad = 0x00;
  while (c->bufLen != 56) gk_sha256_update(c, &pad, 1);
  uint8_t lenBytes[8];
  for (int i = 0; i < 8; i++) lenBytes[i] = (uint8_t)(bits >> (56 - 8*i));
  gk_sha256_update(c, lenBytes, 8);
  for (int i = 0; i < 8; i++) {
    out[4*i]   = (uint8_t)(c->h[i] >> 24);
    out[4*i+1] = (uint8_t)(c->h[i] >> 16);
    out[4*i+2] = (uint8_t)(c->h[i] >> 8);
    out[4*i+3] = (uint8_t)(c->h[i]);
  }
}

// HMAC-SHA256(key, msg) -> out[32]
static void gk_hmac_sha256(const uint8_t *key, uint32_t keyLen,
                           const uint8_t *msg, uint32_t msgLen, uint8_t out[32]) {
  uint8_t k[64] = {0};
  if (keyLen > 64) {                                 // long keys are hashed first
    gk_sha256_ctx t; gk_sha256_init(&t);
    gk_sha256_update(&t, key, keyLen); gk_sha256_final(&t, k);
  } else {
    memcpy(k, key, keyLen);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  uint8_t inner[32];
  gk_sha256_ctx c;
  gk_sha256_init(&c); gk_sha256_update(&c, ipad, 64);
  gk_sha256_update(&c, msg, msgLen); gk_sha256_final(&c, inner);
  gk_sha256_init(&c); gk_sha256_update(&c, opad, 64);
  gk_sha256_update(&c, inner, 32); gk_sha256_final(&c, out);
}

#endif
