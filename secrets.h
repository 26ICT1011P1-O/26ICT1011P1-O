// secrets.h - shared secret between the watch and the Raspberry Pi.
// DO NOT commit this file to GitHub (add it to .gitignore).
// Generate a fresh key with:  python3 -c "import os;print(os.urandom(16).hex())"
// and put the SAME hex string in pi/gk_key.txt.
#ifndef SECRETS_H
#define SECRETS_H
#include <stdint.h>
static const uint8_t GK_KEY[16] = { 0x2a, 0x44, 0xa3, 0x6e, 0x11, 0x7c, 0x63, 0xa7, 0x51, 0x6b, 0xc6, 0xa2, 0x37, 0x8c, 0xa6, 0xde };
#endif
