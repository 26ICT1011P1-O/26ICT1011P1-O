"""
gk_proto.py - the GestureKey wire protocol, laptop side (pure functions, no I/O).

Python twin of firmware/gk_auth.h. Every authenticated message carries a 16-byte tag:
    tag = HMAC-SHA256(key, label || a || b)[:16]
The label separates purposes so a tag made for one purpose is useless for another, and the nonces
make every tag single-use.

  Laptop <-> WATCH                                   Laptop <-> LOCK
  --------------------------------------------      ---------------------------------------
  laptop  'Q'                     ask for a nonce    laptop  'Q'
  watch   'Z' + wn(16)            watch nonce        lock    'Z' + ln(16)     lock nonce
  laptop  'C' + pn(16)            laptop nonce       laptop  'O' + tag_O(ln)  open, authenticated
  laptop  'M' + tag_P(wn, pn)     "I know the key"   lock    'Y' + tag_Y(ln)  opened (or 'X' = refused)
  watch   'R' + tag_A(wn, pn)     gesture approved   lock    'K'              closed again (it closes itself)
          or 'N'                  wrong gesture
  laptop  'W' + seconds           waiting for phone approval
  laptop  'D' + code              decision: N denied, T timed out, X phone unreachable, F lock error
  laptop  'L' / 'T' h m s / 'S' U|K    locked-out notice / clock / door status (display only)
"""
import hmac, hashlib, os

TAG_LEN = 16
NONCE_LEN = 16


def tag(key: bytes, label: bytes, a: bytes, b: bytes = b"") -> bytes:
    return hmac.new(key, label + a + b, hashlib.sha256).digest()[:TAG_LEN]


def tag_P(key, wn, pn): return tag(key, b"P", wn, pn)     # laptop proves itself to the watch
def tag_A(key, wn, pn): return tag(key, b"A", wn, pn)     # watch approves the gesture
def tag_O(key, ln):     return tag(key, b"O", ln)         # laptop orders the lock to open
def tag_Y(key, ln):     return tag(key, b"Y", ln)         # lock confirms it opened


def new_nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def make_nonce_like_firmware(key: bytes, counter: int, t1: int, t2: int) -> bytes:
    """What the SAMD21 firmware does (no hardware RNG): HMAC(key, 'N' || counter || t1 || t2)[:16]."""
    msg = b"N" + counter.to_bytes(4, "big") + t1.to_bytes(4, "big") + t2.to_bytes(4, "big")
    return hmac.new(key, msg, hashlib.sha256).digest()[:NONCE_LEN]


def equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
