#!/usr/bin/env python3
"""virtual_door.py - the laptop acts as the door lock.

A window that shows the door state: red LOCKED, green UNLOCKED, and an orange flash with a
beep when an attempt is refused. It only READS two files that gk_lock.py writes, so run it in a
second terminal next to gk_lock.py:

    python virtual_door.py

Keys: F11 = full screen, Esc = quit.  Needs only Python's built-in tkinter (no pip install).
"""
import json, os, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.environ.get("GK_DOOR_STATE", os.path.join(HERE, "door_state.json"))   # written by set_lock()
LOG_FILE = os.environ.get("GK_LOG_FILE", os.path.join(HERE, "access_log.jsonl"))      # written by log()
POLL_MS = 250          # how often the window looks at the files
FLASH_S = 3.0          # how long a refused attempt stays on screen

LOCKED_BG, UNLOCKED_BG, DENIED_BG = "#b71c1c", "#1b5e20", "#e65100"

# log event -> text shown when it happens
BAD_EVENTS = {
    "fail": "ACCESS DENIED",
    "lockout": "LOCKED OUT",
    "blocked": "LOCKDOWN",
    "outside_hours": "OUTSIDE HOURS",
    "timeout": "NO RESPONSE",
    "denied": "NOT APPROVED",
    "approval_timeout": "NOT APPROVED",
    "approval_unavailable": "NOT APPROVED",
}


def read_unlocked() -> bool:
    """True when gk_lock.py says the door is open. A missing or half-written file means locked."""
    try:
        with open(STATE_FILE) as f:
            return bool(json.load(f).get("unlocked"))
    except (OSError, ValueError):
        return False


def last_log_record():
    """The newest line of the access log as a dict, or None. Reads only the end of the file."""
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 4096))
            lines = f.read().decode("utf-8", "ignore").splitlines()
    except OSError:
        return None
    for line in reversed(lines):            # the first line read may be cut in half, so skip bad ones
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def beep(kind: str, root=None):
    """Short sounds on a background thread so the window never freezes. Windows beeps; others use the bell."""
    tones = {"unlock": [(880, 120), (1320, 200)], "lock": [(440, 150)], "bad": [(220, 250), (220, 250)]}[kind]

    def play():
        try:
            import winsound
            for freq, ms in tones:
                winsound.Beep(freq, ms)
        except Exception:
            if root is not None:
                try:
                    root.bell()
                except Exception:
                    pass

    threading.Thread(target=play, daemon=True).start()


def main():
    import tkinter as tk

    root = tk.Tk()
    root.title("GestureKey - virtual door")
    root.geometry("760x440")
    root.configure(bg=LOCKED_BG)

    icon = tk.Label(root, text="\U0001F512", font=("Segoe UI Emoji", 88), bg=LOCKED_BG, fg="white")
    big = tk.Label(root, text="LOCKED", font=("Helvetica", 60, "bold"), bg=LOCKED_BG, fg="white")
    sub = tk.Label(root, text="waiting for the watch...", font=("Helvetica", 16), bg=LOCKED_BG, fg="white")
    icon.pack(expand=True, pady=(20, 0))
    big.pack()
    sub.pack(expand=True, pady=(0, 20))

    state = {"unlocked": None, "seen": None, "flash_until": 0.0, "flash_text": "", "sub": "waiting for the watch...", "full": False}

    def paint(bg, symbol, text):
        for w in (root, icon, big, sub):
            w.configure(bg=bg)
        icon.configure(text=symbol)
        big.configure(text=text)
        sub.configure(text=state["sub"])

    def poll():
        now = time.time()
        unlocked = read_unlocked()
        rec = last_log_record()
        key = json.dumps(rec, sort_keys=True) if rec else None

        if key != state["seen"]:
            first_look = state["seen"] is None       # the log already has old lines when the window opens
            state["seen"] = key
            if rec:
                state["sub"] = f"{rec.get('t', '')}   {rec.get('event', '')}   {rec.get('detail', '')}".strip()
                if not first_look and rec.get("event") in BAD_EVENTS:
                    state["flash_until"] = now + FLASH_S
                    state["flash_text"] = BAD_EVENTS[rec["event"]]
                    beep("bad", root)

        if unlocked != state["unlocked"]:
            if state["unlocked"] is not None:
                beep("unlock" if unlocked else "lock", root)
            state["unlocked"] = unlocked

        if now < state["flash_until"]:
            paint(DENIED_BG, "\u26D4", state["flash_text"])
        elif unlocked:
            paint(UNLOCKED_BG, "\U0001F513", "UNLOCKED")
        else:
            paint(LOCKED_BG, "\U0001F512", "LOCKED")
        root.after(POLL_MS, poll)

    def toggle_full(_event=None):
        state["full"] = not state["full"]
        root.attributes("-fullscreen", state["full"])

    root.bind("<F11>", toggle_full)
    root.bind("<Escape>", lambda _e: root.destroy())
    poll()
    root.mainloop()


if __name__ == "__main__":
    main()