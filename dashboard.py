#!/usr/bin/env python3
"""dashboard.py - tiny Flask page that shows the GestureKey access log (auto-refreshes).
Run:  pip install flask ; python3 dashboard.py   then open http://<pi-ip>:5000"""
import json, os
from flask import Flask
LOG_FILE = os.path.join(os.path.dirname(__file__), "access_log.jsonl")
app = Flask(__name__)

@app.route("/")
def index():
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            rows = [json.loads(l) for l in f if l.strip()][-50:][::-1]
    colour = {"unlock": "#2e7d32", "fail": "#c62828", "lockout": "#c62828"}
    body = "".join(
        f"<tr style='color:{colour.get(r['event'], '#333')}'><td>{r['t']}</td>"
        f"<td>{r['event']}</td><td>{r['detail']}</td></tr>" for r in rows)
    return ("<meta http-equiv='refresh' content='2'><title>GestureKey log</title>"
            "<h2>GestureKey access log</h2><table cellpadding=6 border=1>"
            "<tr><th>Time</th><th>Event</th><th>Detail</th></tr>" + body + "</table>")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
