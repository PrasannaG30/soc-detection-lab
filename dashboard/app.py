#!/usr/bin/env python3
import os, sqlite3
from flask import Flask, render_template

app = Flask(__name__)
DB_PATH = os.path.expanduser("~/soc-project/soc.db")

@app.route("/")
def index():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    alerts = conn.cursor().execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    events = conn.cursor().execute("SELECT * FROM events ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return render_template("index.html", alerts=alerts, events=events)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
