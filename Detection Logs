import os, json, sqlite3, secrets, threading, urllib.request, urllib.error
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string

DB = os.environ.get("CHEAT_DB", "owner_dashboard.db")
OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id TEXT,
      windows_user TEXT, computer TEXT, event_type TEXT,
      detections_json TEXT, app_version TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS devices(
      device_id TEXT PRIMARY KEY, device_token TEXT UNIQUE NOT NULL,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, app_version TEXT)""")
    c.commit()
    c.close()

def legacy_authorized():
    return bool(INGEST_TOKEN) and secrets.compare_digest(request.headers.get("X-Ingest-Token", ""), INGEST_TOKEN)

def device_authorized():
    token = request.headers.get("X-Device-Token", "")
    if not token:
        return None
    c = db()
    row = c.execute("SELECT * FROM devices WHERE device_token=?", (token,)).fetchone()
    c.close()
    return row

def discord_notify(event):
    if not DISCORD_WEBHOOK_URL:
        return
    detections = event.get("detections", []) or []
    typ = event.get("event_type", "event")
    title = "🟢 Detector launched" if typ == "launch" else ("🚨 Cheat detection report" if detections else "✅ Scan completed")
    lines = []
    for d in detections[:20]:
        lines.append(f"• **{d.get('family', 'Unknown')}** — `{d.get('score', '?')}/100`\n`{d.get('path', '')}`")
    if len(detections) > 20:
        lines.append(f"...and {len(detections)-20} more.")
    fields = [
        {"name": "👤 User", "value": f"`{event.get('windows_user', '')}`", "inline": True},
        {"name": "💻 Computer", "value": f"`{event.get('computer', '')}`", "inline": True},
        {"name": "📌 Event", "value": f"`{typ}`", "inline": True},
    ]
    if typ == "scan":
        fields.append({"name": "🚨 Detections", "value": str(len(detections)), "inline": True})
        if lines:
            fields.append({"name": "📋 Details", "value": "\n\n".join(lines)[:1024], "inline": False})
    payload = {
        "username": "Dukes Cheat Detector",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": title,
            "color": 0xED4245 if detections else 0x57F287,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Dukes-Cheat-Detector-Server"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass

def save_event(d, typ):
    device_id = d.get("device_id", "")
    event = {
        "device_id": device_id,
        "windows_user": d.get("windows_user", ""),
        "computer": d.get("computer", ""),
        "event_type": typ,
        "detections": d.get("detections", []) or [],
        "app_version": d.get("app_version", "")
    }
    now = datetime.now(timezone.utc).isoformat()
    c = db()
    c.execute(
        "INSERT INTO events(ts,device_id,windows_user,computer,event_type,detections_json,app_version) VALUES(?,?,?,?,?,?,?)",
        (now, device_id, event["windows_user"], event["computer"], typ, json.dumps(event["detections"]), event["app_version"])
    )
    if device_id:
        c.execute("UPDATE devices SET last_seen=?, app_version=? WHERE device_id=?", (now, event["app_version"], device_id))
    c.commit()
    c.close()
    threading.Thread(target=discord_notify, args=(event,), daemon=True).start()

def authorized_request():
    return legacy_authorized() or device_authorized() is not None

@app.get("/api/v1/health")
def health():
    return jsonify(ok=True, service="dukes-cheat-detector-server")

@app.post("/api/v1/register")
def register():
    data = request.get_json(silent=True) or {}
    requested = str(data.get("device_id", "")).strip()
    device_id = requested or secrets.token_hex(16)
    c = db()
    row = c.execute("SELECT device_token FROM devices WHERE device_id=?", (device_id,)).fetchone()
    now = datetime.now(timezone.utc).isoformat()
    if row:
        token = row["device_token"]
        c.execute("UPDATE devices SET last_seen=?, app_version=? WHERE device_id=?", (now, str(data.get("app_version", "")), device_id))
    else:
        token = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO devices(device_id,device_token,first_seen,last_seen,app_version) VALUES(?,?,?,?,?)",
            (device_id, token, now, now, str(data.get("app_version", "")))
        )
    c.commit()
    c.close()
    return jsonify(ok=True, device_id=device_id, device_token=token)

def event_endpoint(typ):
    if not authorized_request():
        return jsonify(error="unauthorized"), 401
    save_event(request.get_json(silent=True) or {}, typ)
    return jsonify(ok=True)

@app.post("/api/v1/events/launch")
def launch():
    return event_endpoint("launch")

@app.post("/api/v1/events/scan")
def scan():
    return event_endpoint("scan")

def owner(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("owner"):
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and secrets.compare_digest(request.form.get("password", ""), OWNER_PASSWORD):
        session["owner"] = True
        return redirect("/")
    return '<h2>Owner Login</h2><form method="post"><input name="password" type="password"><button>Login</button></form>'

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.get("/")
@owner
def home():
    c = db()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1000").fetchall()
    c.close()
    return render_template_string("""
<html>
<head><meta http-equiv='refresh' content='5'></head>
<body style='font-family:Arial;background:#111;color:#eee;padding:25px'>
<h1>👑 Dukes Cheat Detector Owner Dashboard</h1>
<p><a href='/logout'>Logout</a> • Auto-refresh: 5 seconds</p>
<table border='1' cellpadding='8' cellspacing='0'>
<tr><th>Time</th><th>User</th><th>PC</th><th>Event</th><th>Detections</th></tr>
{% for r in rows %}
<tr>
<td>{{r['ts']}}</td>
<td>{{r['windows_user']}}</td>
<td>{{r['computer']}}</td>
<td>{{r['event_type']}}</td>
<td><pre>{{r['detections_json']}}</pre></td>
</tr>
{% endfor %}
</table>
</body>
</html>
""", rows=rows)

if __name__ == "__main__":
    init_db()
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
