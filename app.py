"""
SecureDocs — multi-document Flask app with admin-approved, time-limited, PIN-gated
access to encrypted PDFs.

Required env vars:
    FLASK_SECRET_KEY    random string for session signing
    ADMIN_PASSWORD      admin panel password
    ADMIN_EMAIL         receives new-request alerts
    SMTP_USER           SMTP username
    SMTP_PASS           SMTP password

Optional env vars:
    DOCUMENT_NAME       fallback display name (default: Protected Document)
    SMTP_HOST           (default: smtp.gmail.com)
    SMTP_PORT           (default: 587)
    SMTP_USE_TLS        set 0 for local debug SMTP (default: 1)
    WEBHOOK_URL         Slack / Discord / generic webhook for event alerts
    ADMIN_TOTP_SECRET   base32 TOTP secret; if set, 2FA is required for admin login
    GEO_LOOKUP          set 1 to enable ip-api.com geo lookups
    CLEANUP_INTERVAL    seconds between cleanup runs (default: 3600)
    FORCE_HTTPS         set 1 to redirect http -> https
    SESSION_BIND_IP     set 1 to bind sessions to client IP
"""

import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from io import BytesIO

import pypdf
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask, Response, flash, g, jsonify, redirect,
    render_template, request, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from fpdf import FPDF
from reportlab.lib.colors import Color
from reportlab.pdfgen import canvas as rl_canvas

# ── Startup validation ─────────────────────────────────────────────────────────

_REQUIRED_ENV = ["FLASK_SECRET_KEY", "ADMIN_PASSWORD", "ADMIN_EMAIL", "SMTP_USER", "SMTP_PASS"]
_missing = [v for v in _REQUIRED_ENV if not os.environ.get(v)]
if _missing:
    raise RuntimeError(
        f"Missing required environment variables: {', '.join(_missing)}. "
        "Set them before starting the app."
    )

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
csrf = CSRFProtect(app)

# ── Constants ──────────────────────────────────────────────────────────────────

# Use /data (Render persistent disk) if available, otherwise local
_DATA_DIR = "/data" if os.path.isdir("/data") else os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(_DATA_DIR, "requests.db")
PIN_EXPIRY_MINUTES = 30
ACCESS_WINDOW_MINUTES = 60

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
DOCUMENT_NAME = os.environ.get("DOCUMENT_NAME", "Protected Document")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") != "0"
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "0") == "1"

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
ADMIN_TOTP_SECRET = os.environ.get("ADMIN_TOTP_SECRET", "")
GEO_LOOKUP = os.environ.get("GEO_LOOKUP", "0") == "1"
CLEANUP_INTERVAL = int(os.environ.get("CLEANUP_INTERVAL", "3600"))
FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "0") == "1"
SESSION_BIND_IP = os.environ.get("SESSION_BIND_IP", "0") == "1"

_default_emails = (
    "edoffice@riskarenabrokerage.com,eowusu@riskarenabrokerage.com,"
    "fasalu@riskarenabrokerage.com,finance@riskarenabrokerage.com,"
    "gafote@riskarenabrokerage.com,habubakar@riskarenabrokerage.com,"
    "hardwareportability@riskarenabrokerage.com,hello@riskarenabrokerage.com,"
    "info@riskarenabrokerage.com,jimmy@riskarenabrokerage.com,"
    "jnartey@riskarenabrokerage.com,jphillips@riskarenabrokerage.com,"
    "lsackeyfio@riskarenabrokerage.com,magyemang@riskarenabrokerage.com,"
    "marketing@riskarenabrokerage.com,onedrive@riskarenabrokerage.com,"
    "onedriveadmin@riskarenabrokerage.com,onedrivebdm@riskarenabrokerage.com,"
    "quarantine@riskarenabrokerage.com,report@riskarenabrokerage.com,"
    "saboagye@riskarenabrokerage.com,sagor@riskarenabrokerage.com,"
    "test@riskarenabrokerage.com,wuoley@riskarenabrokerage.com"
)
_raw = os.environ.get("SUGGESTED_EMAILS", _default_emails)
SUGGESTED_EMAILS: list[str] = sorted(
    e.strip().lower() for e in _raw.split(",") if e.strip() and "@" in e
)

UPLOADS_DIR = os.path.join(_DATA_DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

ACCESS_DURATION_OPTIONS = [
    (15,   "15 minutes"),
    (30,   "30 minutes"),
    (60,   "1 hour"),
    (120,  "2 hours"),
    (240,  "4 hours"),
    (480,  "8 hours"),
    (1440, "24 hours"),
]

# ── Signed-token helpers ───────────────────────────────────────────────────────

_SIGNING_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(os.environ.get("FLASK_SECRET_KEY", "").encode()).digest()
)
_SIGNER = Fernet(_SIGNING_KEY)


def generate_signed_token(email: str, doc_id: int, req_id: int) -> str:
    payload = json.dumps({"email": email, "doc_id": doc_id, "req_id": req_id,
                          "type": "one_click"}).encode()
    return _SIGNER.encrypt(payload).decode("utf-8")


def verify_signed_token(token_str: str) -> dict | None:
    try:
        data = _SIGNER.decrypt(
            token_str.encode("utf-8"),
            ttl=PIN_EXPIRY_MINUTES * 60,
        )
        return json.loads(data)
    except Exception:
        return None


# ── Database ───────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc: Exception | None) -> None:
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db() -> None:
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS documents (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                name                 TEXT NOT NULL,
                description          TEXT,
                enc_filename         TEXT NOT NULL,
                fernet_key           TEXT NOT NULL,
                created_at           TEXT NOT NULL,
                expires_at           TEXT,
                max_viewers          INTEGER,
                approved_domains     TEXT,
                require_email_verify INTEGER DEFAULT 0,
                status               TEXT DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS requests (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id             INTEGER NOT NULL,
                email                   TEXT NOT NULL,
                email_verified          INTEGER DEFAULT 0,
                verify_token            TEXT,
                pin                     TEXT,
                signed_token            TEXT,
                deny_reason             TEXT,
                status                  TEXT NOT NULL DEFAULT 'pending',
                created_at              TEXT NOT NULL,
                approved_at             TEXT,
                unlocked_at             TEXT,
                last_viewed_at          TEXT,
                session_token           TEXT,
                access_duration_minutes INTEGER DEFAULT 60
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event       TEXT NOT NULL,
                document_id INTEGER,
                email       TEXT,
                ip_address  TEXT,
                country     TEXT,
                city        TEXT,
                user_agent  TEXT,
                request_id  INTEGER,
                extra       TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event       TEXT NOT NULL,
                ip_address  TEXT,
                user_agent  TEXT,
                created_at  TEXT NOT NULL
            );
        """)
        # Migrations: add new columns to existing tables
        _migrations = [
            ("requests", "document_id INTEGER NOT NULL DEFAULT 0"),
            ("requests", "email_verified INTEGER DEFAULT 0"),
            ("requests", "verify_token TEXT"),
            ("requests", "signed_token TEXT"),
            ("requests", "deny_reason TEXT"),
            ("requests", "last_viewed_at TEXT"),
            ("audit_log", "document_id INTEGER"),
            ("audit_log", "country TEXT"),
            ("audit_log", "city TEXT"),
            ("audit_log", "extra TEXT"),
        ]
        for table, col_def in _migrations:
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass
        db.commit()


# ── PIN helpers ────────────────────────────────────────────────────────────────

def hash_pin(pin: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 260_000)
    return f"{salt}:{digest.hex()}"


def verify_pin(pin: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split(":", 1)
        expected = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(expected, bytes.fromhex(digest_hex))
    except Exception:
        return False


# ── CAPTCHA helpers ────────────────────────────────────────────────────────────

def generate_captcha() -> tuple[str, str]:
    if "captcha_salt" not in session:
        session["captcha_salt"] = secrets.token_hex(16)
    salt = session["captcha_salt"]
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    answer = str(a + b)
    answer_hash = hashlib.sha256(f"{answer}{salt}".encode()).hexdigest()
    return f"{a} + {b} = ?", answer_hash


def verify_captcha(submitted: str, stored_hash: str) -> bool:
    try:
        salt = session.get("captcha_salt", "")
        if not salt:
            return False
        expected = hashlib.sha256(f"{submitted.strip()}{salt}".encode()).hexdigest()
        return secrets.compare_digest(expected, stored_hash)
    except Exception:
        return False


# ── Geo lookup ─────────────────────────────────────────────────────────────────

_geo_cache: dict[str, tuple[str, str]] = {}
_geo_lock = threading.Lock()


def _geo_lookup(ip: str) -> tuple[str, str]:
    if not GEO_LOOKUP or not ip or ip in ("127.0.0.1", "::1"):
        return ("", "")
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=country,city",
            headers={"User-Agent": "SecureDocs/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        result = (data.get("country", ""), data.get("city", ""))
    except Exception:
        result = ("", "")
    with _geo_lock:
        _geo_cache[ip] = result
    return result


# ── Email ──────────────────────────────────────────────────────────────────────

def send_email(to: str, subject: str, text: str, html: str | None = None,
               cc: str | None = None) -> None:
    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))
    else:
        msg = MIMEText(text)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to
    recipients = [to]
    if cc:
        msg["Cc"] = cc
        recipients.append(cc)
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_USER, recipients, msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            if SMTP_USE_TLS:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_USER, recipients, msg.as_string())


def _render_email(template: str, **ctx) -> str:
    with app.app_context():
        return render_template(template, doc_name=DOCUMENT_NAME, **ctx)


# ── Webhook ────────────────────────────────────────────────────────────────────

def notify_webhook(event: str, email: str | None = None, doc_name: str | None = None,
                   extra: dict | None = None) -> None:
    if not WEBHOOK_URL:
        return
    name = doc_name or DOCUMENT_NAME
    payload = {
        "event": event,
        "document": name,
        "email": email or "",
        "timestamp": utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        **(extra or {}),
    }
    text = f"*[{event}]* {name}\n{email or ''} — {payload['timestamp']}"
    body = json.dumps({"text": text, "attachments": [{"fields": [
        {"title": k, "value": str(v), "short": True} for k, v in payload.items()
    ]}]}).encode()
    try:
        req = urllib.request.Request(
            WEBHOOK_URL, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        app.logger.warning("Webhook delivery failed: %s", exc)


# ── Auth decorators ────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


def totp_required(f):
    """If ADMIN_TOTP_SECRET is set, also requires totp_verified in session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))
        if ADMIN_TOTP_SECRET and not session.get("totp_verified"):
            return redirect(url_for("admin_login_totp"))
        return f(*args, **kwargs)
    return decorated


# ── Utilities ──────────────────────────────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "")


def log_event(event: str, document_id: int | None = None, email: str | None = None,
              request_id: int | None = None, extra: dict | None = None) -> None:
    ip = _client_ip()
    country, city = "", ""
    if GEO_LOOKUP:
        def _bg_geo():
            result = _geo_lookup(ip)
            try:
                db = sqlite3.connect(DATABASE)
                db.execute(
                    "UPDATE audit_log SET country=?, city=? WHERE id=(SELECT MAX(id) FROM audit_log)",
                    result,
                )
                db.commit()
                db.close()
            except Exception:
                pass
        threading.Thread(target=_bg_geo, daemon=True).start()
    get_db().execute(
        "INSERT INTO audit_log (event, document_id, email, ip_address, country, city,"
        " user_agent, request_id, extra, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (event, document_id, email, ip, country, city,
         request.headers.get("User-Agent", "")[:512],
         request_id, json.dumps(extra) if extra else None,
         utcnow().isoformat()),
    )
    get_db().commit()


def _log_admin_event(event: str) -> None:
    get_db().execute(
        "INSERT INTO admin_events (event, ip_address, user_agent, created_at) VALUES (?,?,?,?)",
        (event, _client_ip(), request.headers.get("User-Agent", "")[:512], utcnow().isoformat()),
    )
    get_db().commit()


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:40]


def _check_session_ip() -> bool:
    """Return False (and clear session) if IP binding is enabled and IP changed."""
    if not SESSION_BIND_IP:
        return True
    bound = session.get("bound_ip")
    if bound and bound != _client_ip():
        session.clear()
        return False
    return True


# ── Security headers & HTTPS redirect ──────────────────────────────────────────

@app.before_request
def _https_redirect():
    if FORCE_HTTPS:
        proto = request.headers.get("X-Forwarded-Proto", "https")
        if proto != "https":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if "application/pdf" not in response.content_type:
        response.headers["Cache-Control"] = "no-store"
    return response


# ── Watermarking ───────────────────────────────────────────────────────────────

def _watermark(pdf_bytes: bytes, email: str, ip: str) -> bytes:
    """Stamp every page in memory. Plaintext bytes never written to disk."""
    timestamp = utcnow().strftime("%Y-%m-%d %H:%M UTC")
    line1 = email
    line2 = f"{ip}  ·  {timestamp}"
    footer = f"CONFIDENTIAL  ·  {email}  ·  {ip}  ·  {timestamp}"

    reader = pypdf.PdfReader(BytesIO(pdf_bytes))
    writer = pypdf.PdfWriter()

    for page in reader.pages:
        w = float(page.mediabox.width)
        h = float(page.mediabox.height)

        buf = BytesIO()
        c = rl_canvas.Canvas(buf, pagesize=(w, h))
        c.setFont("Helvetica", 9)
        c.setFillColor(Color(0.863, 0.149, 0.149, alpha=0.13))
        c.saveState()
        c.translate(w / 2, h / 2)
        c.rotate(38)
        for col in range(-3, 4):
            for row in range(-5, 6):
                x, y = col * 200, row * 90
                c.drawCentredString(x, y + 10, line1)
                c.drawCentredString(x, y - 4, line2)
        c.restoreState()
        c.setFillColor(Color(0.863, 0.149, 0.149, alpha=0.07))
        c.rect(0, 0, w, 20, fill=1, stroke=0)
        c.setFillColor(Color(0.863, 0.149, 0.149, alpha=0.75))
        c.setFont("Helvetica", 6.5)
        c.drawCentredString(w / 2, 7, footer)
        c.save()

        stamp = pypdf.PdfReader(BytesIO(buf.getvalue())).pages[0]
        page.merge_page(stamp)
        writer.add_page(page)
        writer.pages[-1].compress_content_streams()

    out = BytesIO()
    writer.write(out)
    return out.getvalue()


# ── Background cleanup ─────────────────────────────────────────────────────────

def _cleanup_loop() -> None:
    """Mark stale approved rows (PIN never redeemed) as expired every hour."""
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            cutoff = (utcnow() - timedelta(minutes=PIN_EXPIRY_MINUTES)).isoformat()
            db = sqlite3.connect(DATABASE)
            cur = db.execute(
                "UPDATE requests SET status='expired'"
                " WHERE status='approved' AND approved_at < ?",
                (cutoff,),
            )
            db.commit()
            db.close()
            if cur.rowcount:
                app.logger.info("Cleanup: expired %d stale approved rows", cur.rowcount)
        except Exception as exc:
            app.logger.error("Cleanup error: %s", exc)


_cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
_cleanup_thread.start()


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    db = get_db()
    docs = db.execute(
        "SELECT * FROM documents WHERE status='active' ORDER BY created_at DESC"
    ).fetchall()
    if len(docs) == 1:
        return redirect(url_for("doc_landing", doc_id=docs[0]["id"]))
    return render_template("index.html", documents=docs, doc_name=DOCUMENT_NAME)


@app.route("/doc/<int:doc_id>/")
def doc_landing(doc_id: int):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404
    return render_template("doc_landing.html", doc=doc, doc_name=doc["name"])


@app.route("/doc/<int:doc_id>/request", methods=["GET", "POST"])
@csrf.exempt
def request_access(doc_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404

    captcha_q, captcha_hash = generate_captcha()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        captcha_answer = request.form.get("captcha_answer", "").strip()
        stored_hash = request.form.get("captcha_hash", "")

        if not verify_captcha(captcha_answer, stored_hash):
            flash("Incorrect CAPTCHA answer. Please try again.", "error")
            captcha_q, captcha_hash = generate_captcha()
            return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                                   captcha_q=captcha_q, captcha_hash=captcha_hash)

        if not email or "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "error")
            captcha_q, captcha_hash = generate_captcha()
            return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                                   captcha_q=captcha_q, captcha_hash=captcha_hash)

        # Check doc is active
        if doc["status"] != "active":
            flash("This document is no longer available.", "error")
            return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                                   captcha_q=captcha_q, captcha_hash=captcha_hash)

        # Check expiry
        if doc["expires_at"]:
            try:
                if utcnow() > datetime.fromisoformat(doc["expires_at"]):
                    flash("Access to this document has expired.", "error")
                    return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                                           captcha_q=captcha_q, captcha_hash=captcha_hash)
            except ValueError:
                pass

        # Check duplicate
        existing = db.execute(
            "SELECT id FROM requests WHERE email=? AND document_id=? AND status IN ('pending','approved','verify_pending')",
            (email, doc_id),
        ).fetchone()
        if existing:
            flash("A request for this email is already pending or awaiting PIN entry.", "info")
            captcha_q, captcha_hash = generate_captcha()
            return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                                   captcha_q=captcha_q, captcha_hash=captcha_hash)

        now = utcnow().isoformat()
        email_domain = email.split("@")[-1]

        # Auto-approve all requests
        auto_approved = True

        if auto_approved:
            raw_pin = f"{secrets.randbelow(1_000_000):06d}"
            pin_hash = hash_pin(raw_pin)
            cur = db.execute(
                "INSERT INTO requests (document_id, email, pin, status, created_at, approved_at,"
                " access_duration_minutes) VALUES (?,?,?,'approved',?,?,?)",
                (doc_id, email, pin_hash, now, now, ACCESS_WINDOW_MINUTES),
            )
            db.commit()
            req_id = cur.lastrowid
            log_event("access_requested", document_id=doc_id, email=email, request_id=req_id)
            log_event("request_approved", document_id=doc_id, email=email, request_id=req_id,
                      extra={"auto_approved": True})
            notify_webhook("auto_approved", email=email, doc_name=doc["name"])
            try:
                duration_label = next(
                    (l for d, l in ACCESS_DURATION_OPTIONS if d == ACCESS_WINDOW_MINUTES),
                    f"{ACCESS_WINDOW_MINUTES} min"
                )
                send_email(
                    email,
                    f"Your Access PIN — {doc['name']}",
                    f"Your one-time PIN is: {raw_pin}\n\nExpires in {PIN_EXPIRY_MINUTES} min.\n"
                    f"Access window: {duration_label}.",
                    _render_email("email_pin.html", email=email, raw_pin=raw_pin,
                                  pin_expiry=PIN_EXPIRY_MINUTES,
                                  duration_label=duration_label,
                                  enter_pin_url=url_for("enter_pin", doc_id=doc_id, _external=True)),
                    cc=ADMIN_EMAIL,
                )
            except Exception as exc:
                app.logger.error("Auto-approve PIN email to %s failed: %s", email, exc)
            return redirect(url_for("enter_pin", doc_id=doc_id))
        else:
            if doc["require_email_verify"]:
                verify_tok = generate_signed_token(email, doc_id, 0)
                cur = db.execute(
                    "INSERT INTO requests (document_id, email, verify_token, status, created_at)"
                    " VALUES (?,?,?,'verify_pending',?)",
                    (doc_id, email, verify_tok, now),
                )
                db.commit()
                req_id = cur.lastrowid
                log_event("access_requested", document_id=doc_id, email=email, request_id=req_id)
                try:
                    verify_url = url_for("verify_email", doc_id=doc_id, token=verify_tok, _external=True)
                    send_email(
                        email,
                        f"Verify your email — {doc['name']}",
                        f"Please verify your email to submit your access request:\n\n{verify_url}",
                    )
                except Exception as exc:
                    app.logger.error("Verify email to %s failed: %s", email, exc)
                flash("Please check your email to verify your address before your request is reviewed.", "info")
            else:
                cur = db.execute(
                    "INSERT INTO requests (document_id, email, email_verified, status, created_at)"
                    " VALUES (?,?,1,'pending',?)",
                    (doc_id, email, now),
                )
                db.commit()
                req_id = cur.lastrowid
                log_event("access_requested", document_id=doc_id, email=email, request_id=req_id)
                notify_webhook("access_requested", email=email, doc_name=doc["name"])
                try:
                    send_email(
                        ADMIN_EMAIL,
                        f"New Access Request — {doc['name']}",
                        f"New access request from {email} for {doc['name']}.\n\nLog in to approve or deny it.",
                        _render_email("email_admin_request.html", email=email, now=now,
                                      doc_name=doc["name"],
                                      admin_url=url_for("admin_document", document_id=doc_id, _external=True)),
                    )
                except Exception as exc:
                    app.logger.error("Admin notification email failed: %s", exc)
                return redirect(url_for("enter_pin", doc_id=doc_id))

        captcha_q, captcha_hash = generate_captcha()
        return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                               captcha_q=captcha_q, captcha_hash=captcha_hash, submitted=False)

    return render_template("request.html", doc=doc, doc_name=doc["name"], suggested_emails=SUGGESTED_EMAILS,
                           captcha_q=captcha_q, captcha_hash=captcha_hash, submitted=False)


@app.route("/doc/<int:doc_id>/new-captcha")
def new_captcha(doc_id: int):
    q, h = generate_captcha()
    return {"q": q, "hash": h}


@app.route("/doc/<int:doc_id>/status", methods=["GET", "POST"])
@csrf.exempt
def request_status(doc_id: int):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404

    status_info = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email and "@" in email:
            db = get_db()
            row = db.execute(
                "SELECT * FROM requests WHERE email=? AND document_id=? ORDER BY created_at DESC LIMIT 1",
                (email, doc_id),
            ).fetchone()
            if row:
                extra = {}
                if row["status"] == "approved" and row["approved_at"]:
                    approved_at = datetime.fromisoformat(row["approved_at"])
                    expires_at = approved_at + timedelta(minutes=PIN_EXPIRY_MINUTES)
                    remaining = int((expires_at - utcnow()).total_seconds() // 60)
                    extra["pin_expires_in"] = max(0, remaining)
                    extra["pin_expired"] = utcnow() > expires_at
                status_info = {"status": row["status"], "email": email, **extra}
            else:
                status_info = {"status": "not_found", "email": email}
        else:
            flash("Please enter a valid email address.", "error")

    return render_template("status.html", doc=doc, doc_name=doc["name"], status_info=status_info)


@app.route("/doc/<int:doc_id>/verify/<path:token>")
def verify_email(doc_id: int, token: str):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404

    payload = verify_signed_token(token)
    if not payload or payload.get("type") != "one_click" or payload.get("doc_id") != doc_id:
        flash("Invalid or expired verification link.", "error")
        return redirect(url_for("request_access", doc_id=doc_id))

    email = payload.get("email", "")
    db = get_db()
    row = db.execute(
        "SELECT * FROM requests WHERE verify_token=? AND document_id=? AND email=?",
        (token, doc_id, email),
    ).fetchone()
    if not row:
        flash("Verification link not found.", "error")
        return redirect(url_for("request_access", doc_id=doc_id))

    if row["status"] == "verify_pending":
        db.execute(
            "UPDATE requests SET email_verified=1, status='pending', verify_token=NULL WHERE id=?",
            (row["id"],),
        )
        db.commit()
        # Notify admin
        try:
            send_email(
                ADMIN_EMAIL,
                f"New Verified Access Request — {doc['name']}",
                f"New verified access request from {email} for {doc['name']}.",
                _render_email("email_admin_request.html", email=email,
                              now=utcnow().isoformat(), doc_name=doc["name"],
                              admin_url=url_for("admin_document", document_id=doc_id, _external=True)),
            )
        except Exception as exc:
            app.logger.error("Admin notification email failed: %s", exc)
        log_event("email_verified", document_id=doc_id, email=email, request_id=row["id"])
        flash("Email verified! Your request has been submitted for review.", "success")
    else:
        flash("This verification link has already been used.", "info")

    return redirect(url_for("request_access", doc_id=doc_id))


@app.route("/doc/<int:doc_id>/enter-pin", methods=["GET", "POST"])
@csrf.exempt
@limiter.limit("10 per minute; 30 per hour")
def enter_pin(doc_id: int):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404

    BAD = "Invalid email or PIN."

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pin = request.form.get("pin", "").strip()

        if not email or not pin:
            flash(BAD, "error")
            return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        db = get_db()
        row = db.execute(
            "SELECT * FROM requests WHERE email=? AND document_id=? AND status='approved'"
            " ORDER BY approved_at DESC LIMIT 1",
            (email, doc_id),
        ).fetchone()

        if not row:
            flash(BAD, "error")
            return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        approved_at = datetime.fromisoformat(row["approved_at"])
        if utcnow() > approved_at + timedelta(minutes=PIN_EXPIRY_MINUTES):
            flash("PIN has expired. Please request a new one.", "error")
            return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        if not verify_pin(pin, row["pin"]):
            flash(BAD, "error")
            return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        # Check max_viewers
        if doc["max_viewers"]:
            used_count = db.execute(
                "SELECT COUNT(*) FROM requests WHERE document_id=? AND status IN ('used','approved')",
                (doc_id,),
            ).fetchone()[0]
            if used_count >= doc["max_viewers"]:
                flash("Maximum viewer limit has been reached for this document.", "error")
                return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        token = secrets.token_urlsafe(32)
        now_str = utcnow().isoformat()
        cursor = db.execute(
            "UPDATE requests SET status='used', unlocked_at=?, session_token=?"
            " WHERE id=? AND status='approved'",
            (now_str, token, row["id"]),
        )
        db.commit()

        if cursor.rowcount != 1:
            flash(BAD, "error")
            return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])

        log_event("pin_redeemed", document_id=doc_id, email=email, request_id=row["id"])

        duration = int(row["access_duration_minutes"] or ACCESS_WINDOW_MINUTES)
        expires = utcnow() + timedelta(minutes=duration)
        client_ip = _client_ip()

        session.clear()
        session["access_granted"] = True
        session["access_expires"] = expires.isoformat()
        session["user_email"] = email
        session["session_token"] = token
        session["request_id"] = row["id"]
        session["doc_id"] = doc_id
        session["bound_ip"] = client_ip

        return redirect(url_for("viewer", doc_id=doc_id))

    return render_template("pin_entry.html", doc=doc, doc_name=doc["name"])


@app.route("/doc/<int:doc_id>/viewer")
def viewer(doc_id: int):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("404.html", doc_name=DOCUMENT_NAME), 404

    if not session.get("access_granted"):
        return redirect(url_for("locked_page", reason="no_session"))

    if session.get("doc_id") != doc_id:
        return redirect(url_for("locked_page", reason="no_session"))

    if not _check_session_ip():
        return redirect(url_for("locked_page", reason="session_ip_mismatch"))

    expires_str = session.get("access_expires", "")
    try:
        expires = datetime.fromisoformat(expires_str)
    except ValueError:
        session.clear()
        return redirect(url_for("locked_page", reason="invalid_session"))

    if utcnow() > expires:
        session.clear()
        return redirect(url_for("locked_page", reason="expired"))

    token = session.get("session_token")
    req_id = session.get("request_id")
    if not token or not req_id:
        session.clear()
        return redirect(url_for("locked_page", reason="no_session"))

    db_row = get_db().execute(
        "SELECT session_token FROM requests WHERE id=?", (req_id,)
    ).fetchone()
    if not db_row or db_row["session_token"] != token:
        session.clear()
        return redirect(url_for("locked_page", reason="revoked"))

    return render_template(
        "viewer.html",
        doc=doc,
        doc_name=doc["name"],
        doc_id=doc_id,
        access_expires=expires_str,
        user_email=session.get("user_email", ""),
        session_token=token,
        view_pdf_url=url_for("view_pdf", doc_id=doc_id),
    )


@app.route("/doc/<int:doc_id>/view-pdf")
def view_pdf(doc_id: int):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return render_template("locked.html", reason="not_found", doc_name=DOCUMENT_NAME), 404

    if not session.get("access_granted"):
        return Response("Forbidden", status=403)

    if session.get("doc_id") != doc_id:
        return Response("Forbidden", status=403)

    # Require the viewer token header — blocks direct browser navigation to the URL
    token = session.get("session_token")
    if request.headers.get("X-Viewer-Token") != token:
        return Response("Forbidden", status=403)

    if not _check_session_ip():
        return Response("Forbidden", status=403)

    expires_str = session.get("access_expires", "")
    try:
        expires = datetime.fromisoformat(expires_str)
    except ValueError:
        session.clear()
        return Response("Forbidden", status=403)

    if utcnow() > expires:
        session.clear()
        return Response("Forbidden", status=403)

    req_id = session.get("request_id")
    if not token or not req_id:
        session.clear()
        return Response("Forbidden", status=403)

    db_row = get_db().execute(
        "SELECT session_token FROM requests WHERE id=?", (req_id,)
    ).fetchone()
    if not db_row or db_row["session_token"] != token:
        session.clear()
        return render_template("locked.html", reason="revoked", doc_name=doc["name"]), 403

    enc_path = os.path.join(UPLOADS_DIR, doc["enc_filename"])
    try:
        fernet = Fernet(doc["fernet_key"].encode())
        with open(enc_path, "rb") as fh:
            ciphertext = fh.read()
        plaintext = fernet.decrypt(ciphertext)
    except FileNotFoundError:
        app.logger.error("Encrypted PDF not found: %s", enc_path)
        return "Document not found.", 404
    except Exception as exc:
        app.logger.error("Decryption failed: %s", exc)
        return "Could not decrypt document.", 500

    try:
        plaintext = _watermark(plaintext, session.get("user_email", "unknown"), _client_ip())
    except Exception as exc:
        app.logger.error("Watermarking failed, serving unwatermarked: %s", exc)

    log_event("document_viewed", document_id=doc_id, email=session.get("user_email"),
              request_id=req_id)
    # Update last_viewed_at
    get_db().execute(
        "UPDATE requests SET last_viewed_at=? WHERE id=?",
        (utcnow().isoformat(), req_id),
    )
    get_db().commit()

    minutes_left = int((expires - utcnow()).total_seconds() // 60)
    return Response(
        plaintext,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": "inline; filename=document.pdf",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "X-Minutes-Remaining": str(minutes_left),
            "X-Content-Type-Options": "nosniff",
            "X-Robots-Tag": "noindex, noarchive",
            "Content-Security-Policy": "default-src 'none'",
        },
    )


@app.route("/access/<path:token>")
def one_click_access(token: str):
    payload = verify_signed_token(token)
    if not payload or payload.get("type") != "one_click":
        flash("Invalid or expired access link.", "error")
        return redirect(url_for("index"))

    doc_id = payload.get("doc_id")
    req_id = payload.get("req_id")
    email = payload.get("email")

    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    row = db.execute(
        "SELECT * FROM requests WHERE id=? AND email=? AND document_id=? AND status='approved'",
        (req_id, email, doc_id),
    ).fetchone()
    if not row:
        flash("This access link has already been used or is no longer valid.", "error")
        return redirect(url_for("doc_landing", doc_id=doc_id))

    # Atomic update to 'used'
    new_token = secrets.token_urlsafe(32)
    now_str = utcnow().isoformat()
    cursor = db.execute(
        "UPDATE requests SET status='used', unlocked_at=?, session_token=?"
        " WHERE id=? AND status='approved'",
        (now_str, new_token, row["id"]),
    )
    db.commit()

    if cursor.rowcount != 1:
        flash("This access link has already been used.", "error")
        return redirect(url_for("doc_landing", doc_id=doc_id))

    log_event("pin_redeemed", document_id=doc_id, email=email, request_id=row["id"],
              extra={"method": "one_click"})

    duration = int(row["access_duration_minutes"] or ACCESS_WINDOW_MINUTES)
    expires = utcnow() + timedelta(minutes=duration)

    session.clear()
    session["access_granted"] = True
    session["access_expires"] = expires.isoformat()
    session["user_email"] = email
    session["session_token"] = new_token
    session["request_id"] = row["id"]
    session["doc_id"] = doc_id
    session["bound_ip"] = _client_ip()

    return redirect(url_for("viewer", doc_id=doc_id))


@app.route("/locked")
def locked_page():
    reason = request.args.get("reason", "no_session")
    return render_template("locked.html", reason=reason, doc_name=DOCUMENT_NAME), 403


# ── API endpoints ──────────────────────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["POST"])
@csrf.exempt
def api_heartbeat():
    if not session.get("access_granted"):
        return "", 401
    req_id = session.get("request_id")
    if req_id:
        get_db().execute(
            "UPDATE requests SET last_viewed_at=? WHERE id=?",
            (utcnow().isoformat(), req_id),
        )
        get_db().commit()
    return "", 204


@app.route("/api/view-end", methods=["POST"])
@csrf.exempt
def api_view_end():
    if not session.get("access_granted"):
        return "", 401
    seconds = 0
    try:
        data = request.get_json(silent=True) or {}
        seconds = int(data.get("elapsed_seconds", 0))
    except Exception:
        pass
    req_id = session.get("request_id")
    doc_id = session.get("doc_id")
    log_event("view_ended", document_id=doc_id, email=session.get("user_email"),
              request_id=req_id, extra={"elapsed_seconds": seconds})
    return "", 204


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if secrets.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
            session.clear()
            if ADMIN_TOTP_SECRET:
                session["admin_password_ok"] = True
                _log_admin_event("admin_password_ok")
                return redirect(url_for("admin_login_totp"))
            session["admin_authenticated"] = True
            session["totp_verified"] = True
            _log_admin_event("admin_login_success")
            return redirect(url_for("admin_dashboard"))
        _log_admin_event("admin_login_failed")
        flash("Incorrect password.", "error")
    return render_template("admin_login.html", doc_name=DOCUMENT_NAME)


@app.route("/admin/login/totp", methods=["GET", "POST"])
def admin_login_totp():
    if not session.get("admin_password_ok"):
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        try:
            import pyotp
            totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
            if totp.verify(code, valid_window=1):
                session["admin_authenticated"] = True
                session["totp_verified"] = True
                session.pop("admin_password_ok", None)
                _log_admin_event("admin_totp_success")
                return redirect(url_for("admin_dashboard"))
        except Exception as exc:
            app.logger.error("TOTP verification error: %s", exc)
        _log_admin_event("admin_totp_failed")
        flash("Invalid TOTP code. Please try again.", "error")
    return render_template("admin_login_totp.html", doc_name=DOCUMENT_NAME)


@app.route("/admin/logout")
@admin_required
def admin_logout():
    _log_admin_event("admin_logout")
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
@totp_required
def admin_dashboard():
    db = get_db()
    docs_raw = db.execute(
        "SELECT * FROM documents ORDER BY created_at DESC"
    ).fetchall()

    documents = []
    for doc in docs_raw:
        pending_count = db.execute(
            "SELECT COUNT(*) FROM requests WHERE document_id=? AND status='pending'",
            (doc["id"],),
        ).fetchone()[0]
        active_count = db.execute(
            "SELECT COUNT(*) FROM requests WHERE document_id=? AND status='used' AND session_token IS NOT NULL",
            (doc["id"],),
        ).fetchone()[0]
        total_viewers = db.execute(
            "SELECT COUNT(*) FROM requests WHERE document_id=? AND status='used'",
            (doc["id"],),
        ).fetchone()[0]
        documents.append({
            "id": doc["id"],
            "name": doc["name"],
            "description": doc["description"],
            "status": doc["status"],
            "expires_at": doc["expires_at"],
            "max_viewers": doc["max_viewers"],
            "pending_count": pending_count,
            "active_count": active_count,
            "total_viewers": total_viewers,
        })

    total_documents = len(documents)
    total_requests = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    today_str = utcnow().strftime("%Y-%m-%d")
    pending_today = db.execute(
        "SELECT COUNT(*) FROM requests WHERE status='pending' AND created_at LIKE ?",
        (f"{today_str}%",),
    ).fetchone()[0]
    active_sessions = db.execute(
        "SELECT COUNT(*) FROM requests WHERE status='used' AND session_token IS NOT NULL"
    ).fetchone()[0]

    recent_events = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20"
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        documents=documents,
        stats={
            "total_documents": total_documents,
            "total_requests": total_requests,
            "pending_today": pending_today,
            "active_sessions": active_sessions,
        },
        recent_events=recent_events,
        doc_name=DOCUMENT_NAME,
    )


@app.route("/admin/documents")
@totp_required
def admin_documents():
    docs = get_db().execute(
        "SELECT * FROM documents ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin_documents.html", documents=docs, doc_name=DOCUMENT_NAME)


@app.route("/admin/documents/new", methods=["GET", "POST"])
@totp_required
def admin_document_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        expires_at_raw = request.form.get("expires_at", "").strip()
        max_viewers_raw = request.form.get("max_viewers", "").strip()
        approved_domains = request.form.get("approved_domains", "").strip()
        require_email_verify = 1 if request.form.get("require_email_verify") else 0

        if not name:
            flash("Document name is required.", "error")
            return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)

        uploaded = request.files.get("pdf")
        if not uploaded or not uploaded.filename.lower().endswith(".pdf"):
            flash("Please upload a valid .pdf file.", "error")
            return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)

        plaintext = uploaded.read()
        if not plaintext:
            flash("Uploaded file is empty.", "error")
            return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)
        if not plaintext.startswith(b"%PDF"):
            flash("File does not appear to be a valid PDF.", "error")
            return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)

        expires_at = None
        if expires_at_raw:
            try:
                expires_at = datetime.fromisoformat(expires_at_raw).isoformat()
            except ValueError:
                flash("Invalid expiry date format.", "error")
                return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)

        max_viewers = None
        if max_viewers_raw:
            try:
                max_viewers = int(max_viewers_raw)
                if max_viewers < 1:
                    raise ValueError
            except ValueError:
                flash("Max viewers must be a positive integer.", "error")
                return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)

        # Encrypt PDF with a new per-doc Fernet key
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(plaintext)

        slug = _slug(name)
        enc_filename = f"{slug}_{secrets.token_hex(6)}.pdf.enc"
        enc_path = os.path.join(UPLOADS_DIR, enc_filename)
        with open(enc_path, "wb") as fh:
            fh.write(ciphertext)

        now_str = utcnow().isoformat()
        db = get_db()
        db.execute(
            "INSERT INTO documents (name, description, enc_filename, fernet_key, created_at,"
            " expires_at, max_viewers, approved_domains, require_email_verify, status)"
            " VALUES (?,?,?,?,?,?,?,?,?,'active')",
            (name, description or None, enc_filename, fernet_key.decode(),
             now_str, expires_at, max_viewers, approved_domains or None, require_email_verify),
        )
        db.commit()
        flash(f"Document '{name}' created successfully.", "success")
        return redirect(url_for("admin_documents"))

    return render_template("admin_document_new.html", doc_name=DOCUMENT_NAME)


@app.route("/admin/documents/bulk", methods=["GET", "POST"])
@totp_required
def admin_document_bulk():
    if request.method == "POST":
        files = request.files.getlist("pdfs")
        if not files or all(f.filename == "" for f in files):
            flash("Please select at least one PDF file.", "error")
            return render_template("admin_document_bulk.html", doc_name=DOCUMENT_NAME)

        expires_at_raw = request.form.get("expires_at", "").strip()
        max_viewers_raw = request.form.get("max_viewers", "").strip()
        approved_domains = request.form.get("approved_domains", "").strip()
        require_email_verify = 1 if request.form.get("require_email_verify") else 0

        expires_at = None
        if expires_at_raw:
            try:
                expires_at = datetime.fromisoformat(expires_at_raw).isoformat()
            except ValueError:
                flash("Invalid expiry date format.", "error")
                return render_template("admin_document_bulk.html", doc_name=DOCUMENT_NAME)

        max_viewers = None
        if max_viewers_raw:
            try:
                max_viewers = int(max_viewers_raw)
                if max_viewers < 1:
                    raise ValueError
            except ValueError:
                flash("Max viewers must be a positive integer.", "error")
                return render_template("admin_document_bulk.html", doc_name=DOCUMENT_NAME)

        db = get_db()
        now_str = utcnow().isoformat()
        created, skipped = [], []

        for uploaded in files:
            if not uploaded or not uploaded.filename:
                continue
            if not uploaded.filename.lower().endswith(".pdf"):
                skipped.append(f"{uploaded.filename} (not a PDF)")
                continue

            plaintext = uploaded.read()
            if not plaintext or not plaintext.startswith(b"%PDF"):
                skipped.append(f"{uploaded.filename} (invalid PDF)")
                continue

            doc_name = os.path.splitext(uploaded.filename)[0].replace("_", " ").replace("-", " ").strip()
            fernet_key = Fernet.generate_key()
            ciphertext = Fernet(fernet_key).encrypt(plaintext)
            slug = _slug(doc_name)
            enc_filename = f"{slug}_{secrets.token_hex(6)}.pdf.enc"
            enc_path = os.path.join(UPLOADS_DIR, enc_filename)
            with open(enc_path, "wb") as fh:
                fh.write(ciphertext)

            db.execute(
                "INSERT INTO documents (name, enc_filename, fernet_key, created_at,"
                " expires_at, max_viewers, approved_domains, require_email_verify, status)"
                " VALUES (?,?,?,?,?,?,?,?,'active')",
                (doc_name, enc_filename, fernet_key.decode(),
                 now_str, expires_at, max_viewers, approved_domains or None, require_email_verify),
            )
            db.commit()
            log_event("document_created", extra={"name": doc_name})
            created.append(doc_name)

        if created:
            flash(f"{len(created)} document(s) uploaded: {', '.join(created)}.", "success")
        if skipped:
            flash(f"{len(skipped)} file(s) skipped: {', '.join(skipped)}.", "error")

        return redirect(url_for("admin_documents"))

    return render_template("admin_document_bulk.html", doc_name=DOCUMENT_NAME)


@app.route("/admin/documents/<int:document_id>")
@totp_required
def admin_document(document_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))

    page_size = 50
    q = request.args.get("q", "").strip()

    def paginate(query_base, params, page_arg):
        page = max(1, int(request.args.get(page_arg, 1) or 1))
        count = db.execute(f"SELECT COUNT(*) FROM ({query_base})", params).fetchone()[0]
        total_pages = max(1, (count + page_size - 1) // page_size)
        page = min(page, total_pages)
        offset = (page - 1) * page_size
        rows = db.execute(f"{query_base} LIMIT ? OFFSET ?", params + (page_size, offset)).fetchall()
        return rows, page, total_pages

    like = f"%{q}%" if q else "%"
    pending, pending_page, pending_pages = paginate(
        "SELECT * FROM requests WHERE document_id=? AND status='pending' AND email LIKE ? ORDER BY created_at DESC",
        (document_id, like), "pending_page"
    )
    approved, approved_page, approved_pages = paginate(
        "SELECT * FROM requests WHERE document_id=? AND status='approved' AND email LIKE ? ORDER BY approved_at DESC",
        (document_id, like), "approved_page"
    )
    sessions_rows, sessions_page, sessions_pages = paginate(
        "SELECT * FROM requests WHERE document_id=? AND status='used' AND email LIKE ? ORDER BY unlocked_at DESC",
        (document_id, like), "sessions_page"
    )
    denied = db.execute(
        "SELECT * FROM requests WHERE document_id=? AND status='denied' ORDER BY created_at DESC LIMIT 100",
        (document_id,),
    ).fetchall()
    expired = db.execute(
        "SELECT * FROM requests WHERE document_id=? AND status='expired' ORDER BY approved_at DESC LIMIT 100",
        (document_id,),
    ).fetchall()

    return render_template(
        "admin_document.html",
        doc=doc,
        doc_name=doc["name"],
        pending=pending, pending_page=pending_page, pending_pages=pending_pages,
        approved=approved, approved_page=approved_page, approved_pages=approved_pages,
        sessions=sessions_rows, sessions_page=sessions_page, sessions_pages=sessions_pages,
        denied=denied,
        expired=expired,
        pin_expiry=PIN_EXPIRY_MINUTES,
        access_window=ACCESS_WINDOW_MINUTES,
        duration_options=ACCESS_DURATION_OPTIONS,
        q=q,
    )


@app.route("/admin/documents/<int:document_id>/approve/<int:request_id>", methods=["POST"])
@totp_required
def approve_request(document_id: int, request_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    row = db.execute(
        "SELECT * FROM requests WHERE id=? AND document_id=? AND status='pending'",
        (request_id, document_id),
    ).fetchone()
    if not doc or not row:
        flash("Request not found or already processed.", "error")
        return redirect(url_for("admin_document", document_id=document_id))

    try:
        duration = int(request.form.get("duration", ACCESS_WINDOW_MINUTES))
        if duration not in [d for d, _ in ACCESS_DURATION_OPTIONS]:
            duration = ACCESS_WINDOW_MINUTES
    except ValueError:
        duration = ACCESS_WINDOW_MINUTES

    send_link = bool(request.form.get("send_link"))
    now = utcnow().isoformat()
    duration_label = next((l for d, l in ACCESS_DURATION_OPTIONS if d == duration), f"{duration} min")

    if send_link:
        signed_tok = generate_signed_token(row["email"], document_id, request_id)
        db.execute(
            "UPDATE requests SET signed_token=?, status='approved', approved_at=?,"
            " access_duration_minutes=? WHERE id=?",
            (signed_tok, now, duration, request_id),
        )
        db.commit()
        access_url = url_for("one_click_access", token=signed_tok, _external=True)
        try:
            send_email(
                row["email"],
                f"Access Approved — {doc['name']}",
                f"Your access request has been approved.\n\nClick to access: {access_url}\n\n"
                f"Link expires in {PIN_EXPIRY_MINUTES} minutes. Access window: {duration_label}.",
            )
        except Exception as exc:
            app.logger.error("Signed link email to %s failed: %s", row["email"], exc)
            db.execute(
                "UPDATE requests SET signed_token=NULL, status='pending', approved_at=NULL WHERE id=?",
                (request_id,),
            )
            db.commit()
            flash(f"Could not send email: {exc}. Request left as pending.", "error")
            return redirect(url_for("admin_document", document_id=document_id))
    else:
        raw_pin = f"{secrets.randbelow(1_000_000):06d}"
        pin_hash = hash_pin(raw_pin)
        db.execute(
            "UPDATE requests SET pin=?, status='approved', approved_at=?,"
            " access_duration_minutes=? WHERE id=?",
            (pin_hash, now, duration, request_id),
        )
        db.commit()
        try:
            send_email(
                row["email"],
                f"Your Access PIN — {doc['name']}",
                f"Your one-time PIN is: {raw_pin}\n\nExpires in {PIN_EXPIRY_MINUTES} min.\n"
                f"Access window: {duration_label}.",
                _render_email(
                    "email_pin.html",
                    email=row["email"],
                    raw_pin=raw_pin,
                    pin_expiry=PIN_EXPIRY_MINUTES,
                    duration_label=duration_label,
                    enter_pin_url=url_for("enter_pin", doc_id=document_id, _external=True),
                ),
                cc=ADMIN_EMAIL,
            )
        except Exception as exc:
            app.logger.error("PIN email to %s failed: %s", row["email"], exc)
            db.execute(
                "UPDATE requests SET pin=NULL, status='pending', approved_at=NULL WHERE id=?",
                (request_id,),
            )
            db.commit()
            flash(f"Could not send PIN email: {exc}. Request left as pending.", "error")
            return redirect(url_for("admin_document", document_id=document_id))

    log_event("request_approved", document_id=document_id, email=row["email"],
              request_id=request_id)
    notify_webhook("request_approved", email=row["email"], doc_name=doc["name"],
                   extra={"access_window": duration_label})
    flash(f"Approved — {'link' if send_link else 'PIN'} emailed to {row['email']} ({duration_label} window).", "success")
    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/bulk-approve", methods=["POST"])
@totp_required
def bulk_approve_document(document_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))

    ids = request.form.getlist("request_ids")
    if not ids:
        flash("No requests selected.", "info")
        return redirect(url_for("admin_document", document_id=document_id))

    try:
        duration = int(request.form.get("duration", ACCESS_WINDOW_MINUTES))
        if duration not in [d for d, _ in ACCESS_DURATION_OPTIONS]:
            duration = ACCESS_WINDOW_MINUTES
    except ValueError:
        duration = ACCESS_WINDOW_MINUTES

    duration_label = next((l for d, l in ACCESS_DURATION_OPTIONS if d == duration), f"{duration} min")
    success, failed = 0, 0
    now = utcnow().isoformat()

    for rid_str in ids:
        try:
            rid = int(rid_str)
        except ValueError:
            continue

        row = db.execute(
            "SELECT * FROM requests WHERE id=? AND document_id=? AND status='pending'",
            (rid, document_id),
        ).fetchone()
        if not row:
            continue

        raw_pin = f"{secrets.randbelow(1_000_000):06d}"
        db.execute(
            "UPDATE requests SET pin=?, status='approved', approved_at=?, access_duration_minutes=? WHERE id=?",
            (hash_pin(raw_pin), now, duration, rid),
        )
        db.commit()

        try:
            send_email(
                row["email"],
                f"Your Access PIN — {doc['name']}",
                f"Your one-time PIN is: {raw_pin}\n\nExpires in {PIN_EXPIRY_MINUTES} min.\n"
                f"Access window: {duration_label}.",
                _render_email(
                    "email_pin.html",
                    email=row["email"],
                    raw_pin=raw_pin,
                    pin_expiry=PIN_EXPIRY_MINUTES,
                    duration_label=duration_label,
                    enter_pin_url=url_for("enter_pin", doc_id=document_id, _external=True),
                ),
                cc=ADMIN_EMAIL,
            )
            log_event("request_approved", document_id=document_id, email=row["email"],
                      request_id=rid)
            success += 1
        except Exception as exc:
            app.logger.error("Bulk PIN email to %s failed: %s", row["email"], exc)
            db.execute(
                "UPDATE requests SET pin=NULL, status='pending', approved_at=NULL WHERE id=?", (rid,)
            )
            db.commit()
            failed += 1

    if success:
        flash(f"Approved {success} request(s) with {duration_label} window.", "success")
    if failed:
        flash(f"{failed} PIN email(s) failed — those requests left as pending.", "error")
    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/deny/<int:request_id>", methods=["POST"])
@totp_required
def deny_request(document_id: int, request_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    row = db.execute(
        "SELECT * FROM requests WHERE id=? AND document_id=? AND status='pending'",
        (request_id, document_id),
    ).fetchone()
    if not doc or not row:
        flash("Request not found or already processed.", "error")
        return redirect(url_for("admin_document", document_id=document_id))

    reason = request.form.get("deny_reason", "").strip()
    db.execute(
        "UPDATE requests SET status='denied', deny_reason=? WHERE id=?",
        (reason or None, request_id),
    )
    db.commit()
    log_event("request_denied", document_id=document_id, email=row["email"],
              request_id=request_id)
    notify_webhook("request_denied", email=row["email"], doc_name=doc["name"])

    try:
        reason_text = f"\n\nReason: {reason}" if reason else ""
        send_email(
            row["email"],
            f"Access Request Update — {doc['name']}",
            f"Your request to access {doc['name']} has not been approved.{reason_text}\n\n"
            f"Contact the sender if you believe this is an error.",
            _render_email("email_denied.html", email=row["email"],
                          doc_name=doc["name"], deny_reason=reason),
        )
    except Exception as exc:
        app.logger.error("Denial email to %s failed: %s", row["email"], exc)

    flash(f"Request from {row['email']} denied.", "info")
    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/revoke/<int:request_id>", methods=["POST"])
@totp_required
def revoke_session(document_id: int, request_id: int):
    db = get_db()
    cursor = db.execute(
        "UPDATE requests SET session_token=NULL WHERE id=? AND document_id=? AND status='used'",
        (request_id, document_id),
    )
    db.commit()
    if cursor.rowcount:
        log_event("session_revoked", document_id=document_id, request_id=request_id)
        flash("Session revoked — user will be locked out on their next request.", "success")
    else:
        flash("No active session found for that request.", "error")
    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/resend/<int:request_id>", methods=["POST"])
@totp_required
def resend_pin(document_id: int, request_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    row = db.execute(
        "SELECT * FROM requests WHERE id=? AND document_id=? AND status='approved'",
        (request_id, document_id),
    ).fetchone()
    if not doc or not row:
        flash("Request not found or not in approved state.", "error")
        return redirect(url_for("admin_document", document_id=document_id))

    raw_pin = f"{secrets.randbelow(1_000_000):06d}"
    pin_hash = hash_pin(raw_pin)
    db.execute(
        "UPDATE requests SET pin=? WHERE id=?",
        (pin_hash, request_id),
    )
    db.commit()

    duration = int(row["access_duration_minutes"] or ACCESS_WINDOW_MINUTES)
    duration_label = next((l for d, l in ACCESS_DURATION_OPTIONS if d == duration), f"{duration} min")

    try:
        send_email(
            row["email"],
            f"Your New Access PIN — {doc['name']}",
            f"Your new one-time PIN is: {raw_pin}\n\nExpires in {PIN_EXPIRY_MINUTES} min.\n"
            f"Access window: {duration_label}.",
            _render_email(
                "email_pin.html",
                email=row["email"],
                raw_pin=raw_pin,
                pin_expiry=PIN_EXPIRY_MINUTES,
                duration_label=duration_label,
                enter_pin_url=url_for("enter_pin", doc_id=document_id, _external=True),
            ),
            cc=ADMIN_EMAIL,
        )
        log_event("pin_resent", document_id=document_id, email=row["email"],
                  request_id=request_id)
        flash(f"New PIN resent to {row['email']}.", "success")
    except Exception as exc:
        app.logger.error("Resend PIN email to %s failed: %s", row["email"], exc)
        flash(f"Failed to resend PIN: {exc}", "error")

    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/rotate-key", methods=["POST"])
@totp_required
def rotate_document_key(document_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))

    enc_path = os.path.join(UPLOADS_DIR, doc["enc_filename"])
    try:
        old_fernet = Fernet(doc["fernet_key"].encode())
        with open(enc_path, "rb") as fh:
            ciphertext = fh.read()
        plaintext = old_fernet.decrypt(ciphertext)
    except Exception as exc:
        flash(f"Failed to decrypt with current key: {exc}", "error")
        return redirect(url_for("admin_document", document_id=document_id))

    new_key = Fernet.generate_key()
    new_fernet = Fernet(new_key)
    new_ciphertext = new_fernet.encrypt(plaintext)

    with open(enc_path, "wb") as fh:
        fh.write(new_ciphertext)

    db.execute("UPDATE documents SET fernet_key=? WHERE id=?", (new_key.decode(), document_id))
    db.commit()
    log_event("key_rotated", document_id=document_id)
    flash("Encryption key rotated. All active sessions remain valid; new decryptions use the new key.", "success")
    return redirect(url_for("admin_document", document_id=document_id))


@app.route("/admin/documents/<int:document_id>/archive", methods=["POST"])
@totp_required
def archive_document(document_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))
    db.execute("UPDATE documents SET status='archived' WHERE id=?", (document_id,))
    db.commit()
    log_event("document_archived", document_id=document_id)
    flash(f"Document '{doc['name']}' archived.", "info")
    return redirect(url_for("admin_documents"))


@app.route("/admin/documents/<int:document_id>/download-access-pdf")
@totp_required
def admin_download_access_page(document_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))

    server_url = request.host_url.rstrip("/")
    pdf_bytes = _build_access_pdf(
        doc_id=document_id,
        doc_name=doc["name"],
        request_url=server_url + url_for("request_access", doc_id=document_id),
        pin_url=server_url + url_for("enter_pin", doc_id=document_id),
    )
    slug = _slug(doc["name"])
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{slug}-access.pdf"'},
    )


@app.route("/admin/audit")
@totp_required
def admin_audit():
    db = get_db()
    page_size = 50
    page = max(1, int(request.args.get("page", 1) or 1))

    q = request.args.get("q", "").strip()
    event_filter = request.args.get("event", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    filters = {"q": q, "event": event_filter, "date_from": date_from, "date_to": date_to}

    where_parts = []
    params: list = []

    if q:
        where_parts.append("(email LIKE ? OR ip_address LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if event_filter:
        where_parts.append("event = ?")
        params.append(event_filter)
    if date_from:
        where_parts.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where_parts.append("created_at < ?")
        params.append(date_to + "T23:59:59")

    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    total = db.execute(
        f"SELECT COUNT(*) FROM audit_log {where_clause}", params
    ).fetchone()[0]
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    offset = (page - 1) * page_size

    logs = db.execute(
        f"SELECT * FROM audit_log {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [page_size, offset],
    ).fetchall()

    counts_row = db.execute("""
        SELECT
            SUM(CASE WHEN event='access_requested' THEN 1 ELSE 0 END) AS access_requested,
            SUM(CASE WHEN event='pin_redeemed' THEN 1 ELSE 0 END) AS pin_redeemed,
            SUM(CASE WHEN event='document_viewed' THEN 1 ELSE 0 END) AS document_viewed,
            SUM(CASE WHEN event='request_denied' THEN 1 ELSE 0 END) AS request_denied
        FROM audit_log
    """).fetchone()
    counts = {
        "access_requested": counts_row[0] or 0,
        "pin_redeemed": counts_row[1] or 0,
        "document_viewed": counts_row[2] or 0,
        "request_denied": counts_row[3] or 0,
    }

    return render_template(
        "admin_audit.html",
        logs=logs,
        total=total,
        page=page,
        total_pages=total_pages,
        filters=filters,
        counts=counts,
        doc_name=DOCUMENT_NAME,
    )


@app.route("/admin/stats")
@totp_required
def admin_stats():
    return render_template("admin_stats.html", doc_name=DOCUMENT_NAME)


@app.route("/admin/stats/json")
@totp_required
def admin_stats_json():
    db = get_db()

    # Requests per day — last 30 days
    cutoff_30 = (utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
    daily_rows = db.execute(
        "SELECT DATE(created_at) AS date, COUNT(*) AS count"
        " FROM requests"
        " WHERE created_at >= ?"
        " GROUP BY DATE(created_at)"
        " ORDER BY date ASC",
        (cutoff_30,),
    ).fetchall()
    requests_per_day = [{"date": r["date"], "count": r["count"]} for r in daily_rows]

    # Events by hour — last 7 days
    cutoff_7 = (utcnow() - timedelta(days=7)).isoformat()
    hourly_rows = db.execute(
        "SELECT CAST(strftime('%H', created_at) AS INTEGER) AS hour, COUNT(*) AS count"
        " FROM audit_log"
        " WHERE created_at >= ?"
        " GROUP BY hour"
        " ORDER BY hour ASC",
        (cutoff_7,),
    ).fetchall()
    hour_map = {r["hour"]: r["count"] for r in hourly_rows}
    events_by_hour = [{"hour": h, "count": hour_map.get(h, 0)} for h in range(24)]

    # Status distribution
    status_rows = db.execute(
        "SELECT status, COUNT(*) AS count FROM requests GROUP BY status"
    ).fetchall()
    status_distribution = {r["status"]: r["count"] for r in status_rows}

    # Extra stat fields for the stats page
    today_str = utcnow().strftime("%Y-%m-%d")
    requests_today = db.execute(
        "SELECT COUNT(*) FROM requests WHERE created_at LIKE ?", (f"{today_str}%",)
    ).fetchone()[0]
    active_sessions = db.execute(
        "SELECT COUNT(*) FROM requests WHERE status='used' AND session_token IS NOT NULL"
    ).fetchone()[0]
    total_views = db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE event='document_viewed'"
    ).fetchone()[0]
    total_req = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    denied_req = db.execute(
        "SELECT COUNT(*) FROM requests WHERE status='denied'"
    ).fetchone()[0]
    denial_rate = round(denied_req / total_req * 100, 1) if total_req else 0

    # Format for Chart.js
    all_dates = []
    d = utcnow() - timedelta(days=29)
    date_map = {r["date"]: r["count"] for r in daily_rows}
    for _ in range(30):
        all_dates.append(d.strftime("%Y-%m-%d"))
        d += timedelta(days=1)

    return jsonify({
        "requests_per_day": requests_per_day,
        "events_by_hour": events_by_hour,
        "status_distribution": status_distribution,
        "requests_today": requests_today,
        "active_sessions": active_sessions,
        "total_views": total_views,
        "denial_rate": denial_rate,
        "daily": {
            "labels": all_dates,
            "counts": [date_map.get(d, 0) for d in all_dates],
        },
        "hourly": {
            "labels": [f"{h:02d}:00" for h in range(24)],
            "counts": [hour_map.get(h, 0) for h in range(24)],
        },
        "status_dist": {
            "labels": list(status_distribution.keys()),
            "counts": list(status_distribution.values()),
        },
    })


@app.route("/admin/export/requests.csv")
@totp_required
def export_requests():
    rows = get_db().execute(
        "SELECT r.id, d.name AS document_name, r.email, r.status, r.created_at,"
        " r.approved_at, r.unlocked_at, r.access_duration_minutes, r.email_verified,"
        " r.deny_reason"
        " FROM requests r"
        " LEFT JOIN documents d ON d.id = r.document_id"
        " ORDER BY r.created_at DESC"
    ).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "document_name", "email", "status", "created_at", "approved_at",
                "unlocked_at", "access_duration_minutes", "email_verified", "deny_reason"])
    w.writerows(rows)
    return Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=requests.csv"},
    )


@app.route("/admin/export/audit.csv")
@totp_required
def export_audit():
    rows = get_db().execute(
        "SELECT id, event, document_id, email, ip_address, country, city,"
        " user_agent, request_id, extra, created_at"
        " FROM audit_log ORDER BY created_at DESC"
    ).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "event", "document_id", "email", "ip_address", "country", "city",
                "user_agent", "request_id", "extra", "created_at"])
    w.writerows(rows)
    return Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


@app.route("/admin/setup-totp")
@totp_required
def admin_setup_totp():
    if not ADMIN_TOTP_SECRET:
        flash("ADMIN_TOTP_SECRET is not set. Add it to your .env to enable 2FA.", "info")
        return redirect(url_for("admin_dashboard"))
    try:
        import pyotp
        totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
        provisioning_uri = totp.provisioning_uri(
            name=ADMIN_EMAIL,
            issuer_name="SecureDocs",
        )
    except Exception as exc:
        flash(f"TOTP setup error: {exc}", "error")
        return redirect(url_for("admin_dashboard"))
    return render_template(
        "admin_setup_totp.html",
        doc_name=DOCUMENT_NAME,
        provisioning_uri=provisioning_uri,
        totp_secret=ADMIN_TOTP_SECRET,
    )


# ── Access PDF builder ─────────────────────────────────────────────────────────

def _build_access_pdf(doc_id: int, doc_name: str, request_url: str, pin_url: str) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    W, H = 210, 297
    pdf.set_fill_color(244, 245, 247)
    pdf.rect(0, 0, W, H, style="F")
    card_x, card_y, card_w = 30, 55, 150
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(229, 231, 235)
    pdf.rect(card_x, card_y, card_w, 190, style="FD")
    pdf.set_font("Helvetica", style="B", size=36)
    pdf.set_text_color(220, 38, 38)
    pdf.set_xy(card_x, card_y + 14)
    pdf.cell(card_w, 18, "[LOCKED]", align="C")
    pdf.set_font("Helvetica", style="B", size=18)
    pdf.set_text_color(15, 23, 42)
    pdf.set_xy(card_x, card_y + 38)
    pdf.cell(card_w, 10, doc_name, align="C")
    pdf.set_draw_color(220, 38, 38)
    pdf.set_line_width(0.5)
    pdf.line(card_x + 20, card_y + 53, card_x + card_w - 20, card_y + 53)
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(107, 114, 128)
    pdf.set_xy(card_x + 12, card_y + 58)
    pdf.multi_cell(card_w - 24, 6,
        "This document is encrypted and requires an approved PIN to view.\n\n"
        "Step 1: Click \"Request Access\" and enter your email address.\n\n"
        "Step 2: Once approved, you will receive a 6-digit PIN by email.\n\n"
        "Step 3: Click \"Enter PIN\" and unlock the document.",
    )
    btn_x, btn_y, btn_w, btn_h = card_x + 20, card_y + 118, card_w - 40, 14
    pdf.set_fill_color(220, 38, 38)
    pdf.rect(btn_x, btn_y, btn_w, btn_h, style="F")
    pdf.set_font("Helvetica", style="B", size=11)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(btn_x, btn_y + 2)
    pdf.cell(btn_w, 10, "Request Access", align="C", link=request_url)
    btn2_y = btn_y + 20
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(220, 38, 38)
    pdf.set_line_width(0.4)
    pdf.rect(btn_x, btn2_y, btn_w, btn_h, style="FD")
    pdf.set_font("Helvetica", style="B", size=11)
    pdf.set_text_color(220, 38, 38)
    pdf.set_xy(btn_x, btn2_y + 2)
    pdf.cell(btn_w, 10, "Enter PIN", align="C", link=pin_url)
    pdf.set_font("Helvetica", size=8)
    pdf.set_text_color(156, 163, 175)
    pdf.set_xy(card_x, card_y + 165)
    pdf.cell(card_w, 6,
        f"PIN valid {PIN_EXPIRY_MINUTES} min · Single use · Access window set by admin",
        align="C")
    return bytes(pdf.output())


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Your session token expired — please try again.", "warning")
    return redirect(request.referrer or url_for("admin_dashboard")), 303


@app.errorhandler(429)
def handle_rate_limit(e):
    flash("Too many attempts. Please wait a minute before trying again.", "error")
    return redirect(request.referrer or url_for("index")), 303


@app.errorhandler(404)
def handle_404(e):
    return render_template("404.html", doc_name=DOCUMENT_NAME), 404


@app.errorhandler(500)
def handle_500(e):
    return render_template("500.html", doc_name=DOCUMENT_NAME), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
